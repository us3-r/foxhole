use crate::artifact::{self, MAX_REPORT_BYTES};
use crate::sandbox::backend::{BackendKind, BackendMetadata, ReportStage, SandboxRequest};
use crate::structs::SandboxRunResult;
use serde::Serialize;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const REPORT_SCHEMA_VERSION: &str = "2.2";

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub schema_version: &'static str,
    pub generated_at_unix_ms: u64,
    pub tool: ToolInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_invocation: Option<HostInvocationInfo>,
    pub target: TargetInfo,
    pub sandbox: SandboxInfo,
    pub backend_selection: BackendSelectionInfo,
    pub backend_metadata: BackendMetadata,
    pub stages: Vec<ReportStage>,
    pub result: SandboxRunResult,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct HostInvocationInfo {
    pub format: &'static str,
    pub command_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
    pub allowed_networks: Vec<String>,
    pub target_argument_count: usize,
    pub target_arguments_redacted: bool,
}

#[derive(Debug, Serialize)]
pub struct TargetInfo {
    pub path: String,
    pub arguments: Vec<String>,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct SandboxInfo {
    pub provider: String,
    pub backend: String,
    pub dry_run: bool,
    pub security_boundary: bool,
    pub kernel_shared_with_host: bool,
    pub profile: String,
    pub guest_execution_profile: String,
    pub network_policy: String,
    pub integrity_level: String,
    pub mitigation_profile: String,
    pub timeout_seconds: u64,
    pub capabilities: Vec<String>,
    pub isolation_controls: Vec<String>,
    pub resource_limits: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BackendSelectionInfo {
    pub requested: String,
    pub selected: BackendKind,
    pub fallback_used: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct ReportContext {
    pub requested_backend: String,
    pub selected_backend: BackendKind,
    pub fallback_used: bool,
    pub selection_warnings: Vec<String>,
    pub backend_metadata: BackendMetadata,
    pub stages: Vec<ReportStage>,
    pub host_invocation: Option<HostInvocationInfo>,
}

impl AnalysisReport {
    pub fn new(
        target: &Path,
        size_bytes: u64,
        target_sha256: String,
        profile_name: Option<String>,
        request: &SandboxRequest,
        result: SandboxRunResult,
    ) -> io::Result<Self> {
        if request.backend == BackendKind::HyperV {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hyper-V reports require backend metadata and lifecycle stages",
            ));
        }
        let context = ReportContext {
            requested_backend: request.backend.to_string(),
            selected_backend: request.backend,
            fallback_used: false,
            selection_warnings: Vec::new(),
            backend_metadata: BackendMetadata::RestrictedProcess {
                profile_name: profile_name.clone(),
                integrity_level: result.integrity_level.clone(),
                mitigation_profile: result.mitigation_profile.clone(),
            },
            stages: Vec::new(),
            host_invocation: None,
        };
        Self::new_with_context(
            target,
            size_bytes,
            target_sha256,
            profile_name,
            request,
            result,
            context,
        )
    }

    pub fn new_with_context(
        target: &Path,
        size_bytes: u64,
        target_sha256: String,
        profile_name: Option<String>,
        request: &SandboxRequest,
        mut result: SandboxRunResult,
        context: ReportContext,
    ) -> io::Result<Self> {
        if target_sha256.len() != 64 || !target_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the authoritative target SHA-256 is missing or invalid",
            ));
        }
        let target_name = target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<redacted>".to_string());
        let arguments = vec!["<redacted>".to_string(); request.arguments.len()];
        result.working_dir = result.working_dir.as_deref().map(|directory| {
            Path::new(directory)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<redacted>".to_string())
        });
        let is_hyperv = context.selected_backend == BackendKind::HyperV;
        let mut capabilities = Vec::new();
        if !is_hyperv
            && cfg!(target_os = "windows")
            && target
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
                })
        {
            capabilities.extend([
                "registryRead".to_string(),
                "lpacIdentityServices".to_string(),
            ]);
        }
        if !is_hyperv
            && cfg!(target_os = "windows")
            && request.network_policy.needs_internet_capability()
        {
            capabilities.push("internetClient".to_string());
        }

        let (provider, security_boundary, kernel_shared_with_host, isolation_controls, limitations) =
            if is_hyperv {
                let guest_control = match request.hyperv_guest_profile {
                    crate::sandbox::backend::HyperVGuestProfile::Restricted => {
                        "guest target is additionally constrained by the restricted-process backend"
                    }
                    crate::sandbox::backend::HyperVGuestProfile::Normal => {
                        "guest target runs as the configured standard Windows account; the disposable VM is the primary security boundary"
                    }
                    crate::sandbox::backend::HyperVGuestProfile::Admin => {
                        "guest target runs with guest administrator authority; the disposable VM is the primary security boundary"
                    }
                };
                (
                    "hyper-v-disposable-vm".to_string(),
                    true,
                    false,
                    vec![
                        "hardware-virtualized Generation 2 disposable guest".to_string(),
                        "read-only base image with a per-run differencing OS disk".to_string(),
                        "separate run-data disk with bounded, validated result extraction"
                            .to_string(),
                        "automatic and production checkpoints disabled".to_string(),
                        "nested virtualization disabled and Hyper-V host resource protection enabled".to_string(),
                        "virtual DVD removed; Heartbeat is the only enabled Hyper-V integration service".to_string(),
                        "no host drive, clipboard, enhanced-session, or credential sharing"
                            .to_string(),
                        "host-side timeout and force-stop remain authoritative".to_string(),
                        "deny-all networking is implemented by attaching no virtual NIC"
                            .to_string(),
                        guest_control.to_string(),
                    ],
                    vec![
                        "Guest-produced status, results, and artifacts are untrusted and are accepted only after bounded validation, request/result hash binding, and host-side archival hashes.".to_string(),
                        "The run-data VHDX is used for pre-boot input and post-shutdown output; the current transport provides VM health but not live guest READY/status visibility.".to_string(),
                        "Controlled Hyper-V networking is IPv4-only; IPv6 is disabled and independently attested rather than permitted without equivalent containment.".to_string(),
                        "Guest telemetry is bounded and combines Sysmon, Windows Filtering Platform auditing, and Packet Monitor artifacts; it cannot expose plaintext headers or payloads protected by TLS.".to_string(),
                        "A guest-administrator target can tamper with in-guest telemetry; the Hyper-V host boundary and host-side artifact validation remain authoritative.".to_string(),
                    ],
                )
            } else {
                (
                    if cfg!(target_os = "windows") {
                        "windows-restricted-process".to_string()
                    } else {
                        "linux-namespaces".to_string()
                    },
                    false,
                    true,
                    vec![
                        "privilege-stripped restricted primary token with administrator groups deny-only and linked standard-user token derivation for elevated brokers".to_string(),
                        "low integrity by default and untrusted integrity for the maximum profile".to_string(),
                        "less-privileged AppContainer (LPAC)".to_string(),
                        "explicit three-handle standard-stream inheritance allowlist".to_string(),
                        "minimal explicit environment and detached console".to_string(),
                        "unique private window station and desktop".to_string(),
                        "per-run input/work/output/logs workspace with protected DACLs and a read-only staged target".to_string(),
                        "per-run WFP IPv4/IPv6 filters installed before process resume for deny-all and allow-list modes".to_string(),
                        "Job Object UI restrictions and kill-on-close teardown".to_string(),
                        "compatible, strict, and maximum process-creation mitigation profiles".to_string(),
                        "unique disposable profile with loopback-exemption rejection".to_string(),
                    ],
                    vec![
                        "Process and socket observations are polling-based; very short-lived activity can be missed.".to_string(),
                        "TCP/IPv4, TCP/IPv6, and local UDP bindings are observed; UDP destinations, DNS names, payloads, and blocked connection attempts are not captured.".to_string(),
                        "Registry, DNS-name, payload, and in-memory behavior are not monitored yet.".to_string(),
                        "Standard output and standard error capture records console bytes decoded lossily as UTF-8; output written through other channels is not captured.".to_string(),
                        "Windows batch files are streamed to sandboxed cmd.exe because AppContainer blocks direct batch-file execution; batch arguments and control-flow-only batch features are not supported yet.".to_string(),
                        "The target is reduced to its filename, the working directory to its final component, and each <redacted> argument entry represents one supplied value; recovery diagnostics can retain exact protected resource paths.".to_string(),
                        "The profile storage ceiling is polling-based rather than a hard filesystem quota; it can be exceeded between checks and cannot account for deleted-but-open files during a run.".to_string(),
                        "WFP policy installation requires permission to manage the Base Filtering Engine; deny-all and allow-list runs fail closed if filters cannot be installed.".to_string(),
                        "The restricted-process backend shares the host kernel and is not equivalent to VM isolation.".to_string(),
                    ],
                )
            };
        let mut resource_limits = vec![
            format!(
                "{} active processes; {} bytes per process; {} bytes per job",
                request.resource_limits.active_process_limit,
                request.resource_limits.process_memory_bytes,
                request.resource_limits.job_memory_bytes
            ),
            format!(
                "{} percent CPU hard cap and bounded job CPU time",
                request.resource_limits.cpu_rate_percent
            ),
            "8 MiB retained per output stream; bounded terminal replay and observation tables"
                .to_string(),
            "128 MiB/10,000-entry profile storage ceiling enforced by polling".to_string(),
        ];
        if let BackendMetadata::HyperV {
            cpu_count,
            startup_memory_bytes,
            data_disk_bytes,
            maximum_os_disk_growth_bytes,
            ..
        } = &context.backend_metadata
        {
            resource_limits.push(format!(
                "{cpu_count} virtual CPUs and {startup_memory_bytes} bytes startup memory"
            ));
            resource_limits.push(format!(
                "{data_disk_bytes} byte run-data disk and {maximum_os_disk_growth_bytes} byte differencing-disk growth ceiling"
            ));
        }

        Ok(Self {
            schema_version: REPORT_SCHEMA_VERSION,
            generated_at_unix_ms: unix_time_ms(),
            tool: ToolInfo {
                name: env!("CARGO_PKG_NAME"),
                version: env!("CARGO_PKG_VERSION"),
            },
            host_invocation: context.host_invocation,
            target: TargetInfo {
                path: target_name,
                arguments,
                size_bytes,
                sha256: target_sha256.to_ascii_lowercase(),
            },
            sandbox: SandboxInfo {
                provider,
                backend: result.backend.clone(),
                dry_run: request.dry_run,
                security_boundary,
                kernel_shared_with_host,
                profile: profile_name.unwrap_or_else(|| "not-created-dry-run".to_string()),
                guest_execution_profile: request.hyperv_guest_profile.to_string(),
                network_policy: result.network_policy.clone(),
                integrity_level: result.integrity_level.clone(),
                mitigation_profile: result.mitigation_profile.clone(),
                timeout_seconds: request.timeout_secs,
                capabilities,
                isolation_controls,
                resource_limits,
            },
            backend_selection: BackendSelectionInfo {
                requested: context.requested_backend,
                selected: context.selected_backend,
                fallback_used: context.fallback_used,
                warnings: context.selection_warnings,
            },
            backend_metadata: context.backend_metadata,
            stages: context.stages,
            result,
            limitations,
        })
    }
}

pub fn write_report(report: &AnalysisReport, destination: &Path) -> io::Result<PathBuf> {
    artifact::secure_write_new(destination, MAX_REPORT_BYTES, |output| {
        let mut writer = BufWriter::new(output);
        serde_json::to_writer_pretty(&mut writer, report).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
        writer.flush()
    })
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::{CleanupStatus, SandboxRunResult, StreamCaptureSummary};

    #[test]
    fn report_has_a_stable_schema_version() {
        let result = SandboxRunResult {
            backend: "restricted_process".into(),
            network_policy: "deny_all".into(),
            integrity_level: "low".into(),
            mitigation_profile: "compatible".into(),
            pid: 42,
            exit_code: Some(0),
            timed_out: false,
            working_dir: None,
            duration_ms: 10,
            stdout: String::new(),
            stderr: String::new(),
            stdout_capture: StreamCaptureSummary {
                bytes_seen: 0,
                bytes_stored: 0,
                truncated: false,
            },
            stderr_capture: StreamCaptureSummary {
                bytes_seen: 0,
                bytes_stored: 0,
                truncated: false,
            },
            processes: Vec::new(),
            network_connections: Vec::new(),
            file_observations: Vec::new(),
            registry_observations: Vec::new(),
            mapped_paths: Vec::new(),
            monitor_warnings: Vec::new(),
            cleanup: CleanupStatus::pending(),
        };
        let report = AnalysisReport {
            schema_version: REPORT_SCHEMA_VERSION,
            generated_at_unix_ms: 0,
            tool: ToolInfo {
                name: "foxhole",
                version: "test",
            },
            host_invocation: None,
            target: TargetInfo {
                path: "sample.exe".into(),
                arguments: Vec::new(),
                size_bytes: 1,
                sha256: "00".repeat(32),
            },
            sandbox: SandboxInfo {
                provider: "windows-restricted-process".to_string(),
                backend: "restricted_process".to_string(),
                dry_run: false,
                security_boundary: false,
                kernel_shared_with_host: true,
                profile: "foxhole.sandbox".to_string(),
                guest_execution_profile: "restricted".to_string(),
                network_policy: "deny_all".to_string(),
                integrity_level: "low".to_string(),
                mitigation_profile: "compatible".to_string(),
                timeout_seconds: 30,
                capabilities: Vec::new(),
                isolation_controls: Vec::new(),
                resource_limits: Vec::new(),
            },
            backend_selection: BackendSelectionInfo {
                requested: "restricted_process".to_string(),
                selected: BackendKind::RestrictedProcess,
                fallback_used: false,
                warnings: Vec::new(),
            },
            backend_metadata: BackendMetadata::RestrictedProcess {
                profile_name: Some("foxhole.sandbox".to_string()),
                integrity_level: "low".to_string(),
                mitigation_profile: "compatible".to_string(),
            },
            stages: Vec::new(),
            result,
            limitations: Vec::new(),
        };

        let value = serde_json::to_value(report).expect("report should serialize");
        assert_eq!(value["schema_version"], "2.2");
        assert_eq!(value["target"]["sha256"], "00".repeat(32));
        assert_eq!(value["result"]["pid"], 42);
        assert_eq!(value["result"]["stdout"], "");
        assert_eq!(value["result"]["stderr"], "");
        assert_eq!(value["sandbox"]["dry_run"], false);
    }

    #[test]
    fn report_redacts_host_paths_and_argument_values() {
        let target = std::env::temp_dir().join(format!(
            "foxhole-report-redaction-{}.bat",
            std::process::id()
        ));
        std::fs::write(&target, b"sample").expect("write target");
        let result = SandboxRunResult {
            backend: "restricted_process".into(),
            network_policy: "deny_all".into(),
            integrity_level: "low".into(),
            mitigation_profile: "compatible".into(),
            pid: 42,
            exit_code: Some(0),
            timed_out: false,
            working_dir: Some(r"C:\Users\sensitive\run-random".to_string()),
            duration_ms: 10,
            stdout: String::new(),
            stderr: String::new(),
            stdout_capture: StreamCaptureSummary {
                bytes_seen: 0,
                bytes_stored: 0,
                truncated: false,
            },
            stderr_capture: StreamCaptureSummary {
                bytes_seen: 0,
                bytes_stored: 0,
                truncated: false,
            },
            processes: Vec::new(),
            network_connections: Vec::new(),
            file_observations: Vec::new(),
            registry_observations: Vec::new(),
            mapped_paths: Vec::new(),
            monitor_warnings: Vec::new(),
            cleanup: CleanupStatus::pending(),
        };

        let report = AnalysisReport::new(
            &target,
            6,
            "00".repeat(32),
            Some("foxhole.sandbox.test".to_string()),
            &{
                let mut request = SandboxRequest::restricted(&target);
                request.arguments = vec!["--token".to_string(), "secret-value".to_string()];
                request
            },
            result,
        )
        .expect("build report");
        assert_eq!(
            report.target.path,
            target.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(report.target.arguments, ["<redacted>", "<redacted>"]);
        assert_eq!(report.target.sha256, "00".repeat(32));
        assert_eq!(report.result.working_dir.as_deref(), Some("run-random"));
        if cfg!(target_os = "windows") {
            assert_eq!(
                report.sandbox.capabilities,
                ["registryRead", "lpacIdentityServices"]
            );
        }

        std::fs::remove_file(target).expect("remove target");
    }

    #[test]
    fn report_rejects_a_non_sha256_target_digest() {
        let request = SandboxRequest::restricted("sample.exe");
        let error = AnalysisReport::new(
            Path::new("sample.exe"),
            1,
            "not-a-sha256".to_string(),
            None,
            &request,
            empty_result("deny_all"),
        )
        .expect_err("invalid authoritative target digests must fail closed");
        assert!(error.to_string().contains("target SHA-256"));
    }

    fn empty_result(policy: &str) -> SandboxRunResult {
        SandboxRunResult {
            backend: "restricted_process".into(),
            network_policy: policy.into(),
            integrity_level: "low".into(),
            mitigation_profile: "compatible".into(),
            pid: 0,
            exit_code: Some(0),
            timed_out: false,
            working_dir: Some(String::new()),
            duration_ms: 0,
            stdout: String::new(),
            stderr: String::new(),
            stdout_capture: StreamCaptureSummary {
                bytes_seen: 0,
                bytes_stored: 0,
                truncated: false,
            },
            stderr_capture: StreamCaptureSummary {
                bytes_seen: 0,
                bytes_stored: 0,
                truncated: false,
            },
            processes: Vec::new(),
            network_connections: Vec::new(),
            file_observations: Vec::new(),
            registry_observations: Vec::new(),
            mapped_paths: Vec::new(),
            monitor_warnings: Vec::new(),
            cleanup: CleanupStatus::pending(),
        }
    }

    #[test]
    fn report_describes_batch_and_network_capabilities() {
        let mut request = SandboxRequest::restricted("sample.cmd");
        request.network_policy = crate::sandbox::backend::NetworkPolicy::AllowInternet;
        request.dry_run = true;
        let report = AnalysisReport::new(
            Path::new("sample.cmd"),
            5,
            "00".repeat(32),
            None,
            &request,
            empty_result("allow_internet"),
        )
        .unwrap();
        assert_eq!(report.sandbox.profile, "not-created-dry-run");
        assert!(report.sandbox.dry_run);
        assert_eq!(
            serde_json::to_value(&report).unwrap()["sandbox"]["dry_run"],
            true
        );
        assert_eq!(
            report.sandbox.capabilities,
            ["registryRead", "lpacIdentityServices", "internetClient"]
        );
        assert_eq!(report.result.working_dir.as_deref(), Some("<redacted>"));
        assert!(!report.limitations.is_empty());
        assert!(report.generated_at_unix_ms > 0);
    }

    #[test]
    fn report_is_written_once_and_never_overwritten() {
        let request = SandboxRequest::restricted("sample.exe");
        let report = AnalysisReport::new(
            Path::new("sample.exe"),
            1,
            "00".repeat(32),
            None,
            &request,
            empty_result("deny_all"),
        )
        .unwrap();
        let destination = artifact::report_destination(
            Some(Path::new(&format!(
                "self-test/report-{}.json",
                std::process::id()
            ))),
            Path::new("sample.exe"),
        )
        .unwrap();
        if destination.exists() {
            std::fs::remove_file(&destination).unwrap();
        }
        let written = write_report(&report, &destination).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&written).unwrap()).unwrap();
        assert_eq!(json["schema_version"], REPORT_SCHEMA_VERSION);
        assert!(write_report(&report, &destination).is_err());
        std::fs::remove_file(written).unwrap();
    }

    #[test]
    fn hyperv_report_uses_a_separate_kernel_boundary_and_vm_metadata() {
        let request = SandboxRequest::hyperv("sample.exe");
        let mut result = empty_result("deny_all");
        result.backend = "hyperv".to_string();
        result.integrity_level = "low".to_string();
        let stages = [
            "request_validation",
            "preparation",
            "execution",
            "observation",
            "timeout_or_completion",
            "artifact_collection",
            "cleanup",
        ]
        .into_iter()
        .map(|stage| ReportStage::instant(stage, true))
        .collect::<Vec<_>>();
        let report = AnalysisReport::new_with_context(
            Path::new("sample.exe"),
            1,
            "00".repeat(32),
            Some("1.0.0".to_string()),
            &request,
            result,
            ReportContext {
                requested_backend: "auto".to_string(),
                selected_backend: BackendKind::HyperV,
                fallback_used: false,
                selection_warnings: Vec::new(),
                backend_metadata: BackendMetadata::HyperV {
                    run_id: "0123456789abcdef0123456789abcdef".to_string(),
                    guest_image_version: "1.0.0".to_string(),
                    protocol_version: 1,
                    vm_generation: 2,
                    secure_boot: true,
                    cpu_count: 2,
                    startup_memory_bytes: 2 * 1024 * 1024 * 1024,
                    data_disk_bytes: 2 * 1024 * 1024 * 1024,
                    maximum_os_disk_growth_bytes: 16 * 1024 * 1024 * 1024,
                    network_mode: "deny_all".to_string(),
                    network: crate::sandbox::backend::HyperVNetworkMetadata {
                        requested_mode: "deny_all".to_string(),
                        capture_status: "not_requested".to_string(),
                        ..Default::default()
                    },
                },
                stages,
                host_invocation: None,
            },
        )
        .unwrap();

        assert_eq!(report.sandbox.provider, "hyper-v-disposable-vm");
        assert!(report.sandbox.security_boundary);
        assert!(!report.sandbox.kernel_shared_with_host);
        assert_eq!(report.backend_selection.requested, "auto");
        assert_eq!(report.backend_selection.selected, BackendKind::HyperV);
        assert_eq!(report.stages.len(), 7);
        assert!(
            report
                .sandbox
                .isolation_controls
                .iter()
                .any(|control| control.contains("no virtual NIC"))
        );
        assert!(
            report
                .limitations
                .iter()
                .all(|limitation| !limitation.contains("shares the host kernel"))
        );
        assert!(
            report
                .sandbox
                .resource_limits
                .iter()
                .any(|limit| limit.contains("virtual CPUs"))
        );
    }

    #[test]
    fn controlled_hyperv_network_metadata_serializes_every_attested_field() {
        use crate::sandbox::backend::{HyperVNetworkMetadata, HyperVNetworkVerification};
        use std::net::Ipv4Addr;

        let verification = HyperVNetworkVerification {
            verified: true,
            adapter_count: 1,
            switch_id: Some("11111111-1111-1111-1111-111111111111".into()),
            switch_type: Some("Internal".into()),
            host_adapter_id: Some("22222222-2222-2222-2222-222222222222".into()),
            firewall_scope_id: Some("33333333-3333-3333-3333-333333333333".into()),
            host_ipv4: Some(Ipv4Addr::new(192, 168, 250, 1)),
            guest_ipv4: Some(Ipv4Addr::new(192, 168, 250, 10)),
            nat_enabled: false,
            firewall_rule_ids: vec!["Foxhole-run-host-service".into()],
            capture_active: false,
            ipv6_disabled: true,
            no_unexpected_routes: true,
            warnings: Vec::new(),
        };
        let metadata = HyperVNetworkMetadata {
            requested_mode: "host_server".into(),
            switch_id: verification.switch_id.clone(),
            switch_type: verification.switch_type.clone(),
            guest_ipv4: verification.guest_ipv4,
            prefix_length: Some(24),
            gateway_ipv4: None,
            dns_servers: Vec::new(),
            host_service_endpoint: Some("http://192.168.250.1:8080".into()),
            firewall_scope_id: verification.firewall_scope_id.clone(),
            firewall_rule_ids: verification.firewall_rule_ids.clone(),
            capture_status: "not_requested".into(),
            pre_run_verification: Some(verification.clone()),
            post_run_verification: Some(verification),
            cleanup_results: vec!["guest_ip:192.168.250.10".into()],
            warnings: Vec::new(),
        };

        let value = serde_json::to_value(metadata).unwrap();
        assert_eq!(value["requested_mode"], "host_server");
        assert_eq!(value["guest_ipv4"], "192.168.250.10");
        assert_eq!(value["host_service_endpoint"], "http://192.168.250.1:8080");
        assert_eq!(value["pre_run_verification"]["verified"], true);
        assert_eq!(value["post_run_verification"]["ipv6_disabled"], true);
        assert_eq!(value["cleanup_results"][0], "guest_ip:192.168.250.10");
    }
}
