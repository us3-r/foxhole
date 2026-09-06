//! Safe Phase 8 security-policy tests for the Hyper-V backend.
//!
//! Platform-neutral tests exercise only pure validation and state transitions.
//! The real Hyper-V smoke tests are Windows-only, ignored by default, and also
//! refuse to run unless `FOXHOLE_HYPERV_TESTS=1` is present.

use foxhole::sandbox::backend::{
    BackendKind, BackendState, MappedPath, MappedPathAccess, SandboxBackend, SandboxRequest,
};
use foxhole::sandbox::dispatcher::{HyperVCapabilityEvidence, RequestedBackend, resolve_backend};
use foxhole::sandbox::hyperv::guest_protocol::{
    ArtifactManifestEntry, CaptureCoverage, CaptureOptions, GuestMitigationProfile,
    GuestNetworkPolicy, GuestResourceLimits, GuestResultEnvelope, GuestRunRequest,
    GuestTerminalOutcome, MAX_ACTIVE_PROCESSES, MAX_ARGUMENTS, MAX_ARTIFACT_BYTES,
    MAX_GUEST_MEMORY_BYTES, MAX_TOTAL_ARTIFACT_BYTES, ObservationCoverage, PROTOCOL_VERSION,
    ProtocolState, ProtocolStateMachine, StatusRecord, validate_relative_wire_path,
    wire_path_to_native,
};
use foxhole::sandbox::hyperv::{CollectionLimits, HyperVBackend, HyperVConfig};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RUN_ID: &str = "0123456789abcdef0123456789abcdef";
const SHA256_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn backend_policy_never_weakens_isolation_without_explicit_auto_fallback() {
    let unavailable = HyperVCapabilityEvidence::unavailable("test host has no Hyper-V");

    let error = resolve_backend(RequestedBackend::Auto, &unavailable, false)
        .expect_err("auto must fail closed without explicit fallback");
    assert_eq!(error.stage, "backend_selection");
    assert!(error.to_string().contains("not explicitly permitted"));

    let error = resolve_backend(RequestedBackend::HyperV, &unavailable, true)
        .expect_err("an explicit Hyper-V request must never fall back");
    assert_eq!(error.stage, "backend_selection");

    let selection = resolve_backend(RequestedBackend::Auto, &unavailable, true)
        .expect("explicit auto fallback should select restricted isolation");
    assert_eq!(selection.requested, RequestedBackend::Auto);
    assert_eq!(selection.selected, BackendKind::RestrictedProcess);
    assert!(selection.fallback_used);
    assert_eq!(selection.warnings.len(), 1);
    assert!(selection.warnings[0].contains("weaker restricted-process"));
}

#[test]
fn guest_network_policy_fails_closed_on_inconsistent_allow_lists() {
    let mut request = valid_request();
    request.network_policy = GuestNetworkPolicy::DenyAll;
    assert!(request.validate().is_ok());

    request.allowed_networks.push("192.0.2.0/24".to_string());
    let error = request
        .validate()
        .expect_err("deny-all must reject allow-list data");
    assert_eq!(error.code, "invalid_network_policy");

    request.network_policy = GuestNetworkPolicy::AllowList;
    request.allowed_networks.clear();
    assert!(
        request.validate().is_err(),
        "allow-list must contain at least one network"
    );

    request.allowed_networks.push("not-a-network".to_string());
    assert!(
        request.validate().is_err(),
        "allow-list entries must be numeric addresses or CIDRs"
    );

    request.allowed_networks[0] = "2001:db8::/32".to_string();
    assert!(request.validate().is_ok());
}

#[test]
fn untrusted_manifest_rejects_escape_duplicates_and_oversized_totals() {
    for path in [
        "../host.txt",
        "/absolute.txt",
        "C:/host.txt",
        r"artifacts\escape.txt",
        "artifacts/../../host.txt",
        "artifacts/CON",
    ] {
        let error = artifact(path, 1)
            .validate()
            .expect_err("unsafe manifest path must be rejected");
        assert_eq!(error.code, "invalid_relative_path", "path {path:?}");
    }

    let mut envelope = valid_result_envelope();
    envelope.artifacts = vec![
        artifact("artifacts/sample.bin", 1),
        artifact("ARTIFACTS/SAMPLE.BIN", 1),
    ];
    let error = envelope
        .validate_metadata()
        .expect_err("case-insensitive duplicate paths must be rejected");
    assert_eq!(error.code, "invalid_artifact");

    envelope.artifacts = (0..5)
        .map(|index| artifact(&format!("artifacts/{index}.bin"), MAX_ARTIFACT_BYTES))
        .collect();
    assert!(
        envelope
            .artifacts
            .iter()
            .map(|entry| entry.size_bytes)
            .sum::<u64>()
            > MAX_TOTAL_ARTIFACT_BYTES
    );
    let error = envelope
        .validate_metadata()
        .expect_err("oversized manifest total must be rejected");
    assert_eq!(error.code, "invalid_artifact");

    assert!(
        artifact("artifacts/too-large.bin", MAX_ARTIFACT_BYTES + 1)
            .validate()
            .is_err()
    );
}

#[test]
fn wire_paths_remain_relative_and_below_the_chosen_root() {
    for value in [
        "",
        ".",
        "..",
        "../escape",
        "safe/../escape",
        "/absolute",
        r"C:\absolute",
        r"safe\backslash",
        "safe//double",
        "safe/NUL.txt",
        "safe/trailing.",
        "safe/trailing ",
        "safe/\u{0001}control",
    ] {
        assert!(
            validate_relative_wire_path(value).is_err(),
            "unsafe wire path accepted: {value:?}"
        );
    }

    let root = Path::new("isolated-run-root");
    let native = wire_path_to_native(root, "output/nested/result.json")
        .expect("canonical relative path should map below the root");
    assert!(native.starts_with(root));
    assert_eq!(
        native,
        root.join("output").join("nested").join("result.json")
    );
}

#[test]
fn protocol_state_rejects_replay_skips_wrong_runs_and_post_terminal_events() {
    let status = |run_id: &str, sequence: u64, state: ProtocolState| {
        let mut record = StatusRecord::new(run_id, sequence, state);
        record.request_sha256 = Some("ab".repeat(32));
        if matches!(
            state,
            ProtocolState::Completed | ProtocolState::ShutdownReady
        ) {
            record.result_sha256 = Some("cd".repeat(32));
        }
        record
    };
    let mut machine = ProtocolStateMachine::new(RUN_ID).expect("valid run id");
    let valid_states = [
        ProtocolState::HostReady,
        ProtocolState::RequestWritten,
        ProtocolState::GuestReady,
        ProtocolState::StartAllowed,
        ProtocolState::Running,
        ProtocolState::Completed,
        ProtocolState::ShutdownReady,
    ];
    for (index, state) in valid_states.into_iter().enumerate() {
        machine
            .observe(&status(RUN_ID, index as u64 + 1, state))
            .unwrap_or_else(|error| panic!("valid state {state:?} failed: {error}"));
    }
    assert_eq!(machine.last_sequence(), valid_states.len() as u64);
    assert!(machine.has_seen(ProtocolState::Completed));

    let replay = status(
        RUN_ID,
        valid_states.len() as u64 + 1,
        ProtocolState::Completed,
    );
    assert!(machine.observe(&replay).is_err());

    let mut wrong_run = ProtocolStateMachine::new(RUN_ID).expect("valid run id");
    let wrong = status(
        "fedcba9876543210fedcba9876543210",
        1,
        ProtocolState::HostReady,
    );
    assert!(wrong_run.observe(&wrong).is_err());

    let mut skipped = ProtocolStateMachine::new(RUN_ID).expect("valid run id");
    let running = status(RUN_ID, 1, ProtocolState::Running);
    assert!(skipped.observe(&running).is_err());

    let failed_without_error = status(RUN_ID, 1, ProtocolState::Failed);
    assert!(failed_without_error.validate().is_err());
}

#[test]
fn process_bomb_requests_are_rejected_before_execution() {
    let mut request = valid_request();
    request.resource_limits.active_process_limit = 0;
    assert_invalid_resource_limits(&request);

    request.resource_limits.active_process_limit = MAX_ACTIVE_PROCESSES + 1;
    assert_invalid_resource_limits(&request);

    request = valid_request();
    request.arguments = (0..=MAX_ARGUMENTS)
        .map(|index| format!("child-{index}"))
        .collect();
    let error = request
        .validate()
        .expect_err("an oversized process argument fan-out must be rejected");
    assert_eq!(error.code, "invalid_arguments");

    let output = run_bounded_helper_rejection(&["spawn-tree", "5", "0"]);
    assert_rejected_without_work(&output, "between 0 and 4");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("pid="),
        "the rejected process-tree request must not create a child tree"
    );
}

#[test]
fn memory_exhaustion_requests_are_rejected_before_allocation() {
    let mut requests = Vec::new();

    let mut request = valid_request();
    request.resource_limits.process_memory_bytes = 0;
    requests.push(request);

    let mut request = valid_request();
    request.resource_limits.process_memory_bytes = MAX_GUEST_MEMORY_BYTES + 1;
    requests.push(request);

    let mut request = valid_request();
    request.resource_limits.job_memory_bytes = MAX_GUEST_MEMORY_BYTES + 1;
    requests.push(request);

    let mut request = valid_request();
    request.resource_limits.job_memory_bytes = request
        .resource_limits
        .process_memory_bytes
        .saturating_sub(1);
    requests.push(request);

    for request in requests {
        assert_invalid_resource_limits(&request);
    }

    let output = run_bounded_helper_rejection(&["allocate", "65", "0"]);
    assert_rejected_without_work(&output, "between 1 and 64");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("allocated_bytes="),
        "the rejected request must not allocate its requested buffer"
    );
}

#[test]
fn network_bypass_inputs_are_rejected_without_network_io() {
    for arguments in [
        ["connect", "example.com:443", "1"],
        ["connect", "0.0.0.0:80", "1"],
        ["connect", "224.0.0.1:80", "1"],
        ["connect", "255.255.255.255:80", "1"],
        ["connect", "127.0.0.1:0", "1"],
    ] {
        let output = run_bounded_helper_rejection(&arguments);
        assert_rejected_without_work(&output, "foxhole-test-helper");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("connected="),
            "an invalid endpoint must be rejected before a connection is attempted"
        );
    }

    for policy in [
        GuestNetworkPolicy::DenyAll,
        GuestNetworkPolicy::AllowInternet,
        GuestNetworkPolicy::CaptureOnly,
    ] {
        let mut request = valid_request();
        request.network_policy = policy;
        request.allowed_networks = vec!["127.0.0.1/32".to_string()];
        let error = request
            .validate()
            .expect_err("non-allow-list modes must reject injected destinations");
        assert_eq!(error.code, "invalid_network_policy");
    }

    for network in [
        "example.com",
        "192.0.2.1/33",
        "2001:db8::/129",
        "127.0.0.1/32,10.0.0.0/8",
        " 127.0.0.1/32",
        "fe80::1%12",
    ] {
        let mut request = valid_request();
        request.network_policy = GuestNetworkPolicy::AllowList;
        request.allowed_networks = vec![network.to_string()];
        assert!(
            request.validate().is_err(),
            "network parser accepted bypass input {network:?}"
        );
    }
}

#[test]
fn host_filesystem_mappings_are_rejected_before_hyperv_is_contacted() {
    let mut request = SandboxRequest::hyperv("does-not-need-to-exist.exe");
    request.mapped_paths.push(MappedPath {
        host_path: PathBuf::from(r"C:\host-secret"),
        guest_name: "host-secret".to_string(),
        access: MappedPathAccess::ReadOnly,
    });

    let mut backend = HyperVBackend::new(inert_hyperv_config());
    let error = backend
        .prepare(&request)
        .expect_err("Hyper-V must never expose an arbitrary host mapping");
    assert_eq!(error.stage, "hyperv_prepare");
    assert!(error.to_string().contains("mapped paths are not supported"));
    assert_eq!(backend.state(), BackendState::Failed);
}

#[test]
fn failed_preparation_cleanup_is_safe_idempotent_and_bounded() {
    let mut request = SandboxRequest::hyperv("does-not-need-to-exist.exe");
    request.mapped_paths.push(MappedPath {
        host_path: PathBuf::from("host-data"),
        guest_name: "host-data".to_string(),
        access: MappedPathAccess::ReadOnly,
    });

    let mut backend = HyperVBackend::new(inert_hyperv_config());
    backend
        .prepare(&request)
        .expect_err("the deliberately unsupported mapping must fail preparation");

    backend
        .cleanup()
        .expect("cleanup after a pre-resource validation failure must succeed");
    assert_eq!(backend.state(), BackendState::Finished);
    assert!(backend.cleanup_outcome().attempted);
    assert!(backend.cleanup_outcome().success);
    assert!(backend.cleanup_outcome().warnings.is_empty());
    assert!(backend.cleanup_outcome().leftover_resources.is_empty());

    backend
        .cleanup()
        .expect("restarting cleanup after completion must remain idempotent");
    assert_eq!(backend.state(), BackendState::Finished);
}

#[test]
fn escape_payloads_are_rejected_before_filesystem_io() {
    for relative in [
        "../escape",
        "safe/../../escape",
        "/absolute",
        r"C:\host-secret",
        r"\\host\share\secret",
        "output/target.txt:alternate-stream",
        "output/COM1.log",
    ] {
        let output = run_bounded_helper_rejection(&["write-relative", relative, "marker"]);
        assert_rejected_without_work(&output, "foxhole-test-helper");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("wrote_relative="),
            "an escape payload must not produce a file"
        );
    }
}

fn assert_invalid_resource_limits(request: &GuestRunRequest) {
    let error = request
        .validate()
        .expect_err("unsafe resource limits must be rejected");
    assert_eq!(error.code, "invalid_resource_limits");
}

fn inert_hyperv_config() -> HyperVConfig {
    HyperVConfig {
        base_image_path: PathBuf::from("unused-base.vhdx"),
        base_manifest_path: PathBuf::from("unused-manifest.json"),
        run_root: std::env::temp_dir().join("foxhole-phase8-unused-runs"),
        processor_count: 1,
        startup_memory_bytes: 512 * 1024 * 1024,
        data_disk_bytes: 1024 * 1024 * 1024,
        maximum_os_disk_growth_bytes: 1024 * 1024 * 1024,
        boot_timeout_secs: 1,
        shutdown_grace_secs: 1,
        controlled_gateway: None,
        collection_limits: CollectionLimits::default(),
    }
}

fn run_bounded_helper_rejection(arguments: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_foxhole_test_helper"))
        .args(arguments)
        .output()
        .expect("run the bounded Phase 8 test helper");
    assert!(
        output.stdout.len() + output.stderr.len() <= 8 * 1024,
        "bounded helper diagnostics unexpectedly exceeded 8 KiB"
    );
    output
}

fn assert_rejected_without_work(output: &Output, expected_diagnostic: &str) {
    assert!(!output.status.success(), "unsafe helper input was accepted");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected_diagnostic),
        "missing rejection diagnostic; stderr was {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn valid_request() -> GuestRunRequest {
    GuestRunRequest {
        protocol_version: PROTOCOL_VERSION,
        run_id: RUN_ID.to_string(),
        target: "input/foxhole_test_helper.exe".to_string(),
        target_sha256: Some(SHA256_ZERO.to_string()),
        arguments: vec!["emit".to_string(), "stdout".to_string(), "safe".to_string()],
        timeout_seconds: 15,
        network_policy: GuestNetworkPolicy::DenyAll,
        allowed_networks: Vec::new(),
        guest_ipv4: None,
        prefix_length: None,
        gateway_ipv4: None,
        dns_servers: Vec::new(),
        host_service_ipv4: None,
        host_service_port: None,
        mitigation_profile: GuestMitigationProfile::Strict,
        execution_profile:
            foxhole::sandbox::hyperv::guest_protocol::GuestExecutionProfile::Restricted,
        resource_limits: GuestResourceLimits::default(),
        capture: CaptureOptions::default(),
        shutdown_when_complete: true,
    }
}

fn artifact(relative_path: &str, size_bytes: u64) -> ArtifactManifestEntry {
    ArtifactManifestEntry {
        relative_path: relative_path.to_string(),
        size_bytes,
        sha256: SHA256_ZERO.to_string(),
        kind: "test_output".to_string(),
    }
}

fn valid_result_envelope() -> GuestResultEnvelope<()> {
    let not_requested = || CaptureCoverage {
        requested: false,
        collected: false,
        complete: true,
        warnings: Vec::new(),
    };
    GuestResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        run_id: RUN_ID.to_string(),
        agent_version: "phase8-test-agent".to_string(),
        guest_image_version: "phase8-test-image".to_string(),
        outcome: GuestTerminalOutcome::Completed,
        execution: Some(()),
        coverage: ObservationCoverage {
            stdout: not_requested(),
            stderr: not_requested(),
            processes: not_requested(),
            network: not_requested(),
            filesystem: not_requested(),
            registry: not_requested(),
        },
        artifacts: Vec::new(),
        warnings: Vec::new(),
        network_attestation: None,
        error: None,
    }
}

#[cfg(target_os = "windows")]
mod real_hyperv {
    use std::ffi::OsString;
    use std::fs;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const OPT_IN_VARIABLE: &str = "FOXHOLE_HYPERV_TESTS";
    const BASE_IMAGE_VARIABLE: &str = "FOXHOLE_HYPERV_BASE_IMAGE";
    const BASE_MANIFEST_VARIABLE: &str = "FOXHOLE_HYPERV_BASE_MANIFEST";
    const MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;
    const REAL_TEST_DEADLINE: Duration = Duration::from_secs(180);
    static CANARY_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    #[ignore = "requires a disposable Hyper-V test host and FOXHOLE_HYPERV_TESTS=1"]
    fn real_hyperv_runs_the_bounded_emit_helper() {
        let config = require_explicit_opt_in();
        let output = run_helper(&config, &["emit", "stdout", "phase8-hyperv-smoke"]);
        assert!(
            output.status.success(),
            "Hyper-V emit smoke failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("exit=Some(0)"),
            "sandbox summary did not contain a successful target exit"
        );
    }

    #[test]
    #[ignore = "requires a disposable Hyper-V test host and FOXHOLE_HYPERV_TESTS=1"]
    fn real_hyperv_times_out_and_cleans_a_bounded_process_tree() {
        let config = require_explicit_opt_in();
        let output = run_helper_with_timeout(&config, &["spawn-tree", "4", "5000"], 1);
        assert!(
            output.status.success(),
            "Hyper-V process-tree timeout failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("timed_out=true"),
            "sandbox summary did not record the timeout"
        );
    }

    #[test]
    #[ignore = "requires a disposable Hyper-V test host and FOXHOLE_HYPERV_TESTS=1"]
    fn real_hyperv_deny_all_blocks_a_bounded_test_net_connection() {
        let config = require_explicit_opt_in();
        let output = run_helper(&config, &["connect", "192.0.2.1:9", "250"]);
        assert!(
            output.status.success(),
            "Hyper-V deny-all check failed at the host coordinator\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("exit=Some(2)"),
            "the guest unexpectedly completed a connection while deny-all networking was selected"
        );
    }

    #[test]
    #[ignore = "requires a disposable Hyper-V test host and FOXHOLE_HYPERV_TESTS=1"]
    fn real_hyperv_cannot_read_a_host_only_canary() {
        let config = require_explicit_opt_in();
        let canary = HostCanary::create();
        let arguments = [
            OsString::from("read-canary"),
            canary.path.clone().into_os_string(),
            OsString::from(&canary.marker),
        ];
        let output = run_helper_os(&config, &arguments, 15);
        assert!(
            output.status.success(),
            "Hyper-V host-filesystem check failed at the host coordinator\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("exit=Some(2)"),
            "the guest unexpectedly read a randomized host-only canary"
        );
    }

    struct RealHyperVConfig {
        base_image: PathBuf,
        base_manifest: PathBuf,
    }

    fn require_explicit_opt_in() -> RealHyperVConfig {
        assert_eq!(
            std::env::var(OPT_IN_VARIABLE).as_deref(),
            Ok("1"),
            "ignored real-Hyper-V tests additionally require {OPT_IN_VARIABLE}=1"
        );
        let base_image = required_path_variable(BASE_IMAGE_VARIABLE);
        let base_manifest = required_path_variable(BASE_MANIFEST_VARIABLE);
        assert!(
            fs::metadata(&base_image).is_ok_and(|metadata| metadata.is_file()),
            "{BASE_IMAGE_VARIABLE} must name an existing base-image file"
        );
        assert!(
            fs::metadata(&base_manifest).is_ok_and(|metadata| metadata.is_file()),
            "{BASE_MANIFEST_VARIABLE} must name an existing base-image manifest file"
        );
        RealHyperVConfig {
            base_image,
            base_manifest,
        }
    }

    fn required_path_variable(name: &str) -> PathBuf {
        let value = std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| panic!("ignored real-Hyper-V tests require {name}"));
        PathBuf::from(value)
    }

    fn run_helper(config: &RealHyperVConfig, arguments: &[&str]) -> BoundedCommandOutput {
        run_helper_with_timeout(config, arguments, 15)
    }

    fn run_helper_with_timeout(
        config: &RealHyperVConfig,
        helper_arguments: &[&str],
        sandbox_timeout_seconds: u64,
    ) -> BoundedCommandOutput {
        let helper_arguments = helper_arguments
            .iter()
            .map(|argument| OsString::from(*argument))
            .collect::<Vec<_>>();
        run_helper_os(config, &helper_arguments, sandbox_timeout_seconds)
    }

    fn run_helper_os(
        config: &RealHyperVConfig,
        helper_arguments: &[OsString],
        sandbox_timeout_seconds: u64,
    ) -> BoundedCommandOutput {
        let mut command = Command::new(env!("CARGO_BIN_EXE_foxhole"));
        command
            .arg("--path")
            .arg(env!("CARGO_BIN_EXE_foxhole_test_helper"))
            .args(["--sandbox", "hyperv", "--hyperv-base-image"])
            .arg(&config.base_image)
            .arg("--hyperv-base-manifest")
            .arg(&config.base_manifest)
            .args(["--no-report", "--timeout"])
            .arg(sandbox_timeout_seconds.to_string())
            .arg("--")
            .args(helper_arguments);
        run_bounded(command)
    }

    struct HostCanary {
        path: PathBuf,
        marker: String,
    }

    impl HostCanary {
        fn create() -> Self {
            for _ in 0..32 {
                let counter = CANARY_COUNTER.fetch_add(1, Ordering::Relaxed);
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let marker = format!(
                    "foxhole-phase8-{}-{timestamp:x}-{counter:x}",
                    std::process::id()
                );
                let path = std::env::temp_dir().join(format!("{marker}.canary"));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        file.write_all(marker.as_bytes())
                            .and_then(|()| file.sync_all())
                            .expect("write randomized host-only canary");
                        return Self { path, marker };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create randomized host-only canary: {error}"),
                }
            }
            panic!("could not allocate a unique host-only canary path");
        }
    }

    impl Drop for HostCanary {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    struct BoundedCommandOutput {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    struct DrainedStream {
        stored: Vec<u8>,
        overflowed: bool,
    }

    fn run_bounded(mut command: Command) -> BoundedCommandOutput {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch Foxhole Hyper-V smoke test");
        let stdout = child.stdout.take().expect("capture Foxhole stdout");
        let stderr = child.stderr.take().expect("capture Foxhole stderr");
        let stdout_reader = thread::spawn(move || drain(stdout));
        let stderr_reader = thread::spawn(move || drain(stderr));

        let deadline = Instant::now() + REAL_TEST_DEADLINE;
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll Foxhole process") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "real Hyper-V test exceeded {} seconds; inspect the disposable host for leftovers",
                    REAL_TEST_DEADLINE.as_secs()
                );
            }
            thread::sleep(Duration::from_millis(50));
        };

        let stdout = stdout_reader.join().expect("join stdout reader");
        let stderr = stderr_reader.join().expect("join stderr reader");
        assert!(
            !stdout.overflowed && !stderr.overflowed,
            "Foxhole diagnostics exceeded the {MAX_DIAGNOSTIC_BYTES}-byte test bound"
        );
        BoundedCommandOutput {
            status,
            stdout: stdout.stored,
            stderr: stderr.stored,
        }
    }

    fn drain(mut input: impl Read) -> DrainedStream {
        let mut stored = Vec::new();
        let mut overflowed = false;
        let mut buffer = [0u8; 8192];
        loop {
            let count = input.read(&mut buffer).expect("drain Foxhole output");
            if count == 0 {
                break;
            }
            let remaining = MAX_DIAGNOSTIC_BYTES.saturating_sub(stored.len());
            let retained = remaining.min(count);
            stored
                .write_all(&buffer[..retained])
                .expect("retain bounded diagnostics");
            overflowed |= retained != count;
        }
        DrainedStream { stored, overflowed }
    }
}
