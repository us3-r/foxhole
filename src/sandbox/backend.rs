use crate::structs::SandboxRunResult;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub type SandboxResult<T> = Result<T, SandboxError>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    RestrictedProcess,
    #[serde(rename = "hyperv")]
    HyperV,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RestrictedProcess => "restricted_process",
            Self::HyperV => "hyperv",
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MitigationProfile {
    Compatible,
    Strict,
    Maximum,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HyperVGuestProfile {
    #[default]
    Restricted,
    Normal,
    Admin,
}

impl fmt::Display for HyperVGuestProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Restricted => "restricted",
            Self::Normal => "normal",
            Self::Admin => "admin",
        })
    }
}

impl fmt::Display for MitigationProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Compatible => "compatible",
            Self::Strict => "strict",
            Self::Maximum => "maximum",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", content = "entries", rename_all = "snake_case")]
pub enum NetworkPolicy {
    DenyAll,
    HostServer,
    AllowList(Vec<IpNetwork>),
    AllowInternet,
    CaptureOnly,
}

impl NetworkPolicy {
    pub fn name(&self) -> &'static str {
        match self {
            Self::DenyAll => "deny_all",
            Self::HostServer => "host_server",
            Self::AllowList(_) => "allow_list",
            Self::AllowInternet => "allow_internet",
            Self::CaptureOnly => "capture_only",
        }
    }

    pub fn needs_internet_capability(&self) -> bool {
        matches!(
            self,
            Self::AllowList(_) | Self::AllowInternet | Self::CaptureOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum IpNetwork {
    V4 { address: Ipv4Addr, prefix: u8 },
    V6 { address: Ipv6Addr, prefix: u8 },
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { address, prefix } => write!(formatter, "{address}/{prefix}"),
            Self::V6 { address, prefix } => write!(formatter, "{address}/{prefix}"),
        }
    }
}

impl FromStr for IpNetwork {
    type Err = SandboxError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match value.rsplit_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value, None),
        };

        if let Ok(address) = address.parse::<Ipv4Addr>() {
            let prefix = parse_prefix(prefix, 32, value)?;
            return Ok(Self::V4 { address, prefix });
        }
        if let Ok(address) = address.parse::<Ipv6Addr>() {
            let prefix = parse_prefix(prefix, 128, value)?;
            return Ok(Self::V6 { address, prefix });
        }

        Err(SandboxError::new(
            "request_validation",
            format!("allow-list entry is not an IPv4/IPv6 address or CIDR: {value}"),
        ))
    }
}

fn parse_prefix(prefix: Option<&str>, maximum: u8, original: &str) -> SandboxResult<u8> {
    let Some(prefix) = prefix else {
        return Ok(maximum);
    };
    let prefix = prefix.parse::<u8>().map_err(|_| {
        SandboxError::new(
            "request_validation",
            format!("allow-list entry has an invalid prefix: {original}"),
        )
    })?;
    if prefix > maximum {
        return Err(SandboxError::new(
            "request_validation",
            format!("allow-list prefix exceeds /{maximum}: {original}"),
        ));
    }
    Ok(prefix)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappedPathAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappedPath {
    pub host_path: PathBuf,
    pub guest_name: String,
    pub access: MappedPathAccess,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub active_process_limit: u32,
    pub process_memory_bytes: usize,
    pub job_memory_bytes: usize,
    pub cpu_rate_percent: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            active_process_limit: 32,
            process_memory_bytes: 256 * 1024 * 1024,
            job_memory_bytes: 512 * 1024 * 1024,
            cpu_rate_percent: 50,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxRequest {
    pub target: PathBuf,
    pub arguments: Vec<String>,
    pub timeout_secs: u64,
    pub network_policy: NetworkPolicy,
    pub backend: BackendKind,
    pub resource_limits: ResourceLimits,
    pub mitigation_profile: MitigationProfile,
    pub hyperv_guest_profile: HyperVGuestProfile,
    pub mapped_paths: Vec<MappedPath>,
    pub dry_run: bool,
}

impl SandboxRequest {
    pub fn restricted(target: impl Into<PathBuf>) -> Self {
        Self {
            target: target.into(),
            arguments: Vec::new(),
            timeout_secs: 30,
            network_policy: NetworkPolicy::DenyAll,
            backend: BackendKind::RestrictedProcess,
            resource_limits: ResourceLimits::default(),
            mitigation_profile: MitigationProfile::Compatible,
            hyperv_guest_profile: HyperVGuestProfile::Restricted,
            mapped_paths: Vec::new(),
            dry_run: false,
        }
    }

    pub fn hyperv(target: impl Into<PathBuf>) -> Self {
        Self {
            backend: BackendKind::HyperV,
            ..Self::restricted(target)
        }
    }

    pub fn validate(&self) -> SandboxResult<()> {
        self.validate_common()
    }

    pub fn validate_common(&self) -> SandboxResult<()> {
        if self.timeout_secs == 0 {
            return Err(SandboxError::new(
                "request_validation",
                "timeout must be at least one second",
            ));
        }
        if self.resource_limits.active_process_limit == 0
            || self.resource_limits.process_memory_bytes == 0
            || self.resource_limits.job_memory_bytes == 0
            || !(1..=100).contains(&self.resource_limits.cpu_rate_percent)
        {
            return Err(SandboxError::new(
                "request_validation",
                "resource limits must be non-zero and CPU rate must be between 1 and 100",
            ));
        }
        if self.resource_limits.job_memory_bytes < self.resource_limits.process_memory_bytes {
            return Err(SandboxError::new(
                "request_validation",
                "job memory limit cannot be smaller than the per-process memory limit",
            ));
        }
        if self.backend != BackendKind::HyperV
            && self.hyperv_guest_profile != HyperVGuestProfile::Restricted
        {
            return Err(SandboxError::new(
                "request_validation",
                "normal and admin guest profiles require the Hyper-V backend",
            ));
        }
        if self.backend != BackendKind::HyperV
            && matches!(self.network_policy, NetworkPolicy::HostServer)
        {
            return Err(SandboxError::new(
                "request_validation",
                "host-server networking is supported only by the Hyper-V backend",
            ));
        }
        if self.hyperv_guest_profile != HyperVGuestProfile::Restricted
            && self.mitigation_profile != MitigationProfile::Compatible
        {
            return Err(SandboxError::new(
                "request_validation",
                "normal and admin guest profiles currently require the compatible mitigation profile",
            ));
        }

        let mut names = std::collections::HashSet::new();
        for mapping in &self.mapped_paths {
            if mapping.guest_name.is_empty()
                || mapping.guest_name == "."
                || mapping.guest_name == ".."
                || mapping.guest_name.contains(['/', '\\'])
                || crate::artifact::validate_windows_file_name_component(std::ffi::OsStr::new(
                    &mapping.guest_name,
                ))
                .is_err()
                || !names.insert(mapping.guest_name.to_ascii_lowercase())
            {
                return Err(SandboxError::new(
                    "request_validation",
                    format!(
                        "invalid or duplicate mapped-path name: {}",
                        mapping.guest_name
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_for_backend(&self, expected: BackendKind) -> SandboxResult<()> {
        self.validate_common()?;
        if self.backend != expected {
            return Err(SandboxError::new(
                "request_validation",
                format!(
                    "{} backend received a request for {}",
                    expected, self.backend
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendState {
    Created,
    Preparing,
    Ready,
    Running,
    Completed,
    Failed,
    Cleaning,
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportStage {
    pub stage: String,
    pub start_time_unix_ms: u64,
    pub end_time_unix_ms: u64,
    pub duration_ms: u64,
    pub success: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl ReportStage {
    pub fn instant(stage: impl Into<String>, success: bool) -> Self {
        let timestamp = unix_time_ms();
        Self {
            stage: stage.into(),
            start_time_unix_ms: timestamp,
            end_time_unix_ms: timestamp,
            duration_ms: 0,
            success,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

pub struct StageTimer {
    stage: String,
    started_at: Instant,
    start_time_unix_ms: u64,
}

impl StageTimer {
    pub fn start(stage: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            started_at: Instant::now(),
            start_time_unix_ms: unix_time_ms(),
        }
    }

    pub fn finish(self, success: bool, warnings: Vec<String>, errors: Vec<String>) -> ReportStage {
        let end_time_unix_ms = unix_time_ms().max(self.start_time_unix_ms);
        ReportStage {
            stage: self.stage,
            start_time_unix_ms: self.start_time_unix_ms,
            end_time_unix_ms,
            duration_ms: self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
            success,
            warnings,
            errors,
        }
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend")]
#[allow(clippy::large_enum_variant)]
pub enum BackendMetadata {
    #[serde(rename = "restricted_process")]
    RestrictedProcess {
        profile_name: Option<String>,
        integrity_level: String,
        mitigation_profile: String,
    },
    #[serde(rename = "hyperv")]
    HyperV {
        run_id: String,
        guest_image_version: String,
        protocol_version: u32,
        vm_generation: u8,
        secure_boot: bool,
        cpu_count: u16,
        startup_memory_bytes: u64,
        data_disk_bytes: u64,
        maximum_os_disk_growth_bytes: u64,
        network_mode: String,
        network: HyperVNetworkMetadata,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HyperVNetworkVerification {
    pub verified: bool,
    pub adapter_count: u32,
    pub switch_id: Option<String>,
    pub switch_type: Option<String>,
    pub host_adapter_id: Option<String>,
    pub firewall_scope_id: Option<String>,
    pub host_ipv4: Option<Ipv4Addr>,
    pub guest_ipv4: Option<Ipv4Addr>,
    pub nat_enabled: bool,
    pub firewall_rule_ids: Vec<String>,
    pub capture_active: bool,
    pub ipv6_disabled: bool,
    pub no_unexpected_routes: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HyperVNetworkMetadata {
    pub requested_mode: String,
    pub switch_id: Option<String>,
    pub switch_type: Option<String>,
    pub guest_ipv4: Option<Ipv4Addr>,
    pub prefix_length: Option<u8>,
    pub gateway_ipv4: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub host_service_endpoint: Option<String>,
    pub firewall_scope_id: Option<String>,
    pub firewall_rule_ids: Vec<String>,
    pub capture_status: String,
    pub pre_run_verification: Option<HyperVNetworkVerification>,
    pub post_run_verification: Option<HyperVNetworkVerification>,
    pub cleanup_results: Vec<String>,
    pub warnings: Vec<String>,
}

pub trait SandboxBackend {
    fn prepare(&mut self, request: &SandboxRequest) -> SandboxResult<()>;
    fn execute(&mut self, request: &SandboxRequest) -> SandboxResult<SandboxRunResult>;
    fn cleanup(&mut self) -> SandboxResult<()>;
}

#[derive(Debug)]
pub struct SandboxError {
    pub stage: &'static str,
    pub message: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl SandboxError {
    pub fn new(stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        stage: &'static str,
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            stage,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.stage, self.message)?;
        if let Some(source) = self.source.as_deref() {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl Error for SandboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn parses_ipv4_and_ipv6_allow_list_entries() {
        assert_eq!(
            "192.0.2.0/24".parse::<IpNetwork>().unwrap(),
            IpNetwork::V4 {
                address: Ipv4Addr::new(192, 0, 2, 0),
                prefix: 24
            }
        );
        assert_eq!(
            "2001:db8::1".parse::<IpNetwork>().unwrap(),
            IpNetwork::V6 {
                address: "2001:db8::1".parse().unwrap(),
                prefix: 128
            }
        );
    }

    #[test]
    fn rejects_invalid_allow_list_prefixes() {
        assert!("192.0.2.1/33".parse::<IpNetwork>().is_err());
        assert!("2001:db8::/129".parse::<IpNetwork>().is_err());
    }

    #[test]
    fn validates_mapped_path_names() {
        let mut request = SandboxRequest::restricted("sample.exe");
        request.mapped_paths.push(MappedPath {
            host_path: PathBuf::from("data"),
            guest_name: "../escape".to_string(),
            access: MappedPathAccess::ReadOnly,
        });
        assert!(request.validate().is_err());
    }

    #[test]
    fn rejects_windows_unsafe_mapped_path_names() {
        for guest_name in [
            "C:escape",
            "file:stream",
            "CON",
            "NUL.txt",
            "COM1.log",
            "trailing.",
            "trailing ",
        ] {
            let mut request = SandboxRequest::restricted("sample.exe");
            request.mapped_paths.push(MappedPath {
                host_path: PathBuf::from("data"),
                guest_name: guest_name.to_string(),
                access: MappedPathAccess::ReadOnly,
            });
            assert!(
                request.validate().is_err(),
                "Windows-unsafe mapping name should be rejected: {guest_name}"
            );
        }
    }

    #[test]
    fn names_defaults_and_capabilities_are_stable() {
        assert_eq!(
            BackendKind::RestrictedProcess.to_string(),
            "restricted_process"
        );
        assert_eq!(BackendKind::HyperV.to_string(), "hyperv");
        assert_eq!(
            serde_json::to_string(&BackendKind::HyperV).unwrap(),
            "\"hyperv\""
        );
        assert_eq!(MitigationProfile::Compatible.to_string(), "compatible");
        assert_eq!(MitigationProfile::Strict.to_string(), "strict");
        assert_eq!(MitigationProfile::Maximum.to_string(), "maximum");

        let policies = [
            (NetworkPolicy::DenyAll, "deny_all", false),
            (NetworkPolicy::HostServer, "host_server", false),
            (NetworkPolicy::AllowList(Vec::new()), "allow_list", true),
            (NetworkPolicy::AllowInternet, "allow_internet", true),
            (NetworkPolicy::CaptureOnly, "capture_only", true),
        ];
        for (policy, name, capability) in policies {
            assert_eq!(policy.name(), name);
            assert_eq!(policy.needs_internet_capability(), capability);
        }

        let request = SandboxRequest::restricted("sample.exe");
        assert_eq!(request.timeout_secs, 30);
        assert_eq!(request.resource_limits, ResourceLimits::default());
        assert_eq!(request.resource_limits.active_process_limit, 32);
        assert!(request.validate().is_ok());
        let request = SandboxRequest::hyperv("sample.exe");
        assert_eq!(request.backend, BackendKind::HyperV);
        assert!(request.validate_for_backend(BackendKind::HyperV).is_ok());
        assert!(
            request
                .validate_for_backend(BackendKind::RestrictedProcess)
                .is_err()
        );
    }

    #[test]
    fn address_parsing_covers_defaults_display_and_malformed_values() {
        let v4 = "192.0.2.1".parse::<IpNetwork>().unwrap();
        assert_eq!(v4.to_string(), "192.0.2.1/32");
        let v6 = "2001:db8::/64".parse::<IpNetwork>().unwrap();
        assert_eq!(v6.to_string(), "2001:db8::/64");

        for value in ["not-an-ip", "192.0.2.1/nope", "2001:db8::/999"] {
            let error = value
                .parse::<IpNetwork>()
                .expect_err("must reject malformed CIDR");
            assert_eq!(error.stage, "request_validation");
        }
    }

    #[test]
    fn every_resource_limit_failure_is_rejected() {
        let mut cases = Vec::new();
        let mut request = SandboxRequest::restricted("sample.exe");
        request.timeout_secs = 0;
        cases.push(request);

        for mutate in [
            |limits: &mut ResourceLimits| limits.active_process_limit = 0,
            |limits: &mut ResourceLimits| limits.process_memory_bytes = 0,
            |limits: &mut ResourceLimits| limits.job_memory_bytes = 0,
            |limits: &mut ResourceLimits| limits.cpu_rate_percent = 0,
            |limits: &mut ResourceLimits| limits.cpu_rate_percent = 101,
        ] {
            let mut request = SandboxRequest::restricted("sample.exe");
            mutate(&mut request.resource_limits);
            cases.push(request);
        }
        let mut request = SandboxRequest::restricted("sample.exe");
        request.resource_limits.job_memory_bytes = request.resource_limits.process_memory_bytes - 1;
        cases.push(request);

        for request in cases {
            assert!(request.validate().is_err());
        }
    }

    #[test]
    fn guest_profiles_require_hyperv_and_compatible_mitigations() {
        for profile in [HyperVGuestProfile::Normal, HyperVGuestProfile::Admin] {
            let mut local = SandboxRequest::restricted("sample.exe");
            local.hyperv_guest_profile = profile;
            assert!(local.validate().is_err());

            let mut hyperv = SandboxRequest::hyperv("sample.exe");
            hyperv.hyperv_guest_profile = profile;
            assert!(hyperv.validate().is_ok());
            hyperv.mitigation_profile = MitigationProfile::Strict;
            assert!(hyperv.validate().is_err());
        }
    }

    #[test]
    fn every_unsafe_or_duplicate_mapping_name_is_rejected() {
        for names in [
            vec![""],
            vec!["."],
            vec![".."],
            vec!["a/b"],
            vec![r"a\b"],
            vec!["Data", "data"],
        ] {
            let mut request = SandboxRequest::restricted("sample.exe");
            request.mapped_paths = names
                .into_iter()
                .map(|name| MappedPath {
                    host_path: PathBuf::from("data"),
                    guest_name: name.to_string(),
                    access: MappedPathAccess::ReadWrite,
                })
                .collect();
            assert!(request.validate().is_err());
        }
    }

    #[test]
    fn sandbox_errors_preserve_stage_message_and_source() {
        let plain = SandboxError::new("prepare", "failed");
        assert_eq!(plain.to_string(), "prepare: failed");
        assert!(plain.source().is_none());

        let sourced = SandboxError::with_source(
            "workspace",
            "open file",
            io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
        );
        assert!(sourced.to_string().contains("workspace: open file: denied"));
        assert!(sourced.source().is_some());
    }

    #[test]
    fn report_stage_timers_are_monotonic_and_structured() {
        let stage = StageTimer::start("preparation").finish(
            false,
            vec!["warning".to_string()],
            vec!["error".to_string()],
        );
        assert_eq!(stage.stage, "preparation");
        assert!(stage.end_time_unix_ms >= stage.start_time_unix_ms);
        assert!(!stage.success);
        assert_eq!(stage.warnings, ["warning"]);
        assert_eq!(stage.errors, ["error"]);

        let instant = ReportStage::instant("cleanup", true);
        assert_eq!(instant.start_time_unix_ms, instant.end_time_unix_ms);
        assert_eq!(instant.duration_ms, 0);
        assert!(instant.success);
    }
}
