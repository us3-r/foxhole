//! Versioned, bounded messages exchanged between the Hyper-V host and guest agent.
//!
//! This module deliberately contains no Hyper-V or Windows APIs. The host, guest agent, and
//! cross-platform tests can therefore share exactly the same parser and state machine.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: u32 = 2;
pub const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
pub const MAX_STATUS_BYTES: u64 = 64 * 1024;
pub const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_RUN_ID_BYTES: usize = 64;
pub const MAX_WIRE_PATH_BYTES: usize = 1024;
pub const MAX_ARGUMENTS: usize = 128;
pub const MAX_ARGUMENT_BYTES: usize = 32 * 1024;
pub const MAX_ARGUMENT_TOTAL_BYTES: usize = 128 * 1024;
pub const MAX_ALLOWED_NETWORKS: usize = 128;
pub const MAX_TIMEOUT_SECONDS: u64 = 60 * 60;
pub const MAX_ACTIVE_PROCESSES: u32 = 1024;
pub const MAX_GUEST_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_WARNINGS: usize = 256;
pub const MAX_WARNING_BYTES: usize = 4096;
pub const MAX_ARTIFACTS: usize = 4096;
pub const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_TOTAL_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

static TEMPORARY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: &'static str,
    pub message: String,
}

impl ProtocolError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuestNetworkPolicy {
    DenyAll,
    HostServer,
    AllowList,
    AllowInternet,
    CaptureOnly,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuestMitigationProfile {
    Compatible,
    Strict,
    Maximum,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuestExecutionProfile {
    #[default]
    Restricted,
    Normal,
    Admin,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestResourceLimits {
    pub active_process_limit: u32,
    pub process_memory_bytes: u64,
    pub job_memory_bytes: u64,
    pub cpu_rate_percent: u32,
}

impl Default for GuestResourceLimits {
    fn default() -> Self {
        Self {
            active_process_limit: 32,
            process_memory_bytes: 256 * 1024 * 1024,
            job_memory_bytes: 512 * 1024 * 1024,
            cpu_rate_percent: 50,
        }
    }
}

impl GuestResourceLimits {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.active_process_limit == 0 || self.active_process_limit > MAX_ACTIVE_PROCESSES {
            return Err(ProtocolError::new(
                "invalid_resource_limits",
                format!("active process limit must be between 1 and {MAX_ACTIVE_PROCESSES}"),
            ));
        }
        if self.process_memory_bytes == 0
            || self.process_memory_bytes > MAX_GUEST_MEMORY_BYTES
            || self.job_memory_bytes == 0
            || self.job_memory_bytes > MAX_GUEST_MEMORY_BYTES
            || self.job_memory_bytes < self.process_memory_bytes
        {
            return Err(ProtocolError::new(
                "invalid_resource_limits",
                "guest memory limits are zero, out of range, or internally inconsistent",
            ));
        }
        if !(1..=100).contains(&self.cpu_rate_percent) {
            return Err(ProtocolError::new(
                "invalid_resource_limits",
                "CPU rate must be between 1 and 100 percent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaptureOptions {
    pub stdout: bool,
    pub stderr: bool,
    pub processes: bool,
    pub network: bool,
    pub filesystem: bool,
    pub registry: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            stdout: true,
            stderr: true,
            processes: true,
            network: true,
            filesystem: true,
            registry: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestRunRequest {
    pub protocol_version: u32,
    pub run_id: String,
    /// Slash-separated path relative to the run-data root, normally `input/target.exe`.
    pub target: String,
    pub target_sha256: Option<String>,
    pub arguments: Vec<String>,
    pub timeout_seconds: u64,
    pub network_policy: GuestNetworkPolicy,
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    #[serde(default)]
    pub guest_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub prefix_length: Option<u8>,
    #[serde(default)]
    pub gateway_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    #[serde(default)]
    pub host_service_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub host_service_port: Option<u16>,
    pub mitigation_profile: GuestMitigationProfile,
    #[serde(default)]
    pub execution_profile: GuestExecutionProfile,
    #[serde(default)]
    pub resource_limits: GuestResourceLimits,
    #[serde(default)]
    pub capture: CaptureOptions,
    /// The agent only requests guest shutdown when this flag was explicitly set by the host.
    #[serde(default)]
    pub shutdown_when_complete: bool,
}

impl GuestRunRequest {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_protocol_version(self.protocol_version)?;
        validate_run_id(&self.run_id)?;
        validate_relative_wire_path(&self.target)?;
        if !self.target.starts_with("input/") {
            return Err(ProtocolError::new(
                "invalid_target",
                "target must be located below the input directory",
            ));
        }
        let target_digest = self.target_sha256.as_deref().ok_or_else(|| {
            ProtocolError::new(
                "invalid_target",
                "target_sha256 is required for every guest execution request",
            )
        })?;
        validate_sha256(target_digest)?;
        if self.arguments.len() > MAX_ARGUMENTS {
            return Err(ProtocolError::new(
                "invalid_arguments",
                format!("request contains more than {MAX_ARGUMENTS} arguments"),
            ));
        }
        let mut total = 0usize;
        for argument in &self.arguments {
            if argument.contains('\0') || argument.len() > MAX_ARGUMENT_BYTES {
                return Err(ProtocolError::new(
                    "invalid_arguments",
                    "an argument contains NUL or exceeds the per-argument byte limit",
                ));
            }
            total = total.checked_add(argument.len()).ok_or_else(|| {
                ProtocolError::new("invalid_arguments", "argument byte count overflowed")
            })?;
        }
        if total > MAX_ARGUMENT_TOTAL_BYTES {
            return Err(ProtocolError::new(
                "invalid_arguments",
                format!("argument bytes exceed {MAX_ARGUMENT_TOTAL_BYTES}"),
            ));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(ProtocolError::new(
                "invalid_timeout",
                format!("timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"),
            ));
        }
        if self.allowed_networks.len() > MAX_ALLOWED_NETWORKS {
            return Err(ProtocolError::new(
                "invalid_network_policy",
                format!("allow list contains more than {MAX_ALLOWED_NETWORKS} entries"),
            ));
        }
        if self.network_policy != GuestNetworkPolicy::AllowList && !self.allowed_networks.is_empty()
        {
            return Err(ProtocolError::new(
                "invalid_network_policy",
                "allowed_networks is only valid with allow_list policy",
            ));
        }
        if self.network_policy == GuestNetworkPolicy::AllowList && self.allowed_networks.is_empty()
        {
            return Err(ProtocolError::new(
                "invalid_network_policy",
                "allow_list policy requires at least one network",
            ));
        }
        for network in &self.allowed_networks {
            validate_ip_network(network)?;
        }
        self.validate_network_configuration()?;
        if self.execution_profile != GuestExecutionProfile::Restricted
            && self.mitigation_profile != GuestMitigationProfile::Compatible
        {
            return Err(ProtocolError::new(
                "invalid_execution_profile",
                "normal and admin execution profiles require the compatible mitigation profile",
            ));
        }
        self.resource_limits.validate()
    }

    fn validate_network_configuration(&self) -> ProtocolResult<()> {
        let configured = self.guest_ipv4.is_some()
            || self.prefix_length.is_some()
            || self.gateway_ipv4.is_some()
            || !self.dns_servers.is_empty()
            || self.host_service_ipv4.is_some()
            || self.host_service_port.is_some();
        if matches!(
            self.network_policy,
            GuestNetworkPolicy::DenyAll
                | GuestNetworkPolicy::AllowList
                | GuestNetworkPolicy::CaptureOnly
        ) {
            if configured {
                return Err(ProtocolError::new(
                    "invalid_network_configuration",
                    "per-run NIC configuration is valid only for host_server or allow_internet",
                ));
            }
            return Ok(());
        }
        let guest = self.guest_ipv4.ok_or_else(|| {
            ProtocolError::new(
                "invalid_network_configuration",
                "networked guest request requires guest_ipv4",
            )
        })?;
        let prefix = self.prefix_length.ok_or_else(|| {
            ProtocolError::new(
                "invalid_network_configuration",
                "networked guest request requires prefix_length",
            )
        })?;
        if !(1..=30).contains(&prefix) || !valid_guest_unicast(guest) {
            return Err(ProtocolError::new(
                "invalid_network_configuration",
                "guest address or prefix is unsafe",
            ));
        }
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(guest) & mask;
        let broadcast = u32::from(guest) | !mask;
        if u32::from(guest) == network || u32::from(guest) == broadcast {
            return Err(ProtocolError::new(
                "invalid_network_configuration",
                "guest address is the subnet network or broadcast address",
            ));
        }
        match self.network_policy {
            GuestNetworkPolicy::HostServer => {
                let host = self.host_service_ipv4.ok_or_else(|| {
                    ProtocolError::new(
                        "invalid_network_configuration",
                        "host_server requires host_service_ipv4",
                    )
                })?;
                if !valid_guest_unicast(host)
                    || host == guest
                    || (u32::from(host) & mask) != network
                    || self.host_service_port.is_none_or(|port| port == 0)
                    || self.gateway_ipv4.is_some()
                    || !self.dns_servers.is_empty()
                {
                    return Err(ProtocolError::new(
                        "invalid_network_configuration",
                        "host_server endpoint, gateway, or DNS configuration is unsafe",
                    ));
                }
            }
            GuestNetworkPolicy::AllowInternet => {
                let gateway = self.gateway_ipv4.ok_or_else(|| {
                    ProtocolError::new(
                        "invalid_network_configuration",
                        "allow_internet requires gateway_ipv4",
                    )
                })?;
                if !valid_guest_unicast(gateway)
                    || gateway == guest
                    || (u32::from(gateway) & mask) != network
                    || self.dns_servers.is_empty()
                    || self.dns_servers.len() > 8
                    || self.dns_servers.iter().any(|address| {
                        !valid_guest_unicast(*address)
                            || address.is_private()
                            || address.is_documentation()
                    })
                    || self.host_service_ipv4.is_some()
                    || self.host_service_port.is_some()
                {
                    return Err(ProtocolError::new(
                        "invalid_network_configuration",
                        "allow_internet gateway, DNS, or host-service configuration is unsafe",
                    ));
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

fn valid_guest_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolActor {
    Host,
    Guest,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolState {
    HostReady,
    RequestWritten,
    StartAllowed,
    CancelRequested,
    GuestReady,
    Running,
    Completed,
    Failed,
    ShutdownReady,
}

impl ProtocolState {
    pub fn actor(self) -> ProtocolActor {
        match self {
            Self::HostReady | Self::RequestWritten | Self::StartAllowed | Self::CancelRequested => {
                ProtocolActor::Host
            }
            Self::GuestReady
            | Self::Running
            | Self::Completed
            | Self::Failed
            | Self::ShutdownReady => ProtocolActor::Guest,
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Self::HostReady => "host-ready.json",
            Self::RequestWritten => "request-written.json",
            Self::StartAllowed => "start-allowed.json",
            Self::CancelRequested => "cancel-requested.json",
            Self::GuestReady => "guest-ready.json",
            Self::Running => "running.json",
            Self::Completed => "completed.json",
            Self::Failed => "failed.json",
            Self::ShutdownReady => "shutdown-ready.json",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestError {
    pub stage: String,
    pub code: String,
    pub message: String,
}

impl GuestError {
    pub fn new(
        stage: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage: stage.into(),
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_small_field("error stage", &self.stage, 128)?;
        validate_small_field("error code", &self.code, 128)?;
        validate_small_field("error message", &self.message, MAX_WARNING_BYTES)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusRecord {
    pub protocol_version: u32,
    pub run_id: String,
    pub sequence: u64,
    pub actor: ProtocolActor,
    pub state: ProtocolState,
    pub timestamp_ms: u64,
    pub request_sha256: Option<String>,
    pub result_sha256: Option<String>,
    pub error: Option<GuestError>,
}

impl StatusRecord {
    pub fn new(run_id: impl Into<String>, sequence: u64, state: ProtocolState) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            run_id: run_id.into(),
            sequence,
            actor: state.actor(),
            state,
            timestamp_ms: unix_timestamp_ms(),
            request_sha256: None,
            result_sha256: None,
            error: None,
        }
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_protocol_version(self.protocol_version)?;
        validate_run_id(&self.run_id)?;
        if self.sequence == 0 {
            return Err(ProtocolError::new(
                "invalid_status",
                "status sequence must be non-zero",
            ));
        }
        if self.actor != self.state.actor() {
            return Err(ProtocolError::new(
                "invalid_status",
                "status actor does not own the state",
            ));
        }
        let request_digest = self.request_sha256.as_deref().ok_or_else(|| {
            ProtocolError::new(
                "invalid_status",
                "every protocol status must authenticate request.json",
            )
        })?;
        validate_sha256(request_digest)?;
        if let Some(digest) = self.result_sha256.as_deref() {
            validate_sha256(digest)?;
        }
        if let Some(error) = self.error.as_ref() {
            error.validate()?;
        }
        if self.state == ProtocolState::Failed && self.error.is_none() {
            return Err(ProtocolError::new(
                "invalid_status",
                "failed status requires an error",
            ));
        }
        if self.state != ProtocolState::Failed && self.error.is_some() {
            return Err(ProtocolError::new(
                "invalid_status",
                "only failed status may carry an error",
            ));
        }
        if self.state == ProtocolState::Completed && self.result_sha256.is_none() {
            return Err(ProtocolError::new(
                "invalid_status",
                "completed status must authenticate result.json",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuestTerminalOutcome {
    Completed,
    TimedOut,
    Cancelled,
    AgentFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaptureCoverage {
    pub requested: bool,
    pub collected: bool,
    pub complete: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl CaptureCoverage {
    pub fn unavailable(requested: bool, warning: impl Into<String>) -> Self {
        Self {
            requested,
            collected: false,
            complete: !requested,
            warnings: requested.then(|| warning.into()).into_iter().collect(),
        }
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.complete && self.requested && !self.collected {
            return Err(ProtocolError::new(
                "invalid_coverage",
                "requested capture cannot be complete when nothing was collected",
            ));
        }
        validate_warnings(&self.warnings)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationCoverage {
    pub stdout: CaptureCoverage,
    pub stderr: CaptureCoverage,
    pub processes: CaptureCoverage,
    pub network: CaptureCoverage,
    pub filesystem: CaptureCoverage,
    pub registry: CaptureCoverage,
}

impl ObservationCoverage {
    pub fn validate(&self) -> ProtocolResult<()> {
        self.stdout.validate()?;
        self.stderr.validate()?;
        self.processes.validate()?;
        self.network.validate()?;
        self.filesystem.validate()?;
        self.registry.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifestEntry {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub kind: String,
}

impl ArtifactManifestEntry {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_relative_wire_path(&self.relative_path)?;
        if self.size_bytes > MAX_ARTIFACT_BYTES {
            return Err(ProtocolError::new(
                "invalid_artifact",
                format!("artifact exceeds {MAX_ARTIFACT_BYTES} bytes"),
            ));
        }
        validate_sha256(&self.sha256)?;
        validate_small_field("artifact kind", &self.kind, 64)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestNetworkAttestation {
    pub interface_index: u32,
    pub interface_guid: String,
    pub mac_address: String,
    pub guest_ipv4: Ipv4Addr,
    pub prefix_length: u8,
    #[serde(default)]
    pub gateway_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub ipv6_disabled: bool,
    pub no_unexpected_routes: bool,
}

impl GuestNetworkAttestation {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.interface_index == 0
            || self.interface_guid.is_empty()
            || self.interface_guid.len() > 128
            || self.mac_address.is_empty()
            || self.mac_address.len() > 32
            || !valid_guest_unicast(self.guest_ipv4)
            || !(1..=30).contains(&self.prefix_length)
            || self
                .gateway_ipv4
                .is_some_and(|address| !valid_guest_unicast(address))
            || self.dns_servers.len() > 8
            || self
                .dns_servers
                .iter()
                .any(|address| !valid_guest_unicast(*address))
            || !self.ipv6_disabled
            || !self.no_unexpected_routes
        {
            return Err(ProtocolError::new(
                "invalid_network_attestation",
                "guest NIC attestation is incomplete or unsafe",
            ));
        }
        validate_small_field("guest interface GUID", &self.interface_guid, 128)?;
        validate_small_field("guest MAC address", &self.mac_address, 32)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestResultEnvelope<T> {
    pub protocol_version: u32,
    pub run_id: String,
    pub agent_version: String,
    pub guest_image_version: String,
    pub outcome: GuestTerminalOutcome,
    pub execution: Option<T>,
    pub coverage: ObservationCoverage,
    #[serde(default)]
    pub artifacts: Vec<ArtifactManifestEntry>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub network_attestation: Option<GuestNetworkAttestation>,
    pub error: Option<GuestError>,
}

impl<T> GuestResultEnvelope<T> {
    pub fn validate_metadata(&self) -> ProtocolResult<()> {
        validate_protocol_version(self.protocol_version)?;
        validate_run_id(&self.run_id)?;
        validate_small_field("agent version", &self.agent_version, 128)?;
        validate_small_field("guest image version", &self.guest_image_version, 128)?;
        self.coverage.validate()?;
        validate_warnings(&self.warnings)?;
        if let Some(attestation) = self.network_attestation.as_ref() {
            attestation.validate()?;
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(ProtocolError::new(
                "invalid_artifact",
                format!("manifest contains more than {MAX_ARTIFACTS} artifacts"),
            ));
        }
        let mut paths = HashSet::new();
        let mut total = 0u64;
        for artifact in &self.artifacts {
            artifact.validate()?;
            let folded = artifact.relative_path.to_lowercase();
            if !paths.insert(folded) {
                return Err(ProtocolError::new(
                    "invalid_artifact",
                    "manifest contains a case-insensitive duplicate path",
                ));
            }
            total = total.checked_add(artifact.size_bytes).ok_or_else(|| {
                ProtocolError::new("invalid_artifact", "artifact byte count overflowed")
            })?;
        }
        if total > MAX_TOTAL_ARTIFACT_BYTES {
            return Err(ProtocolError::new(
                "invalid_artifact",
                format!("artifact bytes exceed {MAX_TOTAL_ARTIFACT_BYTES}"),
            ));
        }
        if let Some(error) = self.error.as_ref() {
            error.validate()?;
        }
        match self.outcome {
            GuestTerminalOutcome::AgentFailed if self.error.is_none() => Err(ProtocolError::new(
                "invalid_result",
                "agent_failed outcome requires an error",
            )),
            GuestTerminalOutcome::AgentFailed if self.execution.is_some() => {
                Err(ProtocolError::new(
                    "invalid_result",
                    "agent_failed outcome cannot contain an execution result",
                ))
            }
            GuestTerminalOutcome::Completed | GuestTerminalOutcome::TimedOut
                if self.execution.is_none() =>
            {
                Err(ProtocolError::new(
                    "invalid_result",
                    "completed and timed_out outcomes require an execution result",
                ))
            }
            GuestTerminalOutcome::Cancelled if self.execution.is_some() || self.error.is_some() => {
                Err(ProtocolError::new(
                    "invalid_result",
                    "cancelled outcome cannot contain execution data or an agent error",
                ))
            }
            GuestTerminalOutcome::Completed | GuestTerminalOutcome::TimedOut
                if self.error.is_some() =>
            {
                Err(ProtocolError::new(
                    "invalid_result",
                    "successful or timed-out execution cannot carry an agent error",
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolStateMachine {
    run_id: String,
    seen: HashSet<ProtocolState>,
    last_sequence: u64,
}

impl ProtocolStateMachine {
    pub fn new(run_id: impl Into<String>) -> ProtocolResult<Self> {
        let run_id = run_id.into();
        validate_run_id(&run_id)?;
        Ok(Self {
            run_id,
            seen: HashSet::new(),
            last_sequence: 0,
        })
    }

    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn has_seen(&self, state: ProtocolState) -> bool {
        self.seen.contains(&state)
    }

    pub fn observe(&mut self, record: &StatusRecord) -> ProtocolResult<()> {
        record.validate()?;
        if record.run_id != self.run_id {
            return Err(ProtocolError::new(
                "state_run_mismatch",
                "status belongs to a different run",
            ));
        }
        if record.sequence <= self.last_sequence {
            return Err(ProtocolError::new(
                "state_sequence",
                "status sequence did not increase",
            ));
        }
        if self.seen.contains(&record.state) {
            return Err(ProtocolError::new(
                "state_replay",
                "protocol state was published more than once",
            ));
        }
        self.validate_prerequisites(record.state)?;
        self.last_sequence = record.sequence;
        self.seen.insert(record.state);
        Ok(())
    }

    fn validate_prerequisites(&self, state: ProtocolState) -> ProtocolResult<()> {
        let seen = |state| self.seen.contains(&state);
        let terminal = seen(ProtocolState::Completed)
            || seen(ProtocolState::Failed)
            || seen(ProtocolState::CancelRequested)
            || seen(ProtocolState::ShutdownReady);
        if terminal && state != ProtocolState::ShutdownReady {
            return Err(ProtocolError::new(
                "state_terminal",
                "no non-shutdown state may follow a terminal state",
            ));
        }

        let valid = match state {
            ProtocolState::HostReady => self.seen.is_empty(),
            ProtocolState::RequestWritten => seen(ProtocolState::HostReady),
            ProtocolState::StartAllowed => {
                seen(ProtocolState::RequestWritten) && !seen(ProtocolState::Running) && !terminal
            }
            ProtocolState::GuestReady => seen(ProtocolState::RequestWritten) && !terminal,
            ProtocolState::Running => {
                seen(ProtocolState::GuestReady) && seen(ProtocolState::StartAllowed) && !terminal
            }
            ProtocolState::Completed => seen(ProtocolState::Running) && !terminal,
            ProtocolState::Failed => seen(ProtocolState::RequestWritten) && !terminal,
            ProtocolState::CancelRequested => {
                seen(ProtocolState::RequestWritten)
                    && !seen(ProtocolState::Completed)
                    && !seen(ProtocolState::Failed)
            }
            ProtocolState::ShutdownReady => {
                seen(ProtocolState::Completed)
                    || seen(ProtocolState::Failed)
                    || seen(ProtocolState::CancelRequested)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(ProtocolError::new(
                "state_transition",
                format!("prerequisites for state {state:?} were not met"),
            ))
        }
    }
}

pub fn validate_protocol_version(version: u32) -> ProtocolResult<()> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::new(
            "unsupported_protocol",
            format!("expected protocol {PROTOCOL_VERSION}, received {version}"),
        ))
    }
}

pub fn validate_run_id(run_id: &str) -> ProtocolResult<()> {
    if !(8..=MAX_RUN_ID_BYTES).contains(&run_id.len())
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProtocolError::new(
            "invalid_run_id",
            "run id must be 8-64 ASCII letters, digits, hyphens, or underscores",
        ));
    }
    Ok(())
}

pub fn validate_sha256(digest: &str) -> ProtocolResult<()> {
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ProtocolError::new(
            "invalid_checksum",
            "SHA-256 value must contain exactly 64 hexadecimal characters",
        ))
    }
}

pub fn validate_relative_wire_path(value: &str) -> ProtocolResult<()> {
    if value.is_empty()
        || value.len() > MAX_WIRE_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains(['\\', '\0', ':'])
        || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::new(
            "invalid_relative_path",
            "path is empty, absolute, non-canonical, or contains a forbidden character",
        ));
    }
    for component in value.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.ends_with(['.', ' '])
            || is_reserved_windows_component(component)
        {
            return Err(ProtocolError::new(
                "invalid_relative_path",
                format!("path contains an unsafe component: {component:?}"),
            ));
        }
    }
    Ok(())
}

pub fn wire_path_to_native(root: &Path, value: &str) -> ProtocolResult<PathBuf> {
    validate_relative_wire_path(value)?;
    let mut output = root.to_path_buf();
    for component in value.split('/') {
        output.push(component);
    }
    Ok(output)
}

pub fn read_bounded_json<T: DeserializeOwned>(
    path: &Path,
    maximum_bytes: u64,
) -> ProtocolResult<T> {
    if maximum_bytes == 0 {
        return Err(ProtocolError::new(
            "invalid_bound",
            "JSON byte limit must be non-zero",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ProtocolError::new(
            "protocol_io",
            format!("inspect {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum_bytes {
        return Err(ProtocolError::new(
            "protocol_size",
            format!("{} is not a regular bounded protocol file", path.display()),
        ));
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProtocolError::new(
                "protocol_io",
                format!("{} is a reparse point", path.display()),
            ));
        }
    }
    let mut file = File::open(path).map_err(|error| {
        ProtocolError::new("protocol_io", format!("open {}: {error}", path.display()))
    })?;
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ProtocolError::new("protocol_io", format!("read {}: {error}", path.display()))
        })?;
    if bytes.len() as u64 > maximum_bytes || bytes.len() as u64 != metadata.len() {
        return Err(ProtocolError::new(
            "protocol_size",
            format!("{} changed or grew beyond its byte limit", path.display()),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let value = T::deserialize(&mut deserializer).map_err(|error| {
        ProtocolError::new("invalid_json", format!("parse {}: {error}", path.display()))
    })?;
    deserializer.end().map_err(|error| {
        ProtocolError::new(
            "invalid_json",
            format!("reject trailing data in {}: {error}", path.display()),
        )
    })?;
    Ok(value)
}

pub fn write_atomic_json_new<T: Serialize>(
    path: &Path,
    value: &T,
    maximum_bytes: u64,
) -> ProtocolResult<()> {
    if maximum_bytes == 0 {
        return Err(ProtocolError::new(
            "invalid_bound",
            "JSON byte limit must be non-zero",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ProtocolError::new("protocol_io", "protocol destination has no parent"))?;
    let file_name = path.file_name().ok_or_else(|| {
        ProtocolError::new("protocol_io", "protocol destination has no file name")
    })?;
    let counter = TEMPORARY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        counter
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            ProtocolError::new(
                "protocol_io",
                format!("create {}: {error}", temporary.display()),
            )
        })?;
    let mut cleanup = TemporaryFile::new(temporary.clone());
    let mut writer = BoundedWriter::new(file, maximum_bytes);
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        ProtocolError::new(
            "protocol_json",
            format!("serialize {}: {error}", path.display()),
        )
    })?;
    writer.flush_and_sync().map_err(|error| {
        ProtocolError::new(
            "protocol_io",
            format!("flush {}: {error}", temporary.display()),
        )
    })?;
    drop(writer);

    // A hard link publishes the already-flushed inode and fails if the destination exists.
    // Unlike rename on Unix, this cannot silently replace a status/result written by another
    // process. The run-data volume is required to support hard links.
    fs::hard_link(&temporary, path).map_err(|error| {
        ProtocolError::new(
            "protocol_publish",
            format!("publish {} without replacement: {error}", path.display()),
        )
    })?;
    fs::remove_file(&temporary).map_err(|error| {
        ProtocolError::new(
            "protocol_publish",
            format!("remove published temporary file: {error}"),
        )
    })?;
    cleanup.committed = true;
    Ok(())
}

pub fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn validate_ip_network(value: &str) -> ProtocolResult<()> {
    if value.is_empty() || value.len() > 128 {
        return Err(ProtocolError::new(
            "invalid_network_policy",
            "network entry is empty or too long",
        ));
    }
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address = address.parse::<IpAddr>().map_err(|_| {
        ProtocolError::new(
            "invalid_network_policy",
            format!("invalid IP address or CIDR: {value}"),
        )
    })?;
    if let Some(prefix) = prefix {
        let prefix = prefix.parse::<u8>().map_err(|_| {
            ProtocolError::new(
                "invalid_network_policy",
                format!("invalid CIDR prefix: {value}"),
            )
        })?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(ProtocolError::new(
                "invalid_network_policy",
                format!("CIDR prefix exceeds /{maximum}: {value}"),
            ));
        }
    }
    Ok(())
}

fn validate_warnings(warnings: &[String]) -> ProtocolResult<()> {
    if warnings.len() > MAX_WARNINGS
        || warnings
            .iter()
            .any(|warning| warning.len() > MAX_WARNING_BYTES || warning.contains('\0'))
    {
        return Err(ProtocolError::new(
            "invalid_warnings",
            "warning count or size exceeds the protocol limit",
        ));
    }
    Ok(())
}

fn validate_small_field(name: &str, value: &str, maximum: usize) -> ProtocolResult<()> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        Err(ProtocolError::new(
            "invalid_field",
            format!("{name} is empty, contains NUL, or exceeds {maximum} bytes"),
        ))
    } else {
        Ok(())
    }
}

fn is_reserved_windows_component(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

struct BoundedWriter {
    file: File,
    remaining: u64,
}

impl BoundedWriter {
    fn new(file: File, maximum_bytes: u64) -> Self {
        Self {
            file,
            remaining: maximum_bytes,
        }
    }

    fn flush_and_sync(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "serialized protocol file exceeded its byte limit",
            ));
        }
        let written = self.file.write(buffer)?;
        self.remaining = self.remaining.saturating_sub(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct TemporaryFile {
    path: PathBuf,
    committed: bool,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn request() -> GuestRunRequest {
        GuestRunRequest {
            protocol_version: PROTOCOL_VERSION,
            run_id: "01234567-abcd-4321-abcd-0123456789ab".to_string(),
            target: "input/target.exe".to_string(),
            target_sha256: Some("ab".repeat(32)),
            arguments: vec!["--example".to_string(), "value".to_string()],
            timeout_seconds: 30,
            network_policy: GuestNetworkPolicy::DenyAll,
            allowed_networks: Vec::new(),
            guest_ipv4: None,
            prefix_length: None,
            gateway_ipv4: None,
            dns_servers: Vec::new(),
            host_service_ipv4: None,
            host_service_port: None,
            mitigation_profile: GuestMitigationProfile::Strict,
            execution_profile: GuestExecutionProfile::Restricted,
            resource_limits: GuestResourceLimits::default(),
            capture: CaptureOptions::default(),
            shutdown_when_complete: false,
        }
    }

    fn status(run_id: &str, sequence: u64, state: ProtocolState) -> StatusRecord {
        let mut record = StatusRecord::new(run_id, sequence, state);
        record.request_sha256 = Some("ab".repeat(32));
        if matches!(
            state,
            ProtocolState::Completed | ProtocolState::ShutdownReady
        ) {
            record.result_sha256 = Some("cd".repeat(32));
        }
        record
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "foxhole-protocol-{name}-{}-{}",
            std::process::id(),
            TEMPORARY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn valid_request_round_trips_and_validates() {
        let request = request();
        request.validate().unwrap();
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: GuestRunRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
        decoded.validate().unwrap();
    }

    #[test]
    fn execution_profiles_round_trip_and_default_to_restricted() {
        for profile in [
            GuestExecutionProfile::Restricted,
            GuestExecutionProfile::Normal,
            GuestExecutionProfile::Admin,
        ] {
            let mut value = request();
            value.execution_profile = profile;
            let encoded = serde_json::to_vec(&value).unwrap();
            let decoded: GuestRunRequest = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded.execution_profile, profile);
        }

        let mut legacy = serde_json::to_value(request()).unwrap();
        legacy.as_object_mut().unwrap().remove("execution_profile");
        let decoded: GuestRunRequest = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.execution_profile, GuestExecutionProfile::Restricted);

        let mut invalid = request();
        invalid.execution_profile = GuestExecutionProfile::Normal;
        invalid.mitigation_profile = GuestMitigationProfile::Strict;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn strict_json_rejects_unknown_fields() {
        let mut value = serde_json::to_value(request()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("surprise".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<GuestRunRequest>(value).is_err());
    }

    #[test]
    fn unsafe_wire_paths_are_rejected_on_every_host_os() {
        for path in [
            "",
            "../target.exe",
            "./target.exe",
            "/target.exe",
            r"C:\target.exe",
            "C:target.exe",
            r"\\server\share",
            r"\\?\C:\target.exe",
            "input\\target.exe",
            "input//target.exe",
            "input/target.exe/",
            "input/file:stream",
            "input/NUL.txt",
            "input/trailing.",
            "input/trailing ",
        ] {
            assert!(
                validate_relative_wire_path(path).is_err(),
                "unsafe path accepted: {path:?}"
            );
        }
        assert!(validate_relative_wire_path("input/target.exe").is_ok());
    }

    #[test]
    fn every_bounded_request_field_is_enforced() {
        let mut invalid = request();
        invalid.protocol_version += 1;
        assert!(invalid.validate().is_err());

        let mut invalid = request();
        invalid.timeout_seconds = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = request();
        invalid.arguments = vec!["x".repeat(MAX_ARGUMENT_BYTES + 1)];
        assert!(invalid.validate().is_err());

        let mut invalid = request();
        invalid.allowed_networks = vec!["192.0.2.0/24".to_string()];
        assert!(invalid.validate().is_err());

        let mut valid = request();
        valid.network_policy = GuestNetworkPolicy::AllowList;
        valid.allowed_networks = vec!["192.0.2.0/24".to_string(), "2001:db8::/32".to_string()];
        assert!(valid.validate().is_ok());

        valid.allowed_networks[0] = "192.0.2.1/33".to_string();
        assert!(valid.validate().is_err());
    }

    #[test]
    fn controlled_guest_addressing_is_strict_and_mode_specific() {
        let mut host = request();
        host.network_policy = GuestNetworkPolicy::HostServer;
        host.guest_ipv4 = Some(Ipv4Addr::new(192, 168, 250, 10));
        host.prefix_length = Some(24);
        host.host_service_ipv4 = Some(Ipv4Addr::new(192, 168, 250, 1));
        host.host_service_port = Some(8080);
        assert!(host.validate().is_ok());
        host.dns_servers.push(Ipv4Addr::new(1, 1, 1, 1));
        assert!(host.validate().is_err());

        let mut external = request();
        external.network_policy = GuestNetworkPolicy::AllowInternet;
        external.guest_ipv4 = Some(Ipv4Addr::new(192, 168, 250, 10));
        external.prefix_length = Some(24);
        external.gateway_ipv4 = Some(Ipv4Addr::new(192, 168, 250, 1));
        external.dns_servers.push(Ipv4Addr::new(1, 1, 1, 1));
        assert!(external.validate().is_ok());
        external.dns_servers[0] = Ipv4Addr::new(169, 254, 169, 254);
        assert!(external.validate().is_err());
    }

    #[test]
    fn state_machine_supports_preapproved_and_live_start_orders() {
        let run_id = request().run_id;
        for states in [
            vec![
                ProtocolState::HostReady,
                ProtocolState::RequestWritten,
                ProtocolState::StartAllowed,
                ProtocolState::GuestReady,
                ProtocolState::Running,
                ProtocolState::Completed,
                ProtocolState::ShutdownReady,
            ],
            vec![
                ProtocolState::HostReady,
                ProtocolState::RequestWritten,
                ProtocolState::GuestReady,
                ProtocolState::StartAllowed,
                ProtocolState::Running,
                ProtocolState::Completed,
                ProtocolState::ShutdownReady,
            ],
        ] {
            let mut machine = ProtocolStateMachine::new(&run_id).unwrap();
            for (index, state) in states.into_iter().enumerate() {
                machine
                    .observe(&status(&run_id, index as u64 + 1, state))
                    .unwrap();
            }
        }
    }

    #[test]
    fn state_machine_rejects_replay_wrong_run_and_missing_prerequisites() {
        let run_id = request().run_id;
        let mut machine = ProtocolStateMachine::new(&run_id).unwrap();
        assert!(
            machine
                .observe(&status(&run_id, 1, ProtocolState::Running))
                .is_err()
        );
        machine
            .observe(&status(&run_id, 1, ProtocolState::HostReady))
            .unwrap();
        assert!(
            machine
                .observe(&status(&run_id, 2, ProtocolState::HostReady))
                .is_err()
        );
        assert!(
            machine
                .observe(&status(
                    "different-run-id",
                    3,
                    ProtocolState::RequestWritten
                ))
                .is_err()
        );
    }

    #[test]
    fn atomic_json_publication_is_bounded_and_never_overwrites() {
        let root = temporary_directory("atomic");
        let destination = root.join("request.json");
        let request = request();
        write_atomic_json_new(&destination, &request, MAX_REQUEST_BYTES).unwrap();
        assert_eq!(
            read_bounded_json::<GuestRunRequest>(&destination, MAX_REQUEST_BYTES).unwrap(),
            request
        );
        assert!(
            write_atomic_json_new(&destination, &request, MAX_REQUEST_BYTES).is_err(),
            "a second publication must not replace the first"
        );
        let oversized = root.join("oversized.json");
        assert!(write_atomic_json_new(&oversized, &request, 8).is_err());
        assert!(!oversized.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_rejects_case_duplicates_and_bad_totals() {
        let coverage = CaptureCoverage {
            requested: true,
            collected: true,
            complete: true,
            warnings: Vec::new(),
        };
        let mut envelope = GuestResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            run_id: request().run_id,
            agent_version: "0.2.0".to_string(),
            guest_image_version: "1.0.0".to_string(),
            outcome: GuestTerminalOutcome::Completed,
            execution: Some(serde_json::json!({"exit_code": 0})),
            coverage: ObservationCoverage {
                stdout: coverage.clone(),
                stderr: coverage.clone(),
                processes: coverage.clone(),
                network: coverage.clone(),
                filesystem: coverage.clone(),
                registry: CaptureCoverage::unavailable(true, "not implemented"),
            },
            artifacts: vec![ArtifactManifestEntry {
                relative_path: "extracted/a.bin".to_string(),
                size_bytes: 1,
                sha256: "01".repeat(32),
                kind: "extracted_file".to_string(),
            }],
            warnings: Vec::new(),
            network_attestation: None,
            error: None,
        };
        envelope.validate_metadata().unwrap();
        envelope.artifacts.push(ArtifactManifestEntry {
            relative_path: "EXTRACTED/A.BIN".to_string(),
            ..envelope.artifacts[0].clone()
        });
        assert!(envelope.validate_metadata().is_err());
    }
}
