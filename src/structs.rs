use serde::{Deserialize, Serialize};

use once_cell::sync::Lazy;
use std::collections::HashMap;

pub static COLOR_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("red", "31");
    m.insert("blue", "34");
    m.insert("green", "32");
    m.insert("yellow", "33");
    m.insert("purple", "35");
    m.insert("cyan", "36");
    m.insert("white", "37");
    m.insert("grey", "90");
    m
});

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone)]
pub struct PatternVS {
    pub pattern: String,
    pub comment: String,
    pub regex: bool,
    pub severity: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReportParams {
    pub type_: String,
    pub exclude_: String,
    pub caps_: bool,
    pub filename_as_head: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RunSettings {
    // Struct for parsing the settings.json file
    pub color_output: bool,
    pub display_ok_files: bool,
    pub show_patterns: bool,
    pub use_custom_severity_and_exp: bool,
    pub check_code: bool,
    pub write_report: bool,
    pub vt_api: String,
    pub debug: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CodeOptionsChck {
    pub comments: bool,
    pub ends_with_blank_line: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReportSettings {
    pub report_path: String,
    pub report_title: String,
    pub report_params: ReportParams,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VirusTotalApiPathStruct {
    pub method: String,
    pub url: String,
    pub expected: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VirusTotalApiPath {
    pub upload_small: VirusTotalApiPathStruct,
    pub get_url_large: VirusTotalApiPathStruct,
    pub upload_large: VirusTotalApiPathStruct,
    pub analyze_result: VirusTotalApiPathStruct,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Settings {
    pub run_settings: RunSettings,
    pub check_code_options: CodeOptionsChck,
    pub report_settings: ReportSettings,
    pub mc_patterns: Vec<String>,
    pub virus_total_api: VirusTotalApiPath,
    pub trusted_engines: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum ValiDPathType {
    Invalid,
    File,
    Directory,
    Url, // for future use
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidatePathResult {
    pub is_valid: bool,
    pub type_: ValiDPathType,
    pub error_message: Option<String>,
}

// nix flags for ::unshare
// #[allow(non_camel_case_types)]
// #[derive(Serialize, Deserialize, Clone)]

// pub enum UnshareFlags {
//     CLONE_VM,
//     CLONE_FS,
//     CLONE_FILES,
//     CLONE_SIGHAND,
//     CLONE_PTRACE,
//     CLONE_VFORK,
//     CLONE_PARENT,
//     CLONE_THREAD,
//     CLONE_NEWNS,
//     CLONE_SYSVSEM,
//     CLONE_UNTRACER,
//     CLONE_NEWCGROUP,
//     CLONE_NEWUTS,
//     CLONE_NEWIPC,
//     CLONE_NEWUSER,
//     CLONE_NEWPID,
//     CLONE_NEWNET,
//     CLONE_IO
// }

#[allow(non_camel_case_types)]
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub enum UserNixFlags {
    USR_SHARE_VM,        // Shared memory space with parent
    USR_SHARE_FS,        // Shared filesystem (cwd, root)
    USR_SHARE_FILES,     // Shared file descriptors
    USR_SHARE_SIG,       // Shared signal handlers
    USR_ALLOW_TRACE,     // Allow child to be traced/debugged
    USR_PARENT_WAIT,     // Parent waits for child to exec/exit
    USR_SAME_PARENT,     // Use the same parent as caller
    USR_THREAD,          // Create as a thread (same thread group)
    USR_NEW_MOUNT,       // New mount namespace
    USR_SHARE_SEMAPHORE, // Shared System V semaphores
    USR_NO_TRACE,        // Disable tracing on this process
    USR_NEW_CGROUP,      // New cgroup namespace
    USR_NEW_HOSTNAME,    // New UTS namespace (hostname)
    USR_NEW_IPC,         // New IPC namespace
    USR_NEW_USER,        // New user namespace (UID/GID mapping)
    USR_NEW_PID,         // New PID namespace (isolated PIDs)
    USR_NEW_NET,         // New network namespace (own net stack)
    USR_SHARE_IO,        // Shared I/O context
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessObservation {
    pub pid: u32,
    pub parent_pid: u32,
    pub image: String,
    pub observed_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkObservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<NetworkEventContext>,
    pub pid: u32,
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub observed_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamCaptureSummary {
    pub bytes_seen: u64,
    pub bytes_stored: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileObservation {
    pub relative_path: String,
    pub size_bytes: u64,
    pub kind: String,
    pub observed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_source: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryObservation {
    pub key: String,
    pub operation: String,
    pub observed_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappedPathObservation {
    pub source_name: String,
    pub sandbox_path: String,
    pub access: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupStatus {
    pub attempted: bool,
    pub success: bool,
    pub warnings: Vec<String>,
    pub leftover_resources: Vec<String>,
}

impl CleanupStatus {
    pub fn pending() -> Self {
        Self {
            attempted: false,
            success: false,
            warnings: Vec::new(),
            leftover_resources: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxRunResult {
    #[serde(default)]
    pub capture_health: Vec<CaptureHealth>,
    pub backend: String,
    pub network_policy: String,
    pub integrity_level: String,
    pub mitigation_profile: String,
    pub pid: u32,
    pub exit_code: Option<u32>,
    pub timed_out: bool,
    pub working_dir: Option<String>,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
    pub stdout_capture: StreamCaptureSummary,
    pub stderr_capture: StreamCaptureSummary,
    pub processes: Vec<ProcessObservation>,
    pub network_connections: Vec<NetworkObservation>,
    pub file_observations: Vec<FileObservation>,
    pub registry_observations: Vec<RegistryObservation>,
    pub mapped_paths: Vec<MappedPathObservation>,
    pub monitor_warnings: Vec<String>,
    pub cleanup: CleanupStatus,
}

/// Unknown provider counters remain null, never a fabricated zero or completeness claim.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CaptureHealth {
    pub channel: String,
    pub requested: bool,
    pub started: bool,
    pub stopped: bool,
    pub byte_limit: Option<u64>,
    pub event_limit: Option<u64>,
    pub raw_event_limit: Option<u64>,
    pub captured_bytes: Option<u64>,
    pub captured_packets: Option<u64>,
    pub captured_events: Option<u64>,
    pub retained_events: Option<u64>,
    pub truncated: bool,
    pub dropped_events: Option<u64>,
    pub dropped_packets: Option<u64>,
    pub loss_detected: bool,
    pub provider_errors: Vec<String>,
    pub artifacts: Vec<String>,
    pub warnings: Vec<String>,
}

impl CaptureHealth {
    pub fn coverage_warnings(&self) -> Vec<String> {
        let mut warnings = self.warnings.clone();
        if self.requested && !self.started {
            warnings.push(format!(
                "{} capture unavailable: instrumentation start was not confirmed",
                self.channel
            ));
        }
        if self.started && !self.stopped {
            warnings.push(format!(
                "{} capture incomplete: stop was not confirmed",
                self.channel
            ));
        }
        if self.truncated {
            warnings.push(format!("{} capture truncated at configured bounds; earlier or excess activity may be absent", self.channel));
        }
        if self.loss_detected
            || self.dropped_events.is_some_and(|v| v > 0)
            || self.dropped_packets.is_some_and(|v| v > 0)
        {
            warnings.push(format!(
                "{} capture reports lost events or packets",
                self.channel
            ));
        }
        warnings.extend(
            self.provider_errors
                .iter()
                .map(|e| format!("{} provider error: {e}", self.channel)),
        );
        warnings
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEventContext {
    pub time_utc: String,
    pub event_id: u32,
    pub action: String,
    pub image: String,
    pub correlation: NetworkCorrelation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkCorrelation {
    pub target: bool,
    pub confidence: String,
    pub reason: String,
    pub process_guid: Option<String>,
}
