use crate::artifacts::sha256_file;
use crate::filesystem::{GuestWorkspace, ensure_plain_directory};
use crate::monitor::ObservationAvailability;
use crate::runner::{AgentError, AgentResult};
use foxhole::sandbox::hyperv::guest_protocol::ArtifactManifestEntry;
use foxhole::structs::{
    FileObservation, NetworkObservation, ProcessObservation, RegistryObservation,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const COLLECTOR_SCRIPT: &str = include_str!("../assets/Collect-FoxholeTelemetry.ps1");
const MAX_TELEMETRY_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_HELPER_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;
const MAX_PACKET_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(45);
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug)]
pub struct TelemetrySession {
    baseline: TelemetryBaseline,
    started_unix_ms: u64,
    packet_etl: PathBuf,
    packet_capture_started: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct TelemetryResult {
    pub processes: Vec<ProcessObservation>,
    pub network_connections: Vec<NetworkObservation>,
    pub file_observations: Vec<FileObservation>,
    pub registry_observations: Vec<RegistryObservation>,
    pub artifacts: Vec<ArtifactManifestEntry>,
    pub availability: ObservationAvailability,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct TelemetryBaseline {
    sysmon_available: bool,
    sysmon_record_id: u64,
    security_record_id: u64,
    defender_record_id: u64,
    warnings: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CollectedTelemetry {
    processes: Vec<ProcessObservation>,
    network_connections: Vec<NetworkObservation>,
    file_observations: Vec<FileObservation>,
    registry_observations: Vec<RegistryObservation>,
    raw_events: Vec<serde_json::Value>,
    sysmon_collected: bool,
    wfp_collected: bool,
    defender_collected: bool,
    truncated: bool,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct CollectionRequest {
    root_pid: u32,
    started_unix_ms: u64,
    sysmon_available: bool,
    sysmon_record_id: u64,
    security_record_id: u64,
    defender_record_id: u64,
}

impl TelemetrySession {
    pub fn start(workspace: &GuestWorkspace) -> Self {
        let started_unix_ms = unix_ms();
        let mut warnings = Vec::new();
        let baseline = match invoke_collector::<_, TelemetryBaseline>(
            workspace,
            "Baseline",
            &serde_json::json!({}),
        ) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!("telemetry baseline unavailable: {error}"));
                TelemetryBaseline::default()
            }
        };
        warnings.extend(baseline.warnings.iter().cloned());

        let packet_etl = workspace.root.join("packet-capture.etl");
        let packet_capture_started = match start_packet_capture(&packet_etl) {
            Ok(()) => true,
            Err(error) => {
                warnings.push(format!("packet capture unavailable: {error}"));
                false
            }
        };
        Self {
            baseline,
            started_unix_ms,
            packet_etl,
            packet_capture_started,
            warnings,
        }
    }

    pub fn finish(mut self, workspace: &GuestWorkspace, root_pid: u32) -> TelemetryResult {
        let mut result = TelemetryResult::default();
        if self.packet_capture_started {
            if let Err(error) = stop_packet_capture() {
                self.warnings
                    .push(format!("stop packet capture failed: {error}"));
            } else {
                match archive_packet_capture(workspace, &self.packet_etl) {
                    Ok(artifacts) => result.artifacts = artifacts,
                    Err(error) => self
                        .warnings
                        .push(format!("archive packet capture failed: {error}")),
                }
            }
            self.packet_capture_started = false;
        }

        // Sysmon writes asynchronously. A short bounded grace period prevents losing the
        // terminal events while keeping the guest shutdown deadline deterministic.
        thread::sleep(Duration::from_secs(1));
        let request = CollectionRequest {
            root_pid,
            started_unix_ms: self.started_unix_ms,
            sysmon_available: self.baseline.sysmon_available,
            sysmon_record_id: self.baseline.sysmon_record_id,
            security_record_id: self.baseline.security_record_id,
            defender_record_id: self.baseline.defender_record_id,
        };
        match invoke_collector::<_, CollectedTelemetry>(workspace, "Collect", &request) {
            Ok(collected) => {
                result.processes = collected.processes;
                result.network_connections = collected.network_connections;
                result.file_observations = collected.file_observations;
                result.registry_observations = collected.registry_observations;
                match archive_json_artifact(
                    workspace,
                    "telemetry-events.json",
                    "guest_telemetry_events",
                    &collected.raw_events,
                ) {
                    Ok(Some(artifact)) => result.artifacts.push(artifact),
                    Ok(None) => {}
                    Err(error) => self
                        .warnings
                        .push(format!("archive raw telemetry failed: {error}")),
                }
                result.availability = ObservationAvailability {
                    processes: collected.sysmon_collected,
                    network: collected.sysmon_collected || collected.wfp_collected,
                    filesystem: collected.sysmon_collected || collected.defender_collected,
                    registry: collected.sysmon_collected,
                };
                if collected.truncated {
                    self.warnings.push(
                        "guest telemetry was truncated at its bounded event limit".to_string(),
                    );
                }
                self.warnings.extend(collected.warnings);
            }
            Err(error) => self
                .warnings
                .push(format!("structured telemetry collection failed: {error}")),
        }
        result.warnings = std::mem::take(&mut self.warnings);
        result
    }
}

impl Drop for TelemetrySession {
    fn drop(&mut self) {
        if self.packet_capture_started {
            let _ = stop_packet_capture();
            self.packet_capture_started = false;
        }
    }
}

fn invoke_collector<I: Serialize, O: for<'de> Deserialize<'de>>(
    workspace: &GuestWorkspace,
    mode: &str,
    input: &I,
) -> AgentResult<O> {
    let suffix = mode.to_ascii_lowercase();
    let script_path = workspace.root.join(format!("telemetry-{suffix}.ps1"));
    let input_path = workspace
        .root
        .join(format!("telemetry-{suffix}-input.json"));
    let output_path = workspace
        .root
        .join(format!("telemetry-{suffix}-output.json"));
    let diagnostic_path = workspace
        .root
        .join(format!("telemetry-{suffix}-diagnostic.txt"));
    write_new(&script_path, COLLECTOR_SCRIPT.as_bytes())?;
    let encoded = serde_json::to_vec(input).map_err(|error| {
        AgentError::with_source(
            "telemetry",
            "serialize_collector_input",
            "serialize telemetry collector input",
            error,
        )
    })?;
    write_new(&input_path, &encoded)?;

    let powershell = system32_path("WindowsPowerShell\\v1.0\\powershell.exe")?;
    let diagnostic_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&diagnostic_path)
        .map_err(|error| {
            AgentError::with_source(
                "telemetry",
                "create_diagnostic_file",
                "create telemetry helper diagnostic file",
                error,
            )
        })?;
    let mut command = Command::new(powershell);
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
        ])
        .arg("-File")
        .arg(&script_path)
        .arg("-Mode")
        .arg(mode)
        .arg("-InputPath")
        .arg(&input_path)
        .arg("-OutputPath")
        .arg(&output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostic_file));
    let run = run_bounded(
        &mut command,
        COLLECTOR_TIMEOUT,
        "PowerShell telemetry collector",
    );
    let diagnostic = read_optional_plain_bounded(&diagnostic_path, MAX_HELPER_DIAGNOSTIC_BYTES)
        .unwrap_or_default();
    let _ = fs::remove_file(&script_path);
    let _ = fs::remove_file(&input_path);
    let _ = fs::remove_file(&diagnostic_path);
    if let Err(error) = run {
        let text = String::from_utf8_lossy(&diagnostic);
        let detail = text.trim().replace(['\r', '\n'], " ");
        return Err(if detail.is_empty() {
            error
        } else {
            AgentError::new(
                "telemetry",
                "helper_failed",
                format!("{error}; diagnostic: {detail}"),
            )
        });
    }
    let bytes = read_plain_bounded(&output_path, MAX_TELEMETRY_JSON_BYTES)?;
    let _ = fs::remove_file(&output_path);
    serde_json::from_slice(&bytes).map_err(|error| {
        AgentError::with_source(
            "telemetry",
            "decode_collector_output",
            "decode bounded telemetry collector output",
            error,
        )
    })
}

fn read_optional_plain_bounded(path: &Path, limit: u64) -> AgentResult<Vec<u8>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_plain_bounded(path, limit),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(AgentError::with_source(
            "telemetry",
            "inspect_helper_diagnostic",
            "inspect telemetry helper diagnostic output",
            error,
        )),
    }
}

fn start_packet_capture(path: &Path) -> AgentResult<()> {
    let pktmon = system32_path("pktmon.exe")?;
    let mut command = Command::new(pktmon);
    command
        .args([
            "start",
            "--capture",
            "--pkt-size",
            "0",
            "--file-size",
            "64",
            "--log-mode",
            "circular",
            "--file-name",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    run_bounded(&mut command, TOOL_TIMEOUT, "start Packet Monitor")
}

fn stop_packet_capture() -> AgentResult<()> {
    let pktmon = system32_path("pktmon.exe")?;
    let mut command = Command::new(pktmon);
    command
        .arg("stop")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    run_bounded(&mut command, TOOL_TIMEOUT, "stop Packet Monitor")
}

fn archive_packet_capture(
    workspace: &GuestWorkspace,
    etl_path: &Path,
) -> AgentResult<Vec<ArtifactManifestEntry>> {
    let metadata = match fs::symlink_metadata(etl_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(AgentError::with_source(
                "telemetry",
                "inspect_packet_capture",
                "inspect Packet Monitor ETL",
                error,
            ));
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(AgentError::new(
            "telemetry",
            "unsafe_packet_capture",
            "Packet Monitor output is not a plain file",
        ));
    }
    if metadata.len() > MAX_PACKET_ARTIFACT_BYTES {
        return Err(AgentError::new(
            "telemetry",
            "packet_capture_too_large",
            "Packet Monitor output exceeded its artifact limit",
        ));
    }

    let pcap_path = workspace.root.join("packet-capture.pcapng");
    let pktmon = system32_path("pktmon.exe")?;
    let mut convert = Command::new(pktmon);
    convert
        .arg("etl2pcap")
        .arg(etl_path)
        .arg("--out")
        .arg(&pcap_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = run_bounded(&mut convert, TOOL_TIMEOUT, "convert Packet Monitor capture");

    let extracted = workspace.output.join("extracted-files");
    match fs::create_dir(&extracted) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_plain_directory(&extracted)?;
        }
        Err(error) => {
            return Err(AgentError::with_source(
                "telemetry",
                "create_artifact_directory",
                "create telemetry artifact directory",
                error,
            ));
        }
    }

    let mut artifacts = Vec::new();
    for (source, name, kind) in [
        (etl_path, "network-capture.etl", "packet_capture_etl"),
        (
            &pcap_path,
            "network-capture.pcapng",
            "packet_capture_pcapng",
        ),
    ] {
        if !source.exists() {
            continue;
        }
        let destination = extracted.join(name);
        copy_plain_bounded(source, &destination, MAX_PACKET_ARTIFACT_BYTES)?;
        let size_bytes = fs::metadata(&destination)
            .map_err(|error| {
                AgentError::with_source(
                    "telemetry",
                    "inspect_archived_capture",
                    "inspect archived packet capture",
                    error,
                )
            })?
            .len();
        artifacts.push(ArtifactManifestEntry {
            relative_path: format!("extracted-files/{name}"),
            size_bytes,
            sha256: sha256_file(&destination, MAX_PACKET_ARTIFACT_BYTES)?,
            kind: kind.to_string(),
        });
    }
    Ok(artifacts)
}

fn archive_json_artifact<T: Serialize>(
    workspace: &GuestWorkspace,
    name: &str,
    kind: &str,
    value: &T,
) -> AgentResult<Option<ArtifactManifestEntry>> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        AgentError::with_source(
            "telemetry",
            "serialize_telemetry_artifact",
            "serialize raw telemetry artifact",
            error,
        )
    })?;
    if bytes == b"[]" {
        return Ok(None);
    }
    if bytes.len() as u64 > MAX_TELEMETRY_JSON_BYTES {
        return Err(AgentError::new(
            "telemetry",
            "telemetry_artifact_too_large",
            "raw telemetry artifact exceeded its bounded size limit",
        ));
    }
    let extracted = workspace.output.join("extracted-files");
    match fs::create_dir(&extracted) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_plain_directory(&extracted)?;
        }
        Err(error) => {
            return Err(AgentError::with_source(
                "telemetry",
                "create_artifact_directory",
                "create telemetry artifact directory",
                error,
            ));
        }
    }
    let destination = extracted.join(name);
    write_new(&destination, &bytes)?;
    Ok(Some(ArtifactManifestEntry {
        relative_path: format!("extracted-files/{name}"),
        size_bytes: bytes.len() as u64,
        sha256: sha256_file(&destination, MAX_TELEMETRY_JSON_BYTES)?,
        kind: kind.to_string(),
    }))
}

fn copy_plain_bounded(source: &Path, destination: &Path, limit: u64) -> AgentResult<()> {
    let mut input = File::open(source).map_err(|error| {
        AgentError::with_source(
            "telemetry",
            "open_artifact",
            "open telemetry artifact",
            error,
        )
    })?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            AgentError::with_source(
                "telemetry",
                "create_artifact",
                "create archived telemetry artifact",
                error,
            )
        })?;
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).map_err(|error| {
            AgentError::with_source(
                "telemetry",
                "read_artifact",
                "read telemetry artifact",
                error,
            )
        })?;
        if count == 0 {
            break;
        }
        copied = copied.saturating_add(count as u64);
        if copied > limit {
            return Err(AgentError::new(
                "telemetry",
                "artifact_too_large",
                "telemetry artifact exceeded its copy limit",
            ));
        }
        output.write_all(&buffer[..count]).map_err(|error| {
            AgentError::with_source(
                "telemetry",
                "write_artifact",
                "write archived telemetry artifact",
                error,
            )
        })?;
    }
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(|error| {
            AgentError::with_source(
                "telemetry",
                "flush_artifact",
                "flush archived telemetry artifact",
                error,
            )
        })
}

fn write_new(path: &Path, bytes: &[u8]) -> AgentResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            AgentError::with_source(
                "telemetry",
                "create_helper_file",
                "create telemetry helper file",
                error,
            )
        })?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .map_err(|error| {
            AgentError::with_source(
                "telemetry",
                "write_helper_file",
                "write telemetry helper file",
                error,
            )
        })
}

fn read_plain_bounded(path: &Path, limit: u64) -> AgentResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AgentError::with_source(
            "telemetry",
            "inspect_helper_output",
            "inspect telemetry helper output",
            error,
        )
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || is_reparse(&metadata)
        || metadata.len() > limit
    {
        return Err(AgentError::new(
            "telemetry",
            "unsafe_helper_output",
            "telemetry helper output is not a plain bounded file",
        ));
    }
    fs::read(path).map_err(|error| {
        AgentError::with_source(
            "telemetry",
            "read_helper_output",
            "read telemetry helper output",
            error,
        )
    })
}

fn run_bounded(command: &mut Command, timeout: Duration, operation: &str) -> AgentResult<()> {
    let mut child = command.spawn().map_err(|error| {
        AgentError::with_source("telemetry", "start_helper", operation.to_string(), error)
    })?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(AgentError::new(
                    "telemetry",
                    "helper_failed",
                    format!("{operation} failed with {status}"),
                ));
            }
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AgentError::new(
                    "telemetry",
                    "helper_timeout",
                    format!("{operation} exceeded {} seconds", timeout.as_secs()),
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AgentError::with_source(
                    "telemetry",
                    "wait_helper",
                    format!("wait for {operation}"),
                    error,
                ));
            }
        }
    }
}

fn system32_path(relative: &str) -> AgentResult<PathBuf> {
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
        AgentError::new(
            "configuration",
            "missing_system_root",
            "SystemRoot is unavailable",
        )
    })?;
    Ok(PathBuf::from(system_root).join("System32").join(relative))
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(target_os = "windows")]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(target_os = "windows"))]
fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_filters_event_log_queries_before_materializing_rows() {
        assert!(COLLECTOR_SCRIPT.contains(
            "-FilterHashtable @{ LogName=$sysmonLog; Id=$structuredIds; StartTime=$eventStartTime }",
        ));
        assert!(
            !COLLECTOR_SCRIPT
                .contains("Get-WinEvent -LogName $sysmonLog -MaxEvents ($maxEvents + 1)",)
        );
    }

    #[test]
    fn collector_archives_only_bounded_target_related_raw_events() {
        let script = COLLECTOR_SCRIPT.replace("\r\n", "\n");
        assert!(script.contains("$maxRawEvents = 5000"));
        assert!(script.contains(
            "if (-not $guids.Contains($guid)) { continue }\n    if ($rawEvents.Count -lt $maxRawEvents)",
        ));
        assert!(script.contains(
            "if (-not $pids.Contains($processId)) { continue }\n        if ($rawEvents.Count -lt $maxRawEvents)",
        ));
    }

    #[test]
    fn sysmon_configuration_observes_without_enabling_active_file_blocking() {
        let config = include_str!("../assets/sysmon-config.xml");
        assert!(!config.contains("<FileBlockExecutable"));
        assert!(!config.contains("<FileBlockShredding"));
        assert!(config.contains("<FileExecutableDetected onmatch=\"exclude\" />"));
    }

    #[test]
    fn collector_waits_boundedly_for_target_sysmon_events_and_records_defender_events() {
        assert!(COLLECTOR_SCRIPT.contains("$sysmonDeadline = [DateTime]::UtcNow.AddSeconds(5)"));
        assert!(COLLECTOR_SCRIPT.contains("-not $targetProcessObserved"));
        assert!(COLLECTOR_SCRIPT.contains("source = 'windows_defender'"));
        assert!(COLLECTOR_SCRIPT.contains("defender_record_id = Last-Record $defenderLog"));
        assert!(COLLECTOR_SCRIPT.contains("@('-c', $sysmonConfig)"));
        assert!(COLLECTOR_SCRIPT.contains("@('-accepteula', '-i', $sysmonConfig)"));
    }

    #[test]
    fn collector_hashes_target_created_files_with_strict_limits() {
        assert!(COLLECTOR_SCRIPT.contains("function Parse-Sha256"));
        assert!(COLLECTOR_SCRIPT.contains("function Read-BoundedFileSha256"));
        assert!(COLLECTOR_SCRIPT.contains("$maxHashedFiles = 2048"));
        assert!(COLLECTOR_SCRIPT.contains("$maxHashFileBytes = 128MB"));
        assert!(COLLECTOR_SCRIPT.contains("$maxHashTotalBytes = 256MB"));
        assert!(COLLECTOR_SCRIPT.contains("[IO.FileShare]::Read"));
        assert!(COLLECTOR_SCRIPT.contains("hash_source = 'guest_post_run_file'"));
        assert!(COLLECTOR_SCRIPT.contains("$data.Hashes"));
    }

    #[test]
    fn collector_preserves_registry_create_and_delete_direction() {
        assert!(COLLECTOR_SCRIPT.contains("switch ([string]$data.EventType)"));
        assert!(COLLECTOR_SCRIPT.contains("'CreateKey' { 'create_key' }"));
        assert!(COLLECTOR_SCRIPT.contains("'DeleteKey' { 'delete_key' }"));
        assert!(COLLECTOR_SCRIPT.contains("default { 'create_or_delete' }"));
    }

    #[test]
    fn structured_collector_has_more_time_than_packet_tools() {
        assert!(COLLECTOR_TIMEOUT > TOOL_TIMEOUT);
    }
}
