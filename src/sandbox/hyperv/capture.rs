use super::network::NetworkOwnedResources;
use super::powershell::{PowerShellExecutor, PowerShellInvocation};
use crate::structs::CaptureHealth;
use serde_json::json;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const HOST_CAPTURE_BYTES: u64 = 128 * 1024 * 1024;
const STOP: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$session = Get-NetEventSession -Name ([string]$request.session) -ErrorAction Stop
if ([string]$session.LocalFilePath -ne [string]$request.etl) { throw 'Capture ownership path mismatch' }
$wasRunning = [string]$session.SessionStatus -eq 'Running'
if ($wasRunning) { Stop-NetEventSession -Name ([string]$request.session) -ErrorAction Stop | Out-Null }
$session = Get-NetEventSession -Name ([string]$request.session) -ErrorAction Stop
if ([string]$session.SessionStatus -eq 'Running') { throw 'Capture did not stop' }
$eventsLost = $null
if ($null -ne $session.PSObject.Properties['EventsLost']) { $eventsLost = [uint64]$session.EventsLost }
$data = @{ channel='host_ndis'; requested=$true; started=$wasRunning; stopped=$true; dropped_events=$eventsLost }
@{ schema_version=1; ok=$true; data=$data } | ConvertTo-Json -Compress -Depth 8
} catch {
@{ schema_version=1; ok=$false; error=@{code='capture_stop_failed'; message=$_.Exception.Message} } | ConvertTo-Json -Compress -Depth 8
}
"#;

/// Called only after VM removal proves the entire target tree has terminated.
/// Capture failures never cause early removal of network containment.
pub(crate) fn finish(
    executor: &dyn PowerShellExecutor,
    resources: &NetworkOwnedResources,
) -> CaptureHealth {
    let mut health = CaptureHealth {
        channel: "host_ndis".into(), requested: true, byte_limit: Some(HOST_CAPTURE_BYTES),
        warnings: vec!["Host capture is a bounded circular ETL. Overwrite and packet/event loss may be unreported; null counters mean unknown. Packets filtered before the switch provider are not visible.".into()],
        ..CaptureHealth::default()
    };
    let (Some(session), Some(etl)) = (&resources.capture_session, &resources.capture_file) else {
        health.warnings.push(
            "Host packet capture unavailable: this run has no capture-capable virtual NIC.".into(),
        );
        return health;
    };
    match executor.execute(&PowerShellInvocation::new(
        "stop run-owned host packet capture after VM removal",
        STOP,
        json!({"session":session,"etl":etl}),
    )) {
        Ok(value) => match serde_json::from_value::<CaptureHealth>(value) {
            Ok(status) => {
                health.started = status.started;
                health.stopped = status.stopped;
                health.dropped_events = status.dropped_events;
            }
            Err(error) => health.provider_errors.push(error.to_string()),
        },
        Err(error) => health.provider_errors.push(error.to_string()),
    }
    if health.stopped {
        match plain_file_size(etl) {
            Ok(bytes) => {
                health.captured_bytes = Some(bytes);
                health.truncated = bytes >= HOST_CAPTURE_BYTES;
                health.artifacts.push("network-capture.etl".into());
                let pcap = etl.with_extension("pcapng");
                match convert(etl, &pcap) {
                    Ok(()) => {
                        match crate::network_telemetry::pcapng_counts(&pcap, HOST_CAPTURE_BYTES) {
                            Ok(counts) => {
                                health.captured_packets = Some(counts.packets);
                                health.dropped_packets = counts.dropped_packets;
                                health.truncated |= counts.truncated;
                                health.artifacts.push("network-capture.pcapng".into());
                            }
                            Err(error) => health
                                .provider_errors
                                .push(format!("PCAPNG incomplete: {error}")),
                        }
                    }
                    Err(error) => {
                        health
                            .provider_errors
                            .push(format!("PCAPNG unavailable; ETL retained: {error}"));
                        if plain_file_size(&pcap).is_ok_and(|size| size > HOST_CAPTURE_BYTES) {
                            health.truncated = true;
                            // Conversion is stopped and reaped before retaining a bounded partial file.
                            if let Err(error) = std::fs::OpenOptions::new()
                                .write(true)
                                .open(&pcap)
                                .and_then(|file| file.set_len(HOST_CAPTURE_BYTES))
                            {
                                health
                                    .provider_errors
                                    .push(format!("could not bound partial PCAPNG: {error}"));
                            }
                        }
                    }
                }
            }
            Err(error) => health
                .provider_errors
                .push(format!("ETL unavailable: {error}")),
        }
    }
    if let Some(root) = etl.parent() {
        // Also retain health on failed executions and recovery runs with no final report.
        let path = root.join("network-capture-health.json");
        if let Err(error) =
            crate::sandbox::hyperv::guest_protocol::write_atomic_json_new(&path, &health, 64 * 1024)
        {
            health
                .warnings
                .push(format!("host capture health archive unavailable: {error}"));
        }
    }
    health
}

fn plain_file_size(path: &Path) -> std::io::Result<u64> {
    let metadata = std::fs::symlink_metadata(path)?;
    let mut unsafe_file = !metadata.is_file() || metadata.file_type().is_symlink();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        unsafe_file |= metadata.file_attributes() & 0x400 != 0;
    }
    if unsafe_file {
        return Err(std::io::Error::other("capture is not a plain file"));
    }
    Ok(metadata.len())
}

fn convert(etl: &Path, pcap: &Path) -> std::io::Result<()> {
    if plain_file_size(etl)? > HOST_CAPTURE_BYTES {
        return Err(std::io::Error::other("ETL byte limit exceeded"));
    }
    if pcap.try_exists()? {
        return Err(std::io::Error::other("PCAPNG destination already exists"));
    }
    // Administrator-provisioned binary only; never search PATH or execute a guest artifact.
    #[cfg(windows)]
    let converter = super::powershell::system_powershell_path()
        .map_err(|error| std::io::Error::other(error.to_string()))?
        .ancestors()
        .nth(3)
        .ok_or_else(|| std::io::Error::other("System32 unavailable"))?
        .join("etl2pcapng.exe");
    #[cfg(not(windows))]
    let converter = std::path::PathBuf::from("/nonexistent/etl2pcapng.exe");
    plain_file_size(&converter)?;
    let mut command = Command::new(converter);
    command
        .arg(etl)
        .arg(pcap)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    let started = Instant::now();
    loop {
        let over_limit =
            pcap.exists() && plain_file_size(pcap).map_or(true, |bytes| bytes > HOST_CAPTURE_BYTES);
        if over_limit || started.elapsed() > Duration::from_secs(45) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::other(
                "PCAPNG conversion exceeded byte/time bound",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::other(format!("etl2pcapng exited {status}")))
                };
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
