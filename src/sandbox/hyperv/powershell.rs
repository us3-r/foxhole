use crate::sandbox::backend::{SandboxError, SandboxResult};
use serde::Deserialize;
use serde_json::Value;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Convert a validated host path into the Win32 form accepted by Hyper-V cmdlets.
/// Handle-derived paths commonly use the `\\?\` prefix, which cmdlets such as
/// `New-VHD` reject even though ordinary filesystem APIs accept it.
pub(crate) fn command_path(path: &Path, description: &str) -> SandboxResult<String> {
    let value = path.to_str().ok_or_else(|| {
        SandboxError::new(
            "hyperv_powershell",
            format!("{description} is not valid Unicode"),
        )
    })?;
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        return Ok(format!(r"\\{rest}"));
    }
    if let Some(rest) = value.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/')
        {
            return Ok(rest.to_string());
        }
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!("{description} uses an unsupported extended Windows path"),
        ));
    }
    Ok(value.to_string())
}

#[derive(Clone, Debug)]
pub(crate) struct PowerShellInvocation {
    pub operation: &'static str,
    pub script: &'static str,
    pub input: Value,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl PowerShellInvocation {
    pub(crate) fn new(operation: &'static str, script: &'static str, input: Value) -> Self {
        Self {
            operation,
            script,
            input,
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

pub(crate) trait PowerShellExecutor: Send + Sync {
    fn execute(&self, invocation: &PowerShellInvocation) -> SandboxResult<Value>;
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NativePowerShell;

#[derive(Debug)]
struct BoundedOutput {
    stored: Vec<u8>,
    total: usize,
    overflowed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    schema_version: u32,
    ok: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    error: Option<PowerShellError>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerShellError {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

impl PowerShellExecutor for NativePowerShell {
    fn execute(&self, invocation: &PowerShellInvocation) -> SandboxResult<Value> {
        execute_native(invocation)
    }
}

#[cfg(not(target_os = "windows"))]
fn execute_native(invocation: &PowerShellInvocation) -> SandboxResult<Value> {
    Err(SandboxError::new(
        "hyperv_powershell",
        format!(
            "{} is unavailable because the Hyper-V backend requires Windows",
            invocation.operation
        ),
    ))
}

#[cfg(target_os = "windows")]
fn execute_native(invocation: &PowerShellInvocation) -> SandboxResult<Value> {
    if invocation.timeout.is_zero() || invocation.max_output_bytes == 0 {
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!("{} has invalid execution limits", invocation.operation),
        ));
    }
    if invocation.script.as_bytes().contains(&0) {
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!(
                "{} contains an invalid NUL in its static script",
                invocation.operation
            ),
        ));
    }

    println!(
        "[hyperv/powershell debug] starting: {} (timeout={}s)",
        invocation.operation,
        invocation.timeout.as_secs()
    );

    let executable = system_powershell_path()?;
    let system_root = executable
        .ancestors()
        .nth(4)
        .ok_or_else(|| {
            SandboxError::new(
                "hyperv_powershell",
                "cannot derive SystemRoot from the trusted PowerShell path",
            )
        })?
        .to_path_buf();
    let system32 = system_root.join("System32");
    let computer_name = std::env::var_os("COMPUTERNAME");
    let program_data = std::env::var_os("ProgramData");
    let program_files = std::env::var_os("ProgramFiles");
    let program_files_x86 = std::env::var_os("ProgramFiles(x86)");
    let input = serde_json::to_vec(&invocation.input).map_err(|error| {
        SandboxError::with_source(
            "hyperv_powershell",
            format!("serialize {} input", invocation.operation),
            error,
        )
    })?;

    let mut child = Command::new(&executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            invocation.script,
        ])
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("WINDIR", &system_root)
        .env("PATH", &system32)
        .env(
            "PSModulePath",
            system32
                .join("WindowsPowerShell\\v1.0\\Modules")
                .display()
                .to_string(),
        )
        .env("ComSpec", system32.join("cmd.exe"))
        .env("COMPUTERNAME", computer_name.as_deref().unwrap_or_default())
        .env("ProgramData", program_data.as_deref().unwrap_or_default())
        .env("ProgramFiles", program_files.as_deref().unwrap_or_default())
        .env(
            "ProgramFiles(x86)",
            program_files_x86.as_deref().unwrap_or_default(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_powershell",
                format!("start trusted PowerShell for {}", invocation.operation),
                error,
            )
        })?;

    let Some(mut stdin) = child.stdin.take() else {
        terminate_and_reap(&mut child);
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!("{} did not expose a stdin pipe", invocation.operation),
        ));
    };
    if let Err(error) = stdin.write_all(&input) {
        drop(stdin);
        terminate_and_reap(&mut child);
        return Err(SandboxError::with_source(
            "hyperv_powershell",
            format!("write {} JSON input", invocation.operation),
            error,
        ));
    }
    drop(stdin);

    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!("{} did not expose a stdout pipe", invocation.operation),
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child);
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!("{} did not expose a stderr pipe", invocation.operation),
        ));
    };
    let limit = invocation.max_output_bytes;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, limit));

    let started_at = Instant::now();
    let mut last_progress = started_at;
    let deadline = started_at
        .checked_add(invocation.timeout)
        .unwrap_or_else(Instant::now);
    let (status, timed_out) = loop {
        if crate::interrupt::requested() {
            terminate_and_reap(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(SandboxError::new(
                "hyperv_powershell",
                format!("{} interrupted; cleanup will now run", invocation.operation),
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => {
                let now = Instant::now();
                if now.duration_since(last_progress) >= Duration::from_secs(10) {
                    println!(
                        "[hyperv/powershell debug] still running: {} (elapsed={}s)",
                        invocation.operation,
                        now.duration_since(started_at).as_secs()
                    );
                    last_progress = now;
                }
                thread::sleep(POLL_INTERVAL)
            }
            Ok(None) => {
                let _ = child.kill();
                let status = child.wait().map_err(|error| {
                    SandboxError::with_source(
                        "hyperv_powershell",
                        format!("reap timed-out {}", invocation.operation),
                        error,
                    )
                })?;
                break (status, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::with_source(
                    "hyperv_powershell",
                    format!("wait for {}", invocation.operation),
                    error,
                ));
            }
        }
    };

    let stdout = join_reader(stdout_reader, invocation.operation, "stdout")?;
    let stderr = join_reader(stderr_reader, invocation.operation, "stderr")?;
    if timed_out {
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!(
                "{} exceeded its {} ms host timeout; resource reconciliation is required",
                invocation.operation,
                invocation.timeout.as_millis()
            ),
        ));
    }
    if stdout.overflowed || stderr.overflowed {
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!(
                "{} exceeded its bounded output limit (stdout {} bytes, stderr {} bytes)",
                invocation.operation, stdout.total, stderr.total
            ),
        ));
    }
    if !stderr.stored.is_empty() {
        println!(
            "[hyperv/powershell debug] {} stderr: {}",
            invocation.operation,
            bounded_diagnostic(&stderr.stored)
        );
    }
    if !status.success() {
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!(
                "{} failed with exit code {:?}: {}",
                invocation.operation,
                status.code(),
                bounded_diagnostic(&stderr.stored)
            ),
        ));
    }
    let result = parse_envelope(invocation.operation, &stdout.stored);
    println!(
        "[hyperv/powershell debug] finished: {} ({})",
        invocation.operation,
        if result.is_ok() { "ok" } else { "failed" }
    );
    result
}

#[cfg(target_os = "windows")]
fn terminate_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "windows")]
fn system_powershell_path() -> SandboxResult<std::path::PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn GetFileAttributesW(path: *const u16) -> u32;
    }
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;

    let mut buffer = vec![0u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(SandboxError::new(
            "hyperv_powershell",
            "cannot resolve the trusted Windows system directory",
        ));
    }
    buffer.truncate(length as usize);
    let system_directory = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer));
    let executable = system_directory
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let wide = executable
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if unsafe { GetFileAttributesW(wide.as_ptr()) } == INVALID_FILE_ATTRIBUTES {
        return Err(SandboxError::new(
            "hyperv_powershell",
            "trusted Windows PowerShell executable is missing",
        ));
    }
    Ok(executable)
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> io::Result<BoundedOutput> {
    let mut stored = Vec::with_capacity(maximum.min(16 * 1024));
    let mut total = 0usize;
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        if stored.len() < maximum {
            let retain = count.min(maximum - stored.len());
            stored.extend_from_slice(&buffer[..retain]);
        }
    }
    Ok(BoundedOutput {
        stored,
        total,
        overflowed: total > maximum,
    })
}

fn join_reader(
    reader: thread::JoinHandle<io::Result<BoundedOutput>>,
    operation: &'static str,
    stream: &'static str,
) -> SandboxResult<BoundedOutput> {
    reader
        .join()
        .map_err(|_| {
            SandboxError::new(
                "hyperv_powershell",
                format!("{operation} {stream} reader panicked"),
            )
        })?
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_powershell",
                format!("read {operation} {stream}"),
                error,
            )
        })
}

fn parse_envelope(operation: &'static str, bytes: &[u8]) -> SandboxResult<Value> {
    let response: ResponseEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        SandboxError::with_source(
            "hyperv_powershell",
            format!("{operation} returned malformed JSON"),
            error,
        )
    })?;
    if response.schema_version != ENVELOPE_SCHEMA_VERSION {
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!(
                "{operation} returned unsupported envelope schema {}",
                response.schema_version
            ),
        ));
    }
    if !response.ok {
        let error = response.error.unwrap_or(PowerShellError {
            code: "unknown".to_string(),
            message: "PowerShell operation failed without an error payload".to_string(),
        });
        return Err(SandboxError::new(
            "hyperv_powershell",
            format!(
                "{operation} failed [{}]: {}",
                safe_error_field(&error.code),
                safe_error_field(&error.message)
            ),
        ));
    }
    response.data.ok_or_else(|| {
        SandboxError::new(
            "hyperv_powershell",
            format!("{operation} succeeded without a data payload"),
        )
    })
}

fn safe_error_field(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|character| {
            if character.is_control() && !matches!(character, '\t' | '\n') {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    safe_error_field(&String::from_utf8_lossy(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_paths_remove_only_supported_windows_extended_prefixes() {
        assert_eq!(
            command_path(
                Path::new(r"\\?\C:\ProgramData\Foxhole\base.vhdx"),
                "test path"
            )
            .unwrap(),
            r"C:\ProgramData\Foxhole\base.vhdx"
        );
        assert_eq!(
            command_path(Path::new(r"\\?\UNC\server\share\base.vhdx"), "test path").unwrap(),
            r"\\server\share\base.vhdx"
        );
        assert!(command_path(Path::new(r"\\?\Volume{0123}\base.vhdx"), "test path").is_err());
    }

    #[test]
    fn parses_only_successful_versioned_envelopes() {
        let value = parse_envelope(
            "test",
            br#"{"schema_version":1,"ok":true,"data":{"answer":42}}"#,
        )
        .unwrap();
        assert_eq!(value["answer"], 42);

        for invalid in [
            br#"{"schema_version":2,"ok":true,"data":{}}"#.as_slice(),
            br#"{"schema_version":1,"ok":true}"#.as_slice(),
            br#"{"schema_version":1,"ok":false,"error":{"code":"x","message":"no"}}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            assert!(parse_envelope("test", invalid).is_err());
        }
    }

    #[test]
    fn bounded_reader_drains_but_reports_overflow() {
        let output = read_bounded(&b"0123456789"[..], 4).unwrap();
        assert_eq!(output.stored, b"0123");
        assert_eq!(output.total, 10);
        assert!(output.overflowed);
    }

    #[test]
    fn hostile_input_remains_json_data() {
        let invocation = PowerShellInvocation::new(
            "test",
            "'static script'",
            serde_json::json!({"path": "'; Remove-VM *; $(whoami)\n"}),
        );
        assert_eq!(invocation.script, "'static script'");
        assert!(
            serde_json::to_string(&invocation.input)
                .unwrap()
                .contains("Remove-VM")
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn native_executor_is_explicitly_unsupported_off_windows() {
        let error = NativePowerShell
            .execute(&PowerShellInvocation::new(
                "detect",
                "'static'",
                Value::Null,
            ))
            .unwrap_err();
        assert_eq!(error.stage, "hyperv_powershell");
    }
}
