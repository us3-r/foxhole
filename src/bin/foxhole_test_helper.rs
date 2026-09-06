//! Harmless, strictly bounded target behaviors for Foxhole integration tests.
//!
//! This binary intentionally has no unbounded process, memory, CPU, network, or
//! filesystem mode. It never invokes a shell and never performs more than one
//! network connection or creates more than one child per process.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_EMIT_BYTES: usize = 4 * 1024;
const MAX_SLEEP_MS: u64 = 10_000;
const MAX_TREE_DEPTH: u32 = 4;
const MAX_ALLOCATION_MIB: u64 = 64;
const MAX_CPU_SPIN_MS: u64 = 3_000;
const MAX_CONNECT_TIMEOUT_MS: u64 = 1_000;
const MAX_RELATIVE_PATH_BYTES: usize = 512;
const MAX_FILE_BYTES: usize = 4 * 1024;

fn main() {
    if let Err(error) = run(std::env::args_os().skip(1)) {
        eprintln!("foxhole-test-helper: {error}");
        std::process::exit(2);
    }
}

fn run<I>(mut arguments: I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let mode = next_utf8(&mut arguments, "mode")?;
    match mode.as_str() {
        "emit" => emit(&mut arguments),
        "sleep" => bounded_sleep(&mut arguments),
        "spawn-tree" => spawn_tree(&mut arguments),
        "allocate" => allocate(&mut arguments),
        "cpu-spin" => cpu_spin(&mut arguments),
        "connect" => connect(&mut arguments),
        "write-relative" => write_relative(&mut arguments),
        "read-canary" => read_canary(&mut arguments),
        _ => Err(format!(
            "unknown mode {mode:?}; expected emit, sleep, spawn-tree, allocate, cpu-spin, connect, write-relative, or read-canary"
        )),
    }
}

fn emit<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let stream = next_utf8(arguments, "stream (stdout or stderr)")?;
    let text = next_utf8(arguments, "text")?;
    require_end(arguments)?;
    if text.len() > MAX_EMIT_BYTES {
        return Err(format!("emit text exceeds {MAX_EMIT_BYTES} bytes"));
    }
    match stream.as_str() {
        "stdout" => {
            let mut output = std::io::stdout().lock();
            output
                .write_all(text.as_bytes())
                .and_then(|()| output.write_all(b"\n"))
                .and_then(|()| output.flush())
                .map_err(|error| format!("write stdout: {error}"))
        }
        "stderr" => {
            let mut output = std::io::stderr().lock();
            output
                .write_all(text.as_bytes())
                .and_then(|()| output.write_all(b"\n"))
                .and_then(|()| output.flush())
                .map_err(|error| format!("write stderr: {error}"))
        }
        _ => Err("emit stream must be stdout or stderr".to_string()),
    }
}

fn bounded_sleep<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let milliseconds = next_bounded_u64(arguments, "milliseconds", 0, MAX_SLEEP_MS)?;
    require_end(arguments)?;
    thread::sleep(Duration::from_millis(milliseconds));
    Ok(())
}

fn spawn_tree<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let depth = next_bounded_u64(arguments, "depth", 0, u64::from(MAX_TREE_DEPTH))? as u32;
    let milliseconds = next_bounded_u64(arguments, "milliseconds", 0, MAX_SLEEP_MS)?;
    require_end(arguments)?;
    spawn_tree_level(depth, milliseconds)
}

fn spawn_tree_level(depth: u32, milliseconds: u64) -> Result<(), String> {
    let mut child = if depth == 0 {
        None
    } else {
        let executable = std::env::current_exe()
            .map_err(|error| format!("resolve helper executable: {error}"))?;
        Some(
            Command::new(executable)
                .arg("spawn-tree")
                .arg((depth - 1).to_string())
                .arg(milliseconds.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|error| format!("spawn bounded child: {error}"))?,
        )
    };

    println!("pid={} depth={depth}", std::process::id());
    thread::sleep(Duration::from_millis(milliseconds));
    if let Some(child) = child.as_mut() {
        let status = child
            .wait()
            .map_err(|error| format!("wait for bounded child: {error}"))?;
        if !status.success() {
            return Err(format!("bounded child exited with {status}"));
        }
    }
    Ok(())
}

fn allocate<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let mebibytes = next_bounded_u64(arguments, "mebibytes", 1, MAX_ALLOCATION_MIB)?;
    let hold_milliseconds = next_bounded_u64(arguments, "hold milliseconds", 0, MAX_SLEEP_MS)?;
    require_end(arguments)?;

    let bytes = usize::try_from(
        mebibytes
            .checked_mul(1024 * 1024)
            .ok_or_else(|| "allocation byte count overflowed".to_string())?,
    )
    .map_err(|_| "allocation does not fit this platform".to_string())?;
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(bytes)
        .map_err(|error| format!("bounded allocation failed: {error}"))?;
    memory.resize(bytes, 0u8);
    for page in memory.chunks_mut(4096) {
        page[0] = 0xa5;
    }
    println!("allocated_bytes={}", memory.len());
    thread::sleep(Duration::from_millis(hold_milliseconds));
    black_box(memory);
    Ok(())
}

fn cpu_spin<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let milliseconds = next_bounded_u64(arguments, "milliseconds", 0, MAX_CPU_SPIN_MS)?;
    require_end(arguments)?;

    let deadline = Instant::now() + Duration::from_millis(milliseconds);
    let mut value = 0x9e37_79b9_7f4a_7c15u64;
    let mut iterations = 0u64;
    while Instant::now() < deadline {
        value = value
            .rotate_left(7)
            .wrapping_mul(0xbf58_476d_1ce4_e5b9)
            .wrapping_add(iterations);
        iterations = iterations.wrapping_add(1);
        black_box(value);
    }
    println!("cpu_spin_completed_ms={milliseconds}");
    Ok(())
}

fn connect<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let address = next_utf8(arguments, "numeric IP:port")?
        .parse::<SocketAddr>()
        .map_err(|_| "connect address must be one numeric IP:port value".to_string())?;
    let timeout_milliseconds =
        next_bounded_u64(arguments, "timeout milliseconds", 1, MAX_CONNECT_TIMEOUT_MS)?;
    require_end(arguments)?;

    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(
            "connect address is unspecified, multicast, broadcast, or port zero".to_string(),
        );
    }

    let stream = TcpStream::connect_timeout(&address, Duration::from_millis(timeout_milliseconds))
        .map_err(|error| format!("single bounded connection to {address} failed: {error}"))?;
    let _ = stream.shutdown(Shutdown::Both);
    println!("connected={address}");
    Ok(())
}

fn write_relative<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let relative = next_os(arguments, "relative path")?;
    let text = next_utf8(arguments, "text")?;
    require_end(arguments)?;
    if text.len() > MAX_FILE_BYTES {
        return Err(format!("write text exceeds {MAX_FILE_BYTES} bytes"));
    }

    let relative = Path::new(&relative);
    validate_relative_path(relative)?;
    let root = std::env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("resolve working directory: {error}"))?;
    let destination = root.join(relative);
    let parent = destination
        .parent()
        .ok_or_else(|| "relative destination has no parent".to_string())?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|error| format!("resolve destination parent: {error}"))?;
    if !canonical_parent.starts_with(&root) {
        return Err("relative destination resolves outside the working directory".to_string());
    }
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect destination parent: {error}"))?;
    if parent_metadata.file_type().is_symlink() || is_reparse_point(&parent_metadata) {
        return Err("relative destination parent is a link or reparse point".to_string());
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("create relative output without replacement: {error}"))?;
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("write relative output: {error}"))?;
    println!("wrote_relative={}", relative.display());
    Ok(())
}

fn read_canary<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let path = next_os(arguments, "canary path")?;
    let expected = next_utf8(arguments, "expected canary text")?;
    require_end(arguments)?;
    if expected.len() > MAX_FILE_BYTES {
        return Err(format!("expected canary exceeds {MAX_FILE_BYTES} bytes"));
    }

    let mut bytes = Vec::with_capacity(expected.len().min(MAX_FILE_BYTES));
    File::open(Path::new(&path))
        .map_err(|error| format!("open the single requested canary: {error}"))?
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read the bounded canary: {error}"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!("canary exceeds {MAX_FILE_BYTES} bytes"));
    }
    if bytes != expected.as_bytes() {
        return Err("canary contents did not match the expected test marker".to_string());
    }
    println!("canary_match_bytes={}", bytes.len());
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), String> {
    let text = path
        .to_str()
        .ok_or_else(|| "relative path must be Unicode".to_string())?;
    if text.is_empty()
        || text.len() > MAX_RELATIVE_PATH_BYTES
        || text.contains(['\\', ':', '\0'])
        || text.contains("//")
        || text.chars().any(char::is_control)
    {
        return Err(
            "relative path is empty, too long, or contains a forbidden character".to_string(),
        );
    }

    let mut component_count = 0usize;
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err("path must be relative and contain only normal components".to_string());
        };
        let component = component
            .to_str()
            .ok_or_else(|| "relative path component must be Unicode".to_string())?;
        if component.ends_with(['.', ' ']) || is_reserved_windows_name(component) {
            return Err("relative path contains an unsafe Windows component".to_string());
        }
        component_count += 1;
    }
    if component_count == 0 {
        return Err("relative path must contain at least one component".to_string());
    }
    Ok(())
}

fn is_reserved_windows_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(['.', ' '])
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(target_os = "windows")]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(target_os = "windows"))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn next_os<I>(arguments: &mut I, name: &str) -> Result<OsString, String>
where
    I: Iterator<Item = OsString>,
{
    arguments
        .next()
        .ok_or_else(|| format!("missing required {name}"))
}

fn next_utf8<I>(arguments: &mut I, name: &str) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    next_os(arguments, name)?
        .into_string()
        .map_err(|_| format!("{name} must be Unicode"))
}

fn next_bounded_u64<I>(
    arguments: &mut I,
    name: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, String>
where
    I: Iterator<Item = OsString>,
{
    let value = next_utf8(arguments, name)?
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "{name} must be between {minimum} and {maximum}, inclusive"
        ));
    }
    Ok(value)
}

fn require_end<I>(arguments: &mut I) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    if arguments.next().is_some() {
        Err("unexpected extra argument".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn arguments(values: &[&str]) -> impl Iterator<Item = OsString> {
        values
            .iter()
            .map(|value| OsString::from(*value))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn every_expensive_mode_rejects_values_above_its_hard_limit() {
        for values in [
            vec!["sleep", "10001"],
            vec!["spawn-tree", "5", "0"],
            vec!["spawn-tree", "1", "10001"],
            vec!["allocate", "65", "0"],
            vec!["allocate", "1", "10001"],
            vec!["cpu-spin", "3001"],
            vec!["connect", "127.0.0.1:9", "1001"],
        ] {
            assert!(run(arguments(&values)).is_err(), "accepted {values:?}");
        }
    }

    #[test]
    fn relative_path_validation_rejects_escape_and_platform_tricks() {
        for value in [
            "",
            ".",
            "..",
            "../escape",
            "safe/../escape",
            "/absolute",
            r"C:\absolute",
            r"safe\escape",
            "safe//double",
            "safe/NUL.txt",
            "safe/trailing.",
            "safe/trailing ",
        ] {
            assert!(
                validate_relative_path(&PathBuf::from(value)).is_err(),
                "accepted {value:?}"
            );
        }
        assert!(validate_relative_path(Path::new("output/result.txt")).is_ok());
    }

    #[test]
    fn emit_and_file_payloads_are_bounded_before_io() {
        let oversized = "x".repeat(MAX_FILE_BYTES + 1);
        assert!(
            run(vec![
                OsString::from("write-relative"),
                OsString::from("output.txt"),
                OsString::from(&oversized),
            ]
            .into_iter())
            .is_err()
        );
        assert!(
            run(vec![
                OsString::from("read-canary"),
                OsString::from("canary.txt"),
                OsString::from(oversized),
            ]
            .into_iter())
            .is_err()
        );

        let oversized = "x".repeat(MAX_EMIT_BYTES + 1);
        assert!(
            run(vec![
                OsString::from("emit"),
                OsString::from("stdout"),
                OsString::from(oversized),
            ]
            .into_iter())
            .is_err()
        );
    }

    #[test]
    fn connect_accepts_only_one_numeric_unicast_endpoint() {
        for values in [
            vec!["connect", "example.com:443", "100"],
            vec!["connect", "0.0.0.0:80", "100"],
            vec!["connect", "224.0.0.1:80", "100"],
            vec!["connect", "255.255.255.255:80", "100"],
            vec!["connect", "127.0.0.1:0", "100"],
            vec!["connect", "127.0.0.1:80", "100", "extra"],
        ] {
            assert!(run(arguments(&values)).is_err(), "accepted {values:?}");
        }
    }
}
