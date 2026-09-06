use crate::artifact;
use crate::sandbox::backend::{SandboxError, SandboxResult};
use crate::sandbox::hyperv::guest_protocol::{
    self, GuestResultEnvelope, GuestTerminalOutcome, ProtocolState, ProtocolStateMachine,
    StatusRecord,
};
use crate::structs::SandboxRunResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub(crate) const DEFAULT_MAX_RESULT_BYTES: u64 = guest_protocol::MAX_RESULT_BYTES;
pub(crate) const DEFAULT_MAX_STREAM_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_ARTIFACTS: u64 = 512;
pub(crate) const MAX_GUEST_TREE_ENTRIES: u64 = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionLimits {
    pub maximum_result_bytes: u64,
    pub maximum_stream_bytes: u64,
    pub maximum_artifact_bytes: u64,
    pub maximum_total_bytes: u64,
    pub maximum_artifacts: u64,
}

impl Default for CollectionLimits {
    fn default() -> Self {
        Self {
            maximum_result_bytes: DEFAULT_MAX_RESULT_BYTES,
            maximum_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
            maximum_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            maximum_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            maximum_artifacts: DEFAULT_MAX_ARTIFACTS,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct CollectedArtifact {
    pub relative_path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct CollectedGuestOutput {
    pub result: GuestResultEnvelope<SandboxRunResult>,
    pub stdout: String,
    pub stderr: String,
    pub artifacts: Vec<CollectedArtifact>,
    pub warnings: Vec<String>,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PartialCollection {
    pub artifact_count: usize,
    pub total_bytes: u64,
}

struct ArchiveContext<'a> {
    archive_root: &'a Path,
    directory_prefix: &'a Path,
    limits: &'a CollectionLimits,
    artifacts: &'a mut Vec<CollectedArtifact>,
    archived_paths: &'a mut HashSet<String>,
    total_bytes: &'a mut u64,
    visited_entries: &'a mut u64,
}

pub(crate) fn collect(
    mounted_run_root: &Path,
    archive_root: &Path,
    expected_run_id: &str,
    expected_request_sha256: &str,
    limits: &CollectionLimits,
) -> SandboxResult<CollectedGuestOutput> {
    validate_limits(limits)?;
    let output_root = mounted_run_root.join("output");
    validate_plain_directory(&output_root)?;
    prepare_archive_root(archive_root)?;

    let result_bytes = read_bounded_file(
        &output_root.join("result.json"),
        limits.maximum_result_bytes,
    )?;
    let result: GuestResultEnvelope<SandboxRunResult> = serde_json::from_slice(&result_bytes)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                "guest result.json is malformed",
                error,
            )
        })?;
    result
        .validate_metadata()
        .map_err(|error| SandboxError::new("hyperv_result_collection", error.to_string()))?;
    if result.run_id != expected_run_id {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest result run identifier does not match the host run",
        ));
    }
    let result_sha256 = sha256_bytes(&result_bytes);
    validate_status_chain(
        &mounted_run_root.join("status"),
        expected_run_id,
        expected_request_sha256,
        &result_sha256,
        result.outcome,
    )?;
    let mut artifacts = Vec::new();
    let mut total_bytes = 0u64;
    let mut visited_entries = 0u64;
    let mut archived_paths = HashSet::new();
    let mut archive = ArchiveContext {
        archive_root,
        directory_prefix: Path::new("guest-output"),
        limits,
        artifacts: &mut artifacts,
        archived_paths: &mut archived_paths,
        total_bytes: &mut total_bytes,
        visited_entries: &mut visited_entries,
    };
    archive_known_file(
        &output_root.join("result.json"),
        Path::new("guest-output/result.json"),
        &result_bytes,
        &mut archive,
    )?;

    let (stdout_bytes, stderr_bytes) = if result.execution.is_some() {
        (
            read_bounded_file(&output_root.join("stdout.txt"), limits.maximum_stream_bytes)?,
            read_bounded_file(&output_root.join("stderr.txt"), limits.maximum_stream_bytes)?,
        )
    } else {
        (
            read_optional_bounded_file(
                &output_root.join("stdout.txt"),
                limits.maximum_stream_bytes,
            )?,
            read_optional_bounded_file(
                &output_root.join("stderr.txt"),
                limits.maximum_stream_bytes,
            )?,
        )
    };
    for (name, bytes) in [
        ("stdout.txt", stdout_bytes.as_slice()),
        ("stderr.txt", stderr_bytes.as_slice()),
    ] {
        if !bytes.is_empty() || output_root.join(name).exists() {
            archive_known_file(
                &output_root.join(name),
                &Path::new("guest-output").join(name),
                bytes,
                &mut archive,
            )?;
        }
    }

    if let Some(execution) = result.execution.as_ref() {
        for (name, expected) in [
            (
                "process-events.json",
                serde_json::to_value(&execution.processes),
            ),
            (
                "network-events.json",
                serde_json::to_value(&execution.network_connections),
            ),
            (
                "filesystem-events.json",
                serde_json::to_value(&execution.file_observations),
            ),
            (
                "registry-events.json",
                serde_json::to_value(&execution.registry_observations),
            ),
        ] {
            let expected = expected.map_err(|error| {
                SandboxError::with_source(
                    "hyperv_result_collection",
                    "serialize the execution event list",
                    error,
                )
            })?;
            let bytes = read_bounded_file(&output_root.join(name), limits.maximum_stream_bytes)?;
            let observed: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
                SandboxError::with_source(
                    "hyperv_result_collection",
                    format!("guest {name} is malformed"),
                    error,
                )
            })?;
            if observed != expected {
                return Err(SandboxError::new(
                    "hyperv_result_collection",
                    format!("guest {name} contradicts result.json"),
                ));
            }
            archive_known_file(
                &output_root.join(name),
                &Path::new("guest-output").join(name),
                &bytes,
                &mut archive,
            )?;
        }
    }

    for directory_name in ["screenshots", "extracted-files"] {
        let directory = output_root.join(directory_name);
        if !directory.exists() {
            continue;
        }
        validate_plain_directory(&directory)?;
        collect_directory(&output_root, &directory, &mut archive, 0)?;
    }

    let mut warnings = Vec::new();
    let warnings_path = output_root.join("warnings.txt");
    if warnings_path.exists() {
        let bytes = read_bounded_file(&warnings_path, limits.maximum_stream_bytes)?;
        warnings.extend(
            String::from_utf8_lossy(&bytes)
                .lines()
                .take(1_024)
                .map(|line| line.chars().take(1_024).collect()),
        );
        archive_known_file(
            &warnings_path,
            Path::new("guest-output/warnings.txt"),
            &bytes,
            &mut archive,
        )?;
    }

    let status_root = mounted_run_root.join("status");
    for state in all_protocol_states() {
        let source = status_root.join(state.file_name());
        if !source.exists() {
            continue;
        }
        let bytes = read_bounded_file(&source, guest_protocol::MAX_STATUS_BYTES)?;
        archive_known_file(
            &source,
            &Path::new("guest-status").join(state.file_name()),
            &bytes,
            &mut archive,
        )?;
    }
    let claim_path = status_root.join("agent-claim.json");
    if claim_path.exists() {
        let bytes = read_bounded_file(&claim_path, guest_protocol::MAX_STATUS_BYTES)?;
        archive_known_file(
            &claim_path,
            Path::new("guest-status/agent-claim.json"),
            &bytes,
            &mut archive,
        )?;
    }
    validate_artifact_manifest(&result, &artifacts)?;

    let stdout = decode_captured_stream(&stdout_bytes);
    let stderr = decode_captured_stream(&stderr_bytes);

    Ok(CollectedGuestOutput {
        result,
        stdout,
        stderr,
        artifacts,
        warnings,
        total_bytes,
    })
}

pub(crate) fn collect_partial(
    mounted_run_root: &Path,
    archive_root: &Path,
    limits: &CollectionLimits,
) -> SandboxResult<PartialCollection> {
    validate_limits(limits)?;
    prepare_archive_root(archive_root)?;
    let mut artifacts = Vec::new();
    let mut total_bytes = 0u64;
    let mut visited_entries = 0u64;
    let mut archived_paths = HashSet::new();
    let mut archive = ArchiveContext {
        archive_root,
        directory_prefix: Path::new("partial-guest-output"),
        limits,
        artifacts: &mut artifacts,
        archived_paths: &mut archived_paths,
        total_bytes: &mut total_bytes,
        visited_entries: &mut visited_entries,
    };

    let output_root = mounted_run_root.join("output");
    if output_root.exists() {
        validate_plain_directory(&output_root)?;
        for (name, maximum) in [
            ("result.json", limits.maximum_result_bytes),
            ("stdout.txt", limits.maximum_stream_bytes),
            ("stderr.txt", limits.maximum_stream_bytes),
            ("process-events.json", limits.maximum_stream_bytes),
            ("network-events.json", limits.maximum_stream_bytes),
            ("filesystem-events.json", limits.maximum_stream_bytes),
            ("registry-events.json", limits.maximum_stream_bytes),
            ("warnings.txt", limits.maximum_stream_bytes),
        ] {
            let source = output_root.join(name);
            if !source.exists() {
                continue;
            }
            let bytes = read_bounded_file(&source, maximum)?;
            archive_known_file(
                &source,
                &Path::new("partial-guest-output").join(name),
                &bytes,
                &mut archive,
            )?;
        }
        for directory_name in ["screenshots", "extracted-files"] {
            let directory = output_root.join(directory_name);
            if directory.exists() {
                validate_plain_directory(&directory)?;
                collect_directory(&output_root, &directory, &mut archive, 0)?;
            }
        }
    }

    let status_root = mounted_run_root.join("status");
    if status_root.exists() {
        validate_plain_directory(&status_root)?;
        for name in all_protocol_states()
            .iter()
            .map(|state| state.file_name())
            .chain(std::iter::once("agent-claim.json"))
        {
            let source = status_root.join(name);
            if !source.exists() {
                continue;
            }
            let bytes = read_bounded_file(&source, guest_protocol::MAX_STATUS_BYTES)?;
            archive_known_file(
                &source,
                &Path::new("partial-guest-status").join(name),
                &bytes,
                &mut archive,
            )?;
        }
    }

    Ok(PartialCollection {
        artifact_count: artifacts.len(),
        total_bytes,
    })
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    archive: &mut ArchiveContext<'_>,
    depth: usize,
) -> SandboxResult<()> {
    if depth > 16 {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest artifact directory nesting exceeds 16 levels",
        ));
    }
    for entry in fs::read_dir(directory).map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            format!("enumerate guest artifact directory {}", directory.display()),
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                "read a guest artifact entry",
                error,
            )
        })?;
        charge_tree_entry(archive.visited_entries)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                format!("inspect guest artifact {}", path.display()),
                error,
            )
        })?;
        reject_link_or_reparse(&path, &metadata)?;
        if metadata.is_dir() {
            collect_directory(root, &path, archive, depth + 1)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                format!("guest artifact is not a regular file: {}", path.display()),
            ));
        }
        if archive.artifacts.len() as u64 >= archive.limits.maximum_artifacts
            || metadata.len() > archive.limits.maximum_artifact_bytes
        {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest artifact count or per-file size exceeds its limit",
            ));
        }
        let relative = path.strip_prefix(root).map_err(|_| {
            SandboxError::new(
                "hyperv_result_collection",
                "guest artifact escaped the extraction root",
            )
        })?;
        validate_relative_path(relative)?;
        let archived_relative = archive.directory_prefix.join(relative);
        register_archive_path(&archived_relative, archive.archived_paths)?;
        let destination = archive.archive_root.join(&archived_relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                SandboxError::with_source(
                    "hyperv_result_collection",
                    "create an artifact archive directory",
                    error,
                )
            })?;
        }
        add_total_bytes(archive.total_bytes, metadata.len(), archive.limits)?;
        let sha256 = copy_new_bounded(&path, &destination, metadata.len())?;
        archive.artifacts.push(CollectedArtifact {
            relative_path: archived_relative,
            size_bytes: metadata.len(),
            sha256,
        });
    }
    Ok(())
}

fn charge_tree_entry(visited_entries: &mut u64) -> SandboxResult<()> {
    *visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
        SandboxError::new(
            "hyperv_result_collection",
            "guest artifact entry count overflowed",
        )
    })?;
    if *visited_entries > MAX_GUEST_TREE_ENTRIES {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest artifact tree exceeds the aggregate entry limit",
        ));
    }
    Ok(())
}

fn archive_known_file(
    source: &Path,
    relative: &Path,
    expected_bytes: &[u8],
    archive: &mut ArchiveContext<'_>,
) -> SandboxResult<()> {
    if archive.artifacts.len() as u64 >= archive.limits.maximum_artifacts
        || expected_bytes.len() as u64 > archive.limits.maximum_artifact_bytes
    {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest output count or per-file archive size exceeds its limit",
        ));
    }
    validate_relative_path(relative)?;
    register_archive_path(relative, archive.archived_paths)?;
    add_total_bytes(
        archive.total_bytes,
        expected_bytes.len() as u64,
        archive.limits,
    )?;
    let destination = archive.archive_root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                "create a guest-output archive directory",
                error,
            )
        })?;
    }
    let sha256 = copy_new_bounded(source, &destination, expected_bytes.len() as u64)?;
    if sha256 != sha256_bytes(expected_bytes) {
        let _ = fs::remove_file(&destination);
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest output changed between validation and archival",
        ));
    }
    archive.artifacts.push(CollectedArtifact {
        relative_path: relative.to_path_buf(),
        size_bytes: expected_bytes.len() as u64,
        sha256,
    });
    Ok(())
}

fn copy_new_bounded(source: &Path, destination: &Path, expected: u64) -> SandboxResult<String> {
    let mut input = File::open(source).map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            format!("open guest artifact {}", source.display()),
            error,
        )
    })?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                format!("create archived artifact {}", destination.display()),
                error,
            )
        })?;
    let mut copied = 0u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|error| {
            let _ = fs::remove_file(destination);
            SandboxError::with_source(
                "hyperv_result_collection",
                format!("read guest artifact {}", source.display()),
                error,
            )
        })?;
        if read == 0 {
            break;
        }
        copied = copied.saturating_add(read as u64);
        if copied > expected {
            drop(output);
            let _ = fs::remove_file(destination);
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest artifact grew while it was being copied",
            ));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(|error| {
            let _ = fs::remove_file(destination);
            SandboxError::with_source(
                "hyperv_result_collection",
                format!("write archived artifact {}", destination.display()),
                error,
            )
        })?;
    }
    if copied != expected {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest artifact changed while it was being copied",
        ));
    }
    output.flush().map_err(|error| {
        SandboxError::with_source("hyperv_result_collection", "flush archived artifact", error)
    })?;
    output.sync_all().map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            "durably store archived artifact",
            error,
        )
    })?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_bounded_file(path: &Path, maximum: u64) -> SandboxResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            format!("inspect guest output {}", path.display()),
            error,
        )
    })?;
    reject_link_or_reparse(path, &metadata)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            format!(
                "guest output is non-regular or oversized: {}",
                path.display()
            ),
        ));
    }
    let mut file = File::open(path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            format!("open guest output {}", path.display()),
            error,
        )
    })?;
    let mut bytes = Vec::with_capacity(metadata.len().min(maximum) as usize);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                format!("read guest output {}", path.display()),
                error,
            )
        })?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest output changed or exceeded its limit while being read",
        ));
    }
    Ok(bytes)
}

fn read_optional_bounded_file(path: &Path, maximum: u64) -> SandboxResult<Vec<u8>> {
    match read_bounded_file(path, maximum) {
        Ok(bytes) => Ok(bytes),
        Err(error) if !path.exists() => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// Decode console output from Windows tools without losing the raw archived bytes.
/// PowerShell can emit UTF-16LE diagnostics while native tools emit UTF-8/ACP text;
/// a single stream can therefore contain both encodings after several children exit.
fn decode_captured_stream(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16_lossy(&units);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16_lossy(&units);
    }

    // Mixed native/PowerShell output has no BOM. When NULs are frequent, the
    // printable low bytes are the UTF-16LE/BE text; remove only those NULs and
    // then apply UTF-8 replacement handling to any remaining non-UTF-8 bytes.
    let nul_count = bytes.iter().filter(|byte| **byte == 0).count();
    if nul_count >= 2 && nul_count * 20 >= bytes.len().max(1) {
        let without_nuls = bytes
            .iter()
            .copied()
            .filter(|byte| *byte != 0)
            .collect::<Vec<_>>();
        return String::from_utf8_lossy(&without_nuls).into_owned();
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn validate_status_chain(
    status_root: &Path,
    expected_run_id: &str,
    expected_request_sha256: &str,
    expected_result_sha256: &str,
    outcome: GuestTerminalOutcome,
) -> SandboxResult<()> {
    guest_protocol::validate_sha256(expected_request_sha256)
        .map_err(|error| SandboxError::new("hyperv_result_collection", error.to_string()))?;
    validate_plain_directory(status_root)?;

    let allowed_names: HashSet<&str> = all_protocol_states()
        .iter()
        .map(|state| state.file_name())
        .chain(std::iter::once("agent-claim.json"))
        .collect();
    let mut entry_count = 0usize;
    for entry in fs::read_dir(status_root).map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            "enumerate guest protocol status directory",
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                "read a guest protocol status entry",
                error,
            )
        })?;
        entry_count += 1;
        if entry_count > 16 {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest protocol status directory contains too many entries",
            ));
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            SandboxError::new(
                "hyperv_result_collection",
                "guest protocol status filename is not valid Unicode",
            )
        })?;
        if !allowed_names.contains(name) {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                format!("guest protocol status directory contains an unexpected entry: {name}"),
            ));
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                "inspect a guest protocol status entry",
                error,
            )
        })?;
        reject_link_or_reparse(&entry.path(), &metadata)?;
        if !metadata.is_file() {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest protocol status entries must be regular files",
            ));
        }
    }

    let mut records = Vec::new();
    for state in all_protocol_states() {
        let path = status_root.join(state.file_name());
        if !path.exists() {
            continue;
        }
        let bytes = read_bounded_file(&path, guest_protocol::MAX_STATUS_BYTES)?;
        let record: StatusRecord = serde_json::from_slice(&bytes).map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                format!("guest protocol status {} is malformed", state.file_name()),
                error,
            )
        })?;
        if record.state != state {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest protocol status filename contradicts its encoded state",
            ));
        }
        records.push(record);
    }
    records.sort_by_key(|record| record.sequence);
    let mut machine = ProtocolStateMachine::new(expected_run_id)
        .map_err(|error| SandboxError::new("hyperv_result_collection", error.to_string()))?;
    for record in &records {
        if record.request_sha256.as_deref() != Some(expected_request_sha256) {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest protocol status is not bound to the staged request bytes",
            ));
        }
        machine
            .observe(record)
            .map_err(|error| SandboxError::new("hyperv_result_collection", error.to_string()))?;
        let result_state = matches!(
            record.state,
            ProtocolState::Completed | ProtocolState::Failed | ProtocolState::ShutdownReady
        );
        if result_state && record.result_sha256.as_deref() != Some(expected_result_sha256) {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest terminal status does not authenticate result.json",
            ));
        }
        if !result_state && record.result_sha256.is_some() {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "non-terminal guest status unexpectedly refers to result.json",
            ));
        }
    }
    for required in [
        ProtocolState::HostReady,
        ProtocolState::RequestWritten,
        ProtocolState::StartAllowed,
        ProtocolState::ShutdownReady,
    ] {
        if !machine.has_seen(required) {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                format!("guest protocol did not reach required state {required:?}"),
            ));
        }
    }
    if matches!(
        outcome,
        GuestTerminalOutcome::Completed | GuestTerminalOutcome::TimedOut
    ) && !machine.has_seen(ProtocolState::GuestReady)
    {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "executed guest result omitted the trusted GuestReady attestation state",
        ));
    }
    let outcome_matches = match outcome {
        GuestTerminalOutcome::Completed | GuestTerminalOutcome::TimedOut => {
            machine.has_seen(ProtocolState::Running)
                && machine.has_seen(ProtocolState::Completed)
                && !machine.has_seen(ProtocolState::Failed)
                && !machine.has_seen(ProtocolState::CancelRequested)
        }
        GuestTerminalOutcome::AgentFailed => {
            machine.has_seen(ProtocolState::Failed)
                && !machine.has_seen(ProtocolState::Completed)
                && !machine.has_seen(ProtocolState::CancelRequested)
        }
        GuestTerminalOutcome::Cancelled => {
            machine.has_seen(ProtocolState::CancelRequested)
                && !machine.has_seen(ProtocolState::Completed)
                && !machine.has_seen(ProtocolState::Failed)
        }
    };
    if !outcome_matches {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest result outcome contradicts the authenticated protocol state chain",
        ));
    }
    Ok(())
}

fn all_protocol_states() -> [ProtocolState; 9] {
    [
        ProtocolState::HostReady,
        ProtocolState::RequestWritten,
        ProtocolState::StartAllowed,
        ProtocolState::CancelRequested,
        ProtocolState::GuestReady,
        ProtocolState::Running,
        ProtocolState::Completed,
        ProtocolState::Failed,
        ProtocolState::ShutdownReady,
    ]
}

fn register_archive_path(path: &Path, paths: &mut HashSet<String>) -> SandboxResult<()> {
    let folded = path.to_string_lossy().replace('\\', "/").to_lowercase();
    if !paths.insert(folded) {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest output contains a case-insensitive duplicate archive path",
        ));
    }
    Ok(())
}

fn add_total_bytes(
    total: &mut u64,
    additional: u64,
    limits: &CollectionLimits,
) -> SandboxResult<()> {
    *total = total.checked_add(additional).ok_or_else(|| {
        SandboxError::new(
            "hyperv_result_collection",
            "guest output aggregate byte count overflowed",
        )
    })?;
    if *total > limits.maximum_total_bytes {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest output exceeds the aggregate size limit",
        ));
    }
    Ok(())
}

fn validate_artifact_manifest(
    result: &GuestResultEnvelope<SandboxRunResult>,
    artifacts: &[CollectedArtifact],
) -> SandboxResult<()> {
    let by_path: HashMap<String, &CollectedArtifact> = artifacts
        .iter()
        .map(|artifact| {
            (
                artifact
                    .relative_path
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_lowercase(),
                artifact,
            )
        })
        .collect();
    for claimed in &result.artifacts {
        let key = format!("guest-output/{}", claimed.relative_path).to_lowercase();
        let observed = by_path.get(&key).ok_or_else(|| {
            SandboxError::new(
                "hyperv_result_collection",
                format!(
                    "guest artifact manifest refers to a missing file: {}",
                    claimed.relative_path
                ),
            )
        })?;
        if observed.size_bytes != claimed.size_bytes
            || !observed.sha256.eq_ignore_ascii_case(&claimed.sha256)
        {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                format!(
                    "guest artifact manifest hash or size is wrong: {}",
                    claimed.relative_path
                ),
            ));
        }
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn prepare_archive_root(path: &Path) -> SandboxResult<()> {
    if !path.is_absolute() {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "artifact archive root must be absolute",
        ));
    }
    fs::create_dir(path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            "create a new artifact archive root",
            error,
        )
    })
}

fn validate_plain_directory(path: &Path) -> SandboxResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SandboxError::with_source(
            "hyperv_result_collection",
            format!("inspect guest output directory {}", path.display()),
            error,
        )
    })?;
    reject_link_or_reparse(path, &metadata)?;
    if !metadata.is_dir() {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            format!("guest output path is not a directory: {}", path.display()),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> SandboxResult<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest artifact path is empty, absolute, or contains traversal",
        ));
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                "guest artifact path contains a non-normal component",
            ));
        };
        artifact::validate_file_name_component(name).map_err(|error| {
            SandboxError::with_source(
                "hyperv_result_collection",
                "guest artifact name is unsafe on the Windows host",
                error,
            )
        })?;
    }
    Ok(())
}

fn reject_link_or_reparse(path: &Path, metadata: &fs::Metadata) -> SandboxResult<()> {
    if metadata.file_type().is_symlink() {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            format!("guest output contains a symbolic link: {}", path.display()),
        ));
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(SandboxError::new(
                "hyperv_result_collection",
                format!("guest output contains a reparse point: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn validate_limits(limits: &CollectionLimits) -> SandboxResult<()> {
    if limits.maximum_result_bytes == 0
        || limits.maximum_stream_bytes == 0
        || limits.maximum_artifact_bytes == 0
        || limits.maximum_total_bytes == 0
        || limits.maximum_artifacts == 0
        || limits.maximum_result_bytes > limits.maximum_total_bytes
        || limits.maximum_stream_bytes > limits.maximum_total_bytes
        || limits.maximum_artifact_bytes > limits.maximum_total_bytes
    {
        return Err(SandboxError::new(
            "hyperv_result_collection",
            "guest result collection limits are invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_stream_decoder_handles_mixed_native_and_utf16_text() {
        let mut bytes = b"Access is denied.\r\n".to_vec();
        bytes.extend(
            "Windows PowerShell terminated with the following error:\r\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let decoded = decode_captured_stream(&bytes);
        assert!(decoded.contains("Access is denied."));
        assert!(decoded.contains("Windows PowerShell terminated"));
        assert!(!decoded.contains('\0'));
    }

    #[test]
    fn captured_stream_decoder_handles_utf16_bom() {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend("diagnostic".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_captured_stream(&bytes), "diagnostic");
    }

    #[test]
    fn relative_artifact_paths_are_strict() {
        assert!(validate_relative_path(Path::new("nested/file.bin")).is_ok());
        for invalid in ["", "../escape", "/absolute", "./same"] {
            assert!(validate_relative_path(Path::new(invalid)).is_err());
        }
    }

    #[test]
    fn invalid_limit_relationships_fail_closed() {
        let mut limits = CollectionLimits::default();
        assert!(validate_limits(&limits).is_ok());
        limits.maximum_artifact_bytes = limits.maximum_total_bytes + 1;
        assert!(validate_limits(&limits).is_err());
    }

    #[test]
    fn every_guest_tree_entry_consumes_the_shared_budget() {
        let mut visited = MAX_GUEST_TREE_ENTRIES - 1;
        charge_tree_entry(&mut visited).expect("the final allowed entry remains valid");
        let error = charge_tree_entry(&mut visited).expect_err("entry 4097 must be rejected");
        assert!(error.to_string().contains("aggregate entry limit"));
    }

    #[test]
    fn status_chain_binds_request_and_result_hashes() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-status-chain-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let run_id = "0123456789abcdef";
        let request_hash = "ab".repeat(32);
        let result_hash = "cd".repeat(32);
        let states = [
            ProtocolState::HostReady,
            ProtocolState::RequestWritten,
            ProtocolState::StartAllowed,
            ProtocolState::GuestReady,
            ProtocolState::Running,
            ProtocolState::Completed,
            ProtocolState::ShutdownReady,
        ];
        for (index, state) in states.into_iter().enumerate() {
            let mut record = StatusRecord::new(run_id, index as u64 + 1, state);
            record.request_sha256 = Some(request_hash.clone());
            if matches!(
                state,
                ProtocolState::Completed | ProtocolState::ShutdownReady
            ) {
                record.result_sha256 = Some(result_hash.clone());
            }
            guest_protocol::write_atomic_json_new(
                &root.join(state.file_name()),
                &record,
                guest_protocol::MAX_STATUS_BYTES,
            )
            .unwrap();
        }
        assert!(
            validate_status_chain(
                &root,
                run_id,
                &request_hash,
                &result_hash,
                GuestTerminalOutcome::Completed,
            )
            .is_ok()
        );
        assert!(
            validate_status_chain(
                &root,
                run_id,
                &request_hash,
                &"ef".repeat(32),
                GuestTerminalOutcome::Completed,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
