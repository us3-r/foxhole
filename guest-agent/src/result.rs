use crate::artifacts::{sha256_file, write_atomic_bytes_new};
use crate::filesystem::ensure_plain_directory;
use crate::monitor;
use crate::monitor::ObservationAvailability;
use crate::request::RunLayout;
use crate::runner::{AgentError, AgentResult};
use foxhole::sandbox::hyperv::guest_protocol::{
    ArtifactManifestEntry, GuestError, GuestNetworkAttestation, GuestResultEnvelope,
    GuestRunRequest, GuestTerminalOutcome, MAX_ARTIFACT_BYTES, MAX_RESULT_BYTES, PROTOCOL_VERSION,
    wire_path_to_native, write_atomic_json_new,
};
use foxhole::structs::SandboxRunResult;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const MAX_STREAM_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_WARNINGS_BYTES: u64 = 1024 * 1024;

#[allow(clippy::too_many_arguments)]
pub fn completed(
    request: &GuestRunRequest,
    mut execution: SandboxRunResult,
    artifacts: Vec<ArtifactManifestEntry>,
    availability: ObservationAvailability,
    network_attestation: Option<GuestNetworkAttestation>,
    agent_version: &str,
    guest_image_version: &str,
    mut warnings: Vec<String>,
) -> GuestResultEnvelope<SandboxRunResult> {
    let coverage = monitor::apply_capture_policy(request, &mut execution, availability);
    if request.target_sha256.is_none() {
        warnings.push("request did not provide target_sha256".to_string());
    }
    let outcome = if execution.timed_out {
        GuestTerminalOutcome::TimedOut
    } else {
        GuestTerminalOutcome::Completed
    };
    GuestResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        run_id: request.run_id.clone(),
        agent_version: agent_version.to_string(),
        guest_image_version: guest_image_version.to_string(),
        outcome,
        execution: Some(execution),
        coverage,
        artifacts,
        warnings: bounded_warnings(warnings),
        network_attestation,
        error: None,
    }
}

pub fn failed(
    request: &GuestRunRequest,
    agent_version: &str,
    guest_image_version: &str,
    error: &AgentError,
    network_attestation: Option<GuestNetworkAttestation>,
) -> GuestResultEnvelope<SandboxRunResult> {
    GuestResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        run_id: request.run_id.clone(),
        agent_version: agent_version.to_string(),
        guest_image_version: guest_image_version.to_string(),
        outcome: GuestTerminalOutcome::AgentFailed,
        execution: None,
        coverage: monitor::unavailable_coverage(request, "execution did not produce observations"),
        artifacts: Vec::new(),
        warnings: Vec::new(),
        network_attestation,
        error: Some(error.to_guest_error()),
    }
}

pub fn cancelled(
    request: &GuestRunRequest,
    agent_version: &str,
    guest_image_version: &str,
    network_attestation: Option<GuestNetworkAttestation>,
) -> GuestResultEnvelope<SandboxRunResult> {
    GuestResultEnvelope {
        protocol_version: PROTOCOL_VERSION,
        run_id: request.run_id.clone(),
        agent_version: agent_version.to_string(),
        guest_image_version: guest_image_version.to_string(),
        outcome: GuestTerminalOutcome::Cancelled,
        execution: None,
        coverage: monitor::unavailable_coverage(request, "run was cancelled before execution"),
        artifacts: Vec::new(),
        warnings: Vec::new(),
        network_attestation,
        error: None,
    }
}

pub fn write(
    layout: &RunLayout,
    envelope: &GuestResultEnvelope<SandboxRunResult>,
) -> AgentResult<String> {
    envelope.validate_metadata().map_err(|error| {
        AgentError::new(
            "result",
            "invalid_result",
            format!("validate result envelope before publication: {error}"),
        )
    })?;
    create_output_directory(&layout.output.join("screenshots"), true)?;
    create_output_directory(&layout.output.join("extracted-files"), true)?;
    validate_artifact_files(layout, &envelope.artifacts)?;

    // Publish the auxiliary B10 output set first. result.json is deliberately last, so a
    // completed marker can never refer to an envelope whose supporting files were not flushed.
    if let Some(execution) = envelope.execution.as_ref() {
        write_atomic_bytes_new(
            &layout.output.join("stdout.txt"),
            execution.stdout.as_bytes(),
            MAX_STREAM_BYTES,
        )?;
        write_atomic_bytes_new(
            &layout.output.join("stderr.txt"),
            execution.stderr.as_bytes(),
            MAX_STREAM_BYTES,
        )?;
        write_event_file(
            &layout.output.join("process-events.json"),
            &execution.processes,
        )?;
        write_event_file(
            &layout.output.join("network-events.json"),
            &execution.network_connections,
        )?;
        write_event_file(
            &layout.output.join("filesystem-events.json"),
            &execution.file_observations,
        )?;
        write_event_file(
            &layout.output.join("registry-events.json"),
            &execution.registry_observations,
        )?;
    }
    let warnings = warning_file_bytes(envelope);
    if !warnings.is_empty() {
        write_atomic_bytes_new(
            &layout.output.join("warnings.txt"),
            &warnings,
            MAX_WARNINGS_BYTES,
        )?;
    }

    let path = layout.output.join("result.json");
    write_atomic_json_new(&path, envelope, MAX_RESULT_BYTES).map_err(|error| {
        AgentError::new(
            "result",
            "publish_result",
            format!("publish result.json: {error}"),
        )
    })?;
    sha256_file(&path, MAX_RESULT_BYTES)
}

pub fn protocol_error(error: &AgentError) -> GuestError {
    error.to_guest_error()
}

pub fn prepare_failed_publication(layout: &RunLayout) -> AgentResult<()> {
    for name in [
        "stdout.txt",
        "stderr.txt",
        "process-events.json",
        "network-events.json",
        "filesystem-events.json",
        "registry-events.json",
        "warnings.txt",
    ] {
        remove_plain_file_if_present(&layout.output.join(name))?;
    }
    clear_known_artifact_directory(&layout.output.join("screenshots"), &[])?;
    clear_known_artifact_directory(
        &layout.output.join("extracted-files"),
        &[
            "network-capture.etl",
            "network-capture.pcapng",
            "telemetry-events.json",
        ],
    )?;
    Ok(())
}

fn clear_known_artifact_directory(path: &Path, allowed_names: &[&str]) -> AgentResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AgentError::with_source(
                "result",
                "inspect_failed_artifacts",
                format!("inspect {}", path.display()),
                error,
            ));
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(AgentError::new(
            "result",
            "unsafe_failed_artifacts",
            format!("failed artifact root is unsafe: {}", path.display()),
        ));
    }
    for entry in fs::read_dir(path).map_err(|error| {
        AgentError::with_source(
            "result",
            "inspect_failed_artifacts",
            format!("enumerate {}", path.display()),
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            AgentError::with_source(
                "result",
                "inspect_failed_artifacts",
                format!("enumerate {}", path.display()),
                error,
            )
        })?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            AgentError::new(
                "result",
                "unknown_failed_artifact",
                "failed artifact has a non-Unicode name",
            )
        })?;
        if !allowed_names
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
        {
            return Err(AgentError::new(
                "result",
                "unknown_failed_artifact",
                format!("refusing to discard unexpected failed artifact: {name}"),
            ));
        }
        remove_plain_file_if_present(&entry.path())?;
    }
    fs::remove_dir(path).map_err(|error| {
        AgentError::with_source(
            "result",
            "remove_failed_artifact_directory",
            format!("remove {}", path.display()),
            error,
        )
    })
}

fn remove_plain_file_if_present(path: &Path) -> AgentResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AgentError::with_source(
                "result",
                "inspect_failed_output",
                format!("inspect {}", path.display()),
                error,
            ));
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(AgentError::new(
            "result",
            "unsafe_failed_output",
            format!("failed output is not a plain file: {}", path.display()),
        ));
    }
    fs::remove_file(path).map_err(|error| {
        AgentError::with_source(
            "result",
            "remove_failed_output",
            format!("remove {}", path.display()),
            error,
        )
    })
}

fn bounded_warnings(warnings: Vec<String>) -> Vec<String> {
    warnings
        .into_iter()
        .take(256)
        .map(|warning| {
            let mut warning: String = warning
                .chars()
                .map(|character| {
                    if character.is_control() && !matches!(character, '\t' | '\n' | '\r') {
                        '\u{fffd}'
                    } else {
                        character
                    }
                })
                .collect();
            if warning.len() > 4096 {
                let mut end = 4096;
                while !warning.is_char_boundary(end) {
                    end -= 1;
                }
                warning.truncate(end);
            }
            warning
        })
        .collect()
}

fn create_output_directory(path: &Path, allow_existing_content: bool) -> AgentResult<()> {
    match fs::create_dir(path) {
        Ok(()) => ensure_plain_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // A prior publication attempt in this claimed run may already have created these
            // empty collection roots. They must still be plain and empty.
            ensure_plain_directory(path)?;
            let mut entries = fs::read_dir(path).map_err(|error| {
                AgentError::with_source(
                    "result",
                    "inspect_output_directory",
                    format!("inspect {}", path.display()),
                    error,
                )
            })?;
            if !allow_existing_content
                && entries
                    .next()
                    .transpose()
                    .map_err(|error| {
                        AgentError::with_source(
                            "result",
                            "inspect_output_directory",
                            format!("enumerate {}", path.display()),
                            error,
                        )
                    })?
                    .is_some()
            {
                return Err(AgentError::new(
                    "result",
                    "nonempty_output_directory",
                    format!("output directory is not empty: {}", path.display()),
                ));
            }
            Ok(())
        }
        Err(error) => Err(AgentError::with_source(
            "result",
            "create_output_directory",
            format!("create {}", path.display()),
            error,
        )),
    }
}

fn validate_artifact_files(
    layout: &RunLayout,
    artifacts: &[ArtifactManifestEntry],
) -> AgentResult<()> {
    let mut expected = HashSet::new();
    for artifact in artifacts {
        if !(artifact.relative_path.starts_with("extracted-files/")
            || artifact.relative_path.starts_with("screenshots/"))
        {
            return Err(AgentError::new(
                "result",
                "invalid_artifact_location",
                format!(
                    "artifact is outside the published artifact roots: {}",
                    artifact.relative_path
                ),
            ));
        }
        let path =
            wire_path_to_native(&layout.output, &artifact.relative_path).map_err(|error| {
                AgentError::new(
                    "result",
                    "invalid_artifact_path",
                    format!("validate artifact path {}: {error}", artifact.relative_path),
                )
            })?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            AgentError::with_source(
                "result",
                "inspect_artifact",
                format!("inspect {}", path.display()),
                error,
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(AgentError::new(
                "result",
                "unsafe_artifact",
                format!("artifact is not a plain file: {}", path.display()),
            ));
        }
        if metadata.len() != artifact.size_bytes {
            return Err(AgentError::new(
                "result",
                "artifact_size_mismatch",
                format!(
                    "artifact size changed before publication: {}",
                    path.display()
                ),
            ));
        }
        let digest = sha256_file(&path, MAX_ARTIFACT_BYTES)?;
        if !digest.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(AgentError::new(
                "result",
                "artifact_digest_mismatch",
                format!(
                    "artifact digest changed before publication: {}",
                    path.display()
                ),
            ));
        }
        expected.insert(artifact.relative_path.to_ascii_lowercase());
    }

    let mut actual = HashSet::new();
    for root_name in ["screenshots", "extracted-files"] {
        collect_artifact_paths(
            &layout.output,
            &layout.output.join(root_name),
            &mut actual,
            0,
        )?;
    }
    if actual != expected {
        return Err(AgentError::new(
            "result",
            "artifact_manifest_mismatch",
            "published artifact files do not exactly match the manifest",
        ));
    }
    Ok(())
}

fn collect_artifact_paths(
    output_root: &Path,
    directory: &Path,
    paths: &mut HashSet<String>,
    depth: usize,
) -> AgentResult<()> {
    if depth > 8 || paths.len() > 4096 {
        return Err(AgentError::new(
            "result",
            "artifact_tree_limit",
            "artifact tree exceeded its bounded traversal limits",
        ));
    }
    ensure_plain_directory(directory)?;
    for entry in fs::read_dir(directory).map_err(|error| {
        AgentError::with_source(
            "result",
            "inspect_artifact_directory",
            format!("enumerate {}", directory.display()),
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            AgentError::with_source(
                "result",
                "inspect_artifact_directory",
                format!("enumerate {}", directory.display()),
                error,
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            AgentError::with_source(
                "result",
                "inspect_artifact",
                format!("inspect {}", path.display()),
                error,
            )
        })?;
        if metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(AgentError::new(
                "result",
                "unsafe_artifact_tree",
                format!(
                    "artifact tree contains a link or reparse point: {}",
                    path.display()
                ),
            ));
        }
        if metadata.is_dir() {
            collect_artifact_paths(output_root, &path, paths, depth + 1)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(output_root).map_err(|_| {
                AgentError::new(
                    "result",
                    "artifact_path_escape",
                    "artifact escaped the output root",
                )
            })?;
            paths.insert(
                relative
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_ascii_lowercase(),
            );
        } else {
            return Err(AgentError::new(
                "result",
                "unsafe_artifact_tree",
                format!(
                    "artifact tree contains a non-file entry: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
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

fn write_event_file<T: serde::Serialize>(path: &std::path::Path, value: &T) -> AgentResult<()> {
    write_atomic_json_new(path, value, MAX_EVENT_BYTES).map_err(|error| {
        AgentError::new(
            "result",
            "publish_event_file",
            format!("publish {}: {error}", path.display()),
        )
    })
}

fn warning_file_bytes(envelope: &GuestResultEnvelope<SandboxRunResult>) -> Vec<u8> {
    let mut warnings = envelope.warnings.clone();
    for coverage in [
        &envelope.coverage.stdout,
        &envelope.coverage.stderr,
        &envelope.coverage.processes,
        &envelope.coverage.network,
        &envelope.coverage.filesystem,
        &envelope.coverage.registry,
    ] {
        warnings.extend(coverage.warnings.iter().cloned());
    }
    if let Some(error) = envelope.error.as_ref() {
        warnings.push(format!("{}:{}: {}", error.stage, error.code, error.message));
    }
    let mut bytes = Vec::new();
    for warning in bounded_warnings(warnings) {
        let line = warning.replace(['\r', '\n'], " ");
        if bytes.len().saturating_add(line.len()).saturating_add(1) > MAX_WARNINGS_BYTES as usize {
            break;
        }
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxhole::sandbox::hyperv::guest_protocol::{
        CaptureCoverage, GuestTerminalOutcome, ObservationCoverage,
    };
    use foxhole::structs::{CleanupStatus, StreamCaptureSummary};

    fn captured() -> CaptureCoverage {
        CaptureCoverage {
            requested: true,
            collected: true,
            complete: true,
            warnings: Vec::new(),
        }
    }

    fn empty_execution() -> SandboxRunResult {
        SandboxRunResult {
            backend: "restricted_process".to_string(),
            network_policy: "deny_all".to_string(),
            integrity_level: "low".to_string(),
            mitigation_profile: "strict".to_string(),
            pid: 42,
            exit_code: Some(0),
            timed_out: false,
            working_dir: Some("C:/guest/work".to_string()),
            duration_ms: 10,
            stdout: "out".to_string(),
            stderr: "err".to_string(),
            stdout_capture: StreamCaptureSummary {
                bytes_seen: 3,
                bytes_stored: 3,
                truncated: false,
            },
            stderr_capture: StreamCaptureSummary {
                bytes_seen: 3,
                bytes_stored: 3,
                truncated: false,
            },
            processes: Vec::new(),
            network_connections: Vec::new(),
            file_observations: Vec::new(),
            registry_observations: Vec::new(),
            mapped_paths: Vec::new(),
            monitor_warnings: Vec::new(),
            cleanup: CleanupStatus {
                attempted: true,
                success: true,
                warnings: Vec::new(),
                leftover_resources: Vec::new(),
            },
        }
    }

    #[test]
    fn publication_writes_the_complete_b10_output_set_before_result() {
        let root =
            std::env::temp_dir().join(format!("foxhole-agent-result-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for directory in ["input", "output", "status"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        let layout = RunLayout {
            root: root.clone(),
            request: root.join("request.json"),
            input: root.join("input"),
            output: root.join("output"),
            status: root.join("status"),
        };
        let coverage = captured();
        let envelope = GuestResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            run_id: "0123456789abcdef".to_string(),
            agent_version: "0.2.0".to_string(),
            guest_image_version: "1.0.0".to_string(),
            outcome: GuestTerminalOutcome::Completed,
            execution: Some(empty_execution()),
            coverage: ObservationCoverage {
                stdout: coverage.clone(),
                stderr: coverage.clone(),
                processes: coverage.clone(),
                network: coverage.clone(),
                filesystem: coverage.clone(),
                registry: coverage,
            },
            artifacts: Vec::new(),
            warnings: vec!["warning".to_string()],
            network_attestation: None,
            error: None,
        };
        let digest = write(&layout, &envelope).unwrap();
        assert_eq!(digest.len(), 64);
        for relative in [
            "result.json",
            "stdout.txt",
            "stderr.txt",
            "process-events.json",
            "network-events.json",
            "filesystem-events.json",
            "registry-events.json",
            "warnings.txt",
        ] {
            assert!(layout.output.join(relative).is_file(), "{relative}");
        }
        for relative in ["screenshots", "extracted-files"] {
            assert!(layout.output.join(relative).is_dir(), "{relative}");
        }
        assert!(write(&layout, &envelope).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_rejects_unmanifested_artifact_files() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-agent-unmanifested-artifact-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        for directory in ["input", "output", "status", "output/extracted-files"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("output/extracted-files/untrusted.bin"), b"data").unwrap();
        let layout = RunLayout {
            root: root.clone(),
            request: root.join("request.json"),
            input: root.join("input"),
            output: root.join("output"),
            status: root.join("status"),
        };
        let coverage = captured();
        let envelope = GuestResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            run_id: "0123456789abcdef".to_string(),
            agent_version: "0.2.0".to_string(),
            guest_image_version: "1.0.0".to_string(),
            outcome: GuestTerminalOutcome::Completed,
            execution: Some(empty_execution()),
            coverage: ObservationCoverage {
                stdout: coverage.clone(),
                stderr: coverage.clone(),
                processes: coverage.clone(),
                network: coverage.clone(),
                filesystem: coverage.clone(),
                registry: coverage,
            },
            artifacts: Vec::new(),
            warnings: Vec::new(),
            network_attestation: None,
            error: None,
        };
        let error = write(&layout, &envelope).unwrap_err();
        assert_eq!(error.code, "artifact_manifest_mismatch");
        fs::remove_dir_all(root).unwrap();
    }
}
