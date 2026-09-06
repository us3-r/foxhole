use super::model::*;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

const HOST_REPORT_GLOB_PREFIX: &str = "fh_";
const MAX_DISCOVERY_ENTRIES: u64 = 4_096;
const MAX_DISCOVERY_REPORTS: u64 = 512;
const MAX_HOST_REPORT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_GUEST_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVENT_JSON_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANALYSIS_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ANALYSIS_TOTAL_INPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ANALYSIS_INPUT_FILES: u64 = 512;

#[derive(Debug)]
struct AnalysisInputBudget {
    files: u64,
    bytes: u64,
}

impl AnalysisInputBudget {
    fn new() -> Self {
        Self { files: 0, bytes: 0 }
    }

    fn charge(&mut self, bytes: u64) -> io::Result<()> {
        self.files = self
            .files
            .checked_add(1)
            .ok_or_else(|| invalid_data("analysis input file count overflowed"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid_data("analysis input byte count overflowed"))?;
        if self.files > MAX_ANALYSIS_INPUT_FILES || self.bytes > MAX_ANALYSIS_TOTAL_INPUT_BYTES {
            return Err(invalid_data(format!(
                "analysis input budget exceeded (files: {}/{}, bytes: {}/{})",
                self.files, MAX_ANALYSIS_INPUT_FILES, self.bytes, MAX_ANALYSIS_TOTAL_INPUT_BYTES
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredRun {
    pub report_path: PathBuf,
    pub run_directory: PathBuf,
    pub report_name: String,
    pub target_name: String,
    pub generated_at_unix_ms: u64,
}

struct RunLayout {
    source_base: PathBuf,
    host_report: PathBuf,
    run_directory: PathBuf,
}

pub fn load_run(input: &Path) -> io::Result<NormalizedRun> {
    require_windows_analysis()?;
    let mut budget = AnalysisInputBudget::new();
    let layout = discover_layout(input, &mut budget)?;
    let host = read_json(
        &layout.host_report,
        "host report",
        MAX_HOST_REPORT_BYTES,
        &mut budget,
    )?;
    let host_object = host
        .as_object()
        .ok_or_else(|| invalid_data("host report envelope must be a JSON object"))?;
    let run_id = string_at(&host, &["backend_metadata", "run_id"])
        .filter(|value| valid_run_id(value))
        .ok_or_else(|| invalid_data("host report is missing backend_metadata.run_id"))?
        .to_string();
    if layout
        .run_directory
        .file_name()
        .and_then(|name| name.to_str())
        != Some(run_id.as_str())
    {
        return Err(invalid_data(
            "host report run ID does not match the Hyper-V run directory",
        ));
    }

    let guest_output = layout
        .run_directory
        .join("collected-artifacts")
        .join("guest-output");
    let result_path = guest_output.join("result.json");
    let guest = read_json(
        &result_path,
        "guest result",
        MAX_GUEST_RESULT_BYTES,
        &mut budget,
    )?;
    let guest_object = guest
        .as_object()
        .ok_or_else(|| invalid_data("guest result envelope must be a JSON object"))?;
    if guest.get("run_id").and_then(Value::as_str) != Some(run_id.as_str()) {
        return Err(invalid_data(
            "guest result run ID does not match the host report",
        ));
    }
    let execution = guest
        .get("execution")
        .filter(|value| value.is_object())
        .cloned()
        .or_else(|| host.get("result").cloned())
        .ok_or_else(|| invalid_data("run envelope does not contain an execution object"))?;
    let root_pid = u32_at(&execution, &["pid"]).unwrap_or(0);

    let mut warnings = Vec::new();
    let mut source_paths = vec![
        display_relative(&layout.source_base, &layout.host_report),
        display_relative(&layout.source_base, &result_path),
    ];
    let process_path = guest_output.join("process-events.json");
    let network_path = guest_output.join("network-events.json");
    let filesystem_path = guest_output.join("filesystem-events.json");
    let registry_path = guest_output.join("registry-events.json");

    let process_values = load_event_array(
        &process_path,
        execution.get("processes"),
        "process",
        &layout.source_base,
        &mut warnings,
        &mut source_paths,
        &mut budget,
    )?;
    let network_values = load_event_array(
        &network_path,
        execution.get("network_connections"),
        "network",
        &layout.source_base,
        &mut warnings,
        &mut source_paths,
        &mut budget,
    )?;
    let filesystem_values = load_event_array(
        &filesystem_path,
        execution.get("file_observations"),
        "filesystem",
        &layout.source_base,
        &mut warnings,
        &mut source_paths,
        &mut budget,
    )?;
    let registry_values = load_event_array(
        &registry_path,
        execution.get("registry_observations"),
        "registry",
        &layout.source_base,
        &mut warnings,
        &mut source_paths,
        &mut budget,
    )?;

    let raw_event_counts = RawEventCounts {
        process: process_values.len(),
        network: network_values.len(),
        filesystem: filesystem_values.len(),
        registry: registry_values.len(),
    };
    let process_source = source_for_events(&layout.source_base, &process_path, &result_path);
    let network_source = source_for_events(&layout.source_base, &network_path, &result_path);
    let filesystem_source = source_for_events(&layout.source_base, &filesystem_path, &result_path);
    let registry_source = source_for_events(&layout.source_base, &registry_path, &result_path);

    let (processes, process_count) =
        normalize_processes(&process_values, &process_source, &mut warnings);
    let (file_events, file_count) = normalize_files(
        &filesystem_values,
        &filesystem_source,
        &processes,
        root_pid,
        &mut warnings,
    );
    let (registry_events, registry_count) = normalize_registry(
        &registry_values,
        &registry_source,
        &processes,
        root_pid,
        &mut warnings,
    );
    let (network_events, network_count) = normalize_network(
        &network_values,
        &network_source,
        &processes,
        root_pid,
        &mut warnings,
    );
    let artifacts = normalize_artifacts(
        guest
            .get("artifacts")
            .or_else(|| host.pointer("/result/artifacts")),
        &guest_output,
        &display_relative(&layout.source_base, &result_path),
        &mut warnings,
        &mut budget,
    )?;

    let target = host
        .get("target")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let target_hashes = extract_target_hashes(&target, &host, &guest, &execution);
    let sandbox = host
        .get("sandbox")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let coverage = guest
        .get("coverage")
        .cloned()
        .or_else(|| host.get("coverage").cloned())
        .unwrap_or_else(|| Value::Object(Map::new()));
    let limitations = collect_limitations(host_object, guest_object, &execution, &coverage);

    source_paths.sort();
    source_paths.dedup();
    let mut raw = BTreeMap::new();
    raw.insert("guest_result".to_string(), guest);
    raw.insert("host_report".to_string(), host);

    Ok(NormalizedRun {
        schema_version: NORMALIZED_SCHEMA_VERSION.to_string(),
        run_id,
        target,
        target_hashes,
        sandbox,
        execution,
        coverage,
        limitations,
        raw_event_counts,
        normalized_event_counts: RawEventCounts {
            process: process_count,
            network: network_count,
            filesystem: file_count,
            registry: registry_count,
        },
        processes,
        file_events,
        registry_events,
        network_events,
        artifacts,
        validation_warnings: warnings,
        source_paths,
        raw,
    })
}

fn discover_layout(input: &Path, budget: &mut AnalysisInputBudget) -> io::Result<RunLayout> {
    let input = fs::canonicalize(input)?;
    let direct_artifacts = input.join("collected-artifacts");
    let (source_base, direct_run) =
        if crate::artifact::pin_safe_directory_tree(&direct_artifacts, false).is_ok() {
            let source_base = input
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .ok_or_else(|| invalid_data("Hyper-V run directory is not below hyperv/runs"))?
                .to_path_buf();
            (source_base, Some(input.clone()))
        } else {
            (input.clone(), None)
        };
    let mut matches = discover_runs_from_source(&source_base, direct_run.as_deref(), budget)?;
    if matches.len() != 1 {
        return Err(invalid_data(format!(
            "expected exactly one matching fh_*.json host report and Hyper-V run, found {}",
            matches.len()
        )));
    }
    let selected = matches.remove(0);
    Ok(RunLayout {
        source_base,
        host_report: selected.report_path,
        run_directory: selected.run_directory,
    })
}

/// Finds analyzable host-report/Hyper-V-run pairs, newest report first.
pub fn discover_runs(input: &Path) -> io::Result<Vec<DiscoveredRun>> {
    require_windows_analysis()?;
    let mut budget = AnalysisInputBudget::new();
    let input = fs::canonicalize(input)?;
    let direct_artifacts = input.join("collected-artifacts");
    let (source_base, direct_run) =
        if crate::artifact::pin_safe_directory_tree(&direct_artifacts, false).is_ok() {
            let source_base = input
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .ok_or_else(|| invalid_data("Hyper-V run directory is not below hyperv/runs"))?
                .to_path_buf();
            (source_base, Some(input))
        } else {
            (input, None)
        };
    discover_runs_from_source(&source_base, direct_run.as_deref(), &mut budget)
}

pub(super) fn require_windows_analysis() -> io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Foxhole report analysis is supported only on Windows because its filesystem containment relies on Windows handle pinning",
        ))
    }
}

fn discover_runs_from_source(
    source_base: &Path,
    direct_run: Option<&Path>,
    budget: &mut AnalysisInputBudget,
) -> io::Result<Vec<DiscoveredRun>> {
    let reports_dir = source_base.join("reports");
    let _report_pins = crate::artifact::pin_safe_directory_tree(&reports_dir, false)?;
    let mut reports = Vec::new();
    let mut entries = 0u64;
    for entry in fs::read_dir(&reports_dir).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read {}: {error}", reports_dir.display()),
        )
    })? {
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| invalid_data("report directory entry count overflowed"))?;
        if entries > MAX_DISCOVERY_ENTRIES {
            return Err(invalid_data("report directory contains too many entries"));
        }
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(HOST_REPORT_GLOB_PREFIX) && name.ends_with(".json")
                })
        {
            if reports.len() as u64 >= MAX_DISCOVERY_REPORTS {
                return Err(invalid_data(
                    "report directory contains too many matching reports",
                ));
            }
            reports.push(path);
        }
    }
    reports.sort();

    let mut matches = Vec::new();
    for report in reports {
        let value = match read_json(
            &report,
            "host report candidate",
            MAX_HOST_REPORT_BYTES,
            budget,
        ) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(run_id) = string_at(&value, &["backend_metadata", "run_id"]) else {
            continue;
        };
        if !valid_run_id(run_id) {
            continue;
        }
        let run_directory = source_base.join("hyperv").join("runs").join(run_id);
        if crate::artifact::pin_safe_directory_tree(&run_directory, false).is_ok()
            && direct_run.is_none_or(|expected| expected == run_directory)
        {
            let report_name = report
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<unknown report>".to_string());
            let target_name = string_at(&value, &["target", "path"])
                .filter(|name| !name.is_empty())
                .unwrap_or("<unknown target>")
                .to_string();
            let generated_at_unix_ms = parse_u64(value.get("generated_at_unix_ms")).unwrap_or(0);
            matches.push(DiscoveredRun {
                report_path: report,
                run_directory,
                report_name,
                target_name,
                generated_at_unix_ms,
            });
        }
    }
    sort_runs_newest_first(&mut matches);
    Ok(matches)
}

fn sort_runs_newest_first(runs: &mut [DiscoveredRun]) {
    runs.sort_by(|left, right| {
        right
            .generated_at_unix_ms
            .cmp(&left.generated_at_unix_ms)
            .then_with(|| left.report_name.cmp(&right.report_name))
    });
}

fn read_json(
    path: &Path,
    description: &str,
    maximum_bytes: u64,
    budget: &mut AnalysisInputBudget,
) -> io::Result<Value> {
    let file = crate::artifact::open_safe_regular_file(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("open {description} {}: {error}", path.display()),
        )
    })?;
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("read {description} {}: {error}", path.display()),
            )
        })?;
    budget.charge(bytes.len() as u64)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(invalid_data(format!(
            "{description} {} exceeds the {} byte input limit",
            path.display(),
            maximum_bytes
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("parse {description} {}: {error}", path.display())))
}

fn load_event_array(
    path: &Path,
    fallback: Option<&Value>,
    kind: &str,
    source_base: &Path,
    warnings: &mut Vec<ValidationWarning>,
    source_paths: &mut Vec<String>,
    budget: &mut AnalysisInputBudget,
) -> io::Result<Vec<Value>> {
    if crate::artifact::open_safe_regular_file(path).is_ok() {
        source_paths.push(display_relative(source_base, path));
        return match read_json(
            path,
            &format!("{kind} events"),
            MAX_EVENT_JSON_BYTES,
            budget,
        ) {
            Ok(value) if value.is_array() => Ok(value.as_array().cloned().unwrap_or_default()),
            Ok(value) => {
                warnings.push(ValidationWarning {
                    code: format!("malformed_{kind}_artifact"),
                    source: display_relative(source_base, path),
                    event_index: None,
                    message: format!(
                        "{kind} event artifact is not an array; using the guest result fallback"
                    ),
                    raw: Some(value),
                });
                Ok(fallback
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default())
            }
            Err(error) => {
                warnings.push(ValidationWarning {
                    code: format!("malformed_{kind}_artifact"),
                    source: display_relative(source_base, path),
                    event_index: None,
                    message: format!(
                        "{kind} event artifact could not be parsed ({error}); using the guest result fallback"
                    ),
                    raw: None,
                });
                Ok(fallback
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default())
            }
        };
    }
    let source = display_relative(source_base, path);
    warnings.push(ValidationWarning {
        code: "missing_event_artifact".to_string(),
        source,
        event_index: None,
        message: format!("{kind} event artifact is missing; using the guest result fallback"),
        raw: None,
    });
    Ok(fallback
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

fn normalize_processes(
    values: &[Value],
    source: &str,
    warnings: &mut Vec<ValidationWarning>,
) -> (Vec<Process>, usize) {
    let mut grouped: BTreeMap<u32, Vec<ProcessObservation>> = BTreeMap::new();
    let mut normalized_count = 0;
    for (index, raw) in values.iter().enumerate() {
        let Some(object) = raw.as_object() else {
            malformed(
                warnings,
                "process",
                source,
                index,
                "event is not an object",
                raw,
            );
            continue;
        };
        let Some(pid) = parse_u32(object.get("pid")) else {
            malformed(
                warnings,
                "process",
                source,
                index,
                "pid is missing or invalid",
                raw,
            );
            continue;
        };
        let Some(observed_at_ms) = parse_u64(object.get("observed_at_ms")) else {
            malformed(
                warnings,
                "process",
                source,
                index,
                "observed_at_ms is missing or invalid",
                raw,
            );
            continue;
        };
        let Some(encoded_image) = object
            .get("image")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        else {
            malformed(
                warnings,
                "process",
                source,
                index,
                "image is missing or invalid",
                raw,
            );
            continue;
        };
        let (image, command_line, status) = split_process_image(encoded_image);
        let parsed_parent_pid = parse_u32(object.get("parent_pid"));
        if !object.contains_key("parent_pid")
            || (object
                .get("parent_pid")
                .is_some_and(|value| !value.is_null())
                && parsed_parent_pid.is_none())
        {
            warnings.push(ValidationWarning {
                code: "invalid_process_parent_pid".to_string(),
                source: source.to_string(),
                event_index: Some(index),
                message: "parent_pid is missing or invalid; the process observation was retained without a parent".to_string(),
                raw: Some(raw.clone()),
            });
        }
        let parent_pid = parsed_parent_pid.filter(|pid| *pid != 0);
        grouped.entry(pid).or_default().push(ProcessObservation {
            evidence_id: format!("process:{index}"),
            pid,
            parent_pid,
            image,
            command_line,
            status,
            observed_at_ms,
            source: source.to_string(),
            raw: raw.clone(),
        });
        normalized_count += 1;
    }

    let processes = grouped
        .into_iter()
        .map(|(pid, mut observations)| {
            observations.sort_by(|left, right| {
                left.observed_at_ms
                    .cmp(&right.observed_at_ms)
                    .then_with(|| left.evidence_id.cmp(&right.evidence_id))
            });
            let representative = observations
                .iter()
                .find(|observation| {
                    observation.status != "terminated" && observation.command_line.is_some()
                })
                .or_else(|| {
                    observations
                        .iter()
                        .find(|observation| observation.status != "terminated")
                })
                .unwrap_or(&observations[0]);
            let parent_pid = observations
                .iter()
                .find_map(|observation| observation.parent_pid);
            let status = if observations
                .iter()
                .any(|observation| observation.status == "terminated")
            {
                "terminated"
            } else {
                representative.status.as_str()
            };
            let observed_at_ms = observations
                .iter()
                .map(|observation| observation.observed_at_ms)
                .min()
                .unwrap_or(0);
            let raw = Value::Array(
                observations
                    .iter()
                    .map(|observation| observation.raw.clone())
                    .collect(),
            );
            Process {
                pid,
                parent_pid,
                image: representative.image.clone(),
                command_line: representative.command_line.clone(),
                status: status.to_string(),
                observed_at_ms,
                observations,
                raw,
            }
        })
        .collect();
    (processes, normalized_count)
}

fn normalize_files(
    values: &[Value],
    source: &str,
    processes: &[Process],
    root_pid: u32,
    warnings: &mut Vec<ValidationWarning>,
) -> (Vec<FileEvent>, usize) {
    let mut output = Vec::new();
    for (index, raw) in values.iter().enumerate() {
        let Some(object) = raw.as_object() else {
            malformed(
                warnings,
                "filesystem",
                source,
                index,
                "event is not an object",
                raw,
            );
            continue;
        };
        let path = object
            .get("path")
            .or_else(|| object.get("relative_path"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let action = object
            .get("action")
            .or_else(|| object.get("kind"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let Some(observed_at_ms) = parse_u64(object.get("observed_at_ms")) else {
            malformed(
                warnings,
                "filesystem",
                source,
                index,
                "observed_at_ms is missing or invalid",
                raw,
            );
            continue;
        };
        let (Some(path), Some(action)) = (path, action) else {
            malformed(
                warnings,
                "filesystem",
                source,
                index,
                "path or action is missing",
                raw,
            );
            continue;
        };
        let explicit_pid = parse_u32(object.get("pid"));
        warn_invalid_optional_pid(object, raw, "filesystem", source, index, warnings);
        let size_bytes = object
            .get("size_bytes")
            .and_then(|value| parse_u64(Some(value)));
        if size_bytes.is_none() {
            warnings.push(ValidationWarning {
                code: "invalid_filesystem_size".to_string(),
                source: source.to_string(),
                event_index: Some(index),
                message:
                    "size_bytes is missing or invalid; the event was retained with a null size"
                        .to_string(),
                raw: Some(raw.clone()),
            });
        }
        let raw_sha256 = object.get("sha256").and_then(Value::as_str);
        let sha256 = raw_sha256
            .filter(|value| valid_hash(value, 64))
            .map(str::to_ascii_lowercase);
        if raw_sha256.is_some() && sha256.is_none() {
            warnings.push(ValidationWarning {
                code: "invalid_filesystem_sha256".to_string(),
                source: source.to_string(),
                event_index: Some(index),
                message: "sha256 is invalid; the file event was retained without a digest"
                    .to_string(),
                raw: Some(raw.clone()),
            });
        }
        let hash_source = sha256.as_ref().and_then(|_| {
            object
                .get("hash_source")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .map(str::to_string)
        });
        let association = associate_process(explicit_pid, observed_at_ms, processes, root_pid);
        output.push(FileEvent {
            evidence_id: format!("file:{index}"),
            pid: association.pid,
            path: path.to_string(),
            action: action.to_string(),
            size_bytes,
            sha256,
            hash_source,
            observed_at_ms,
            source: source.to_string(),
            association,
            raw: raw.clone(),
        });
    }
    let count = output.len();
    (output, count)
}

fn normalize_registry(
    values: &[Value],
    source: &str,
    processes: &[Process],
    root_pid: u32,
    warnings: &mut Vec<ValidationWarning>,
) -> (Vec<RegistryEvent>, usize) {
    let mut output = Vec::new();
    for (index, raw) in values.iter().enumerate() {
        let Some(object) = raw.as_object() else {
            malformed(
                warnings,
                "registry",
                source,
                index,
                "event is not an object",
                raw,
            );
            continue;
        };
        let key = object
            .get("key")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let Some(observed_at_ms) = parse_u64(object.get("observed_at_ms")) else {
            malformed(
                warnings,
                "registry",
                source,
                index,
                "observed_at_ms is missing or invalid",
                raw,
            );
            continue;
        };
        let (Some(key), Some(operation)) = (key, operation) else {
            malformed(
                warnings,
                "registry",
                source,
                index,
                "key or operation is missing",
                raw,
            );
            continue;
        };
        let explicit_pid = parse_u32(object.get("pid"));
        warn_invalid_optional_pid(object, raw, "registry", source, index, warnings);
        let association = associate_process(explicit_pid, observed_at_ms, processes, root_pid);
        let value_data = object
            .get("value_data")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                operation
                    .split_once(" data=")
                    .map(|(_, data)| data.to_string())
            });
        output.push(RegistryEvent {
            evidence_id: format!("registry:{index}"),
            pid: association.pid,
            key: key.to_string(),
            operation: operation.to_string(),
            value_name: object
                .get("value_name")
                .and_then(Value::as_str)
                .map(str::to_string),
            value_data,
            observed_at_ms,
            source: source.to_string(),
            association,
            raw: raw.clone(),
        });
    }
    let count = output.len();
    (output, count)
}

fn normalize_network(
    values: &[Value],
    source: &str,
    processes: &[Process],
    root_pid: u32,
    warnings: &mut Vec<ValidationWarning>,
) -> (Vec<NetworkEvent>, usize) {
    let mut output = Vec::new();
    for (index, raw) in values.iter().enumerate() {
        let Some(object) = raw.as_object() else {
            malformed(
                warnings,
                "network",
                source,
                index,
                "event is not an object",
                raw,
            );
            continue;
        };
        let protocol = object
            .get("protocol")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let state = object
            .get("state")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let Some(observed_at_ms) = parse_u64(object.get("observed_at_ms")) else {
            malformed(
                warnings,
                "network",
                source,
                index,
                "observed_at_ms is missing or invalid",
                raw,
            );
            continue;
        };
        let (Some(protocol), Some(state)) = (protocol, state) else {
            malformed(
                warnings,
                "network",
                source,
                index,
                "protocol or state is missing",
                raw,
            );
            continue;
        };
        let explicit_pid = parse_u32(object.get("pid"));
        if object.contains_key("pid") && explicit_pid.is_none() {
            malformed(warnings, "network", source, index, "pid is invalid", raw);
            continue;
        }
        let association = associate_process(explicit_pid, observed_at_ms, processes, root_pid);
        let mut remote_address = object
            .get("remote_address")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let domain = if protocol.eq_ignore_ascii_case("dns") && !remote_address.is_empty() {
            let domain = remote_address.clone();
            remote_address.clear();
            Some(domain)
        } else {
            object
                .get("domain")
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        output.push(NetworkEvent {
            evidence_id: format!("network:{index}"),
            pid: association.pid,
            protocol: protocol.to_ascii_lowercase(),
            direction: object
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            local_address: object
                .get("local_address")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            local_port: parse_u16(object.get("local_port")),
            remote_address,
            remote_port: parse_u16(object.get("remote_port")),
            domain,
            state: state.to_string(),
            observed_at_ms,
            source: source.to_string(),
            association,
            raw: raw.clone(),
        });
    }
    let count = output.len();
    (output, count)
}

fn normalize_artifacts(
    value: Option<&Value>,
    guest_output: &Path,
    source: &str,
    warnings: &mut Vec<ValidationWarning>,
    budget: &mut AnalysisInputBudget,
) -> io::Result<Vec<Artifact>> {
    let Some(values) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if values.len() as u64 > MAX_ANALYSIS_INPUT_FILES {
        return Err(invalid_data(format!(
            "artifact manifest exceeds the {} entry analysis limit",
            MAX_ANALYSIS_INPUT_FILES
        )));
    }
    let mut output = Vec::new();
    let mut verified_paths = BTreeMap::<String, Option<(u64, String)>>::new();
    for (index, raw) in values.iter().enumerate() {
        let Some(object) = raw.as_object() else {
            malformed(
                warnings,
                "artifact",
                source,
                index,
                "artifact is not an object",
                raw,
            );
            continue;
        };
        let Some(relative_path) = object.get("relative_path").and_then(Value::as_str) else {
            malformed(
                warnings,
                "artifact",
                source,
                index,
                "relative_path is missing",
                raw,
            );
            continue;
        };
        let Some(size_bytes) = parse_u64(object.get("size_bytes")) else {
            malformed(
                warnings,
                "artifact",
                source,
                index,
                "size_bytes is missing or invalid",
                raw,
            );
            continue;
        };
        let Some(sha256) = object
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|value| valid_hash(value, 64))
        else {
            malformed(
                warnings,
                "artifact",
                source,
                index,
                "sha256 is missing or invalid",
                raw,
            );
            continue;
        };
        let safe = safe_relative_path(relative_path);
        let path = guest_output.join(relative_path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let path_key = relative_path.replace('\\', "/").to_ascii_lowercase();
        let actual = if !safe || size_bytes > MAX_ANALYSIS_ARTIFACT_BYTES {
            None
        } else if let Some(cached) = verified_paths.get(&path_key) {
            cached.clone()
        } else {
            let verified = match sha256_file(&path, MAX_ANALYSIS_ARTIFACT_BYTES, budget) {
                Ok(actual) => Some(actual),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            verified_paths.insert(path_key, verified.clone());
            verified
        };
        let exists = actual.is_some();
        let actual_size = actual.as_ref().map(|(size, _)| *size);
        let actual_hash = actual.as_ref().map(|(_, hash)| hash.as_str());
        let hash_verified = actual_size == Some(size_bytes)
            && actual_hash.is_some_and(|actual| actual.eq_ignore_ascii_case(sha256));
        if !exists {
            warnings.push(ValidationWarning {
                code: "missing_artifact".to_string(),
                source: source.to_string(),
                event_index: Some(index),
                message: format!("referenced artifact does not exist at {relative_path}"),
                raw: Some(raw.clone()),
            });
        } else if !hash_verified {
            warnings.push(ValidationWarning {
                code: "artifact_verification_failed".to_string(),
                source: source.to_string(),
                event_index: Some(index),
                message: format!(
                    "artifact size or SHA-256 does not match its manifest entry: {relative_path}"
                ),
                raw: Some(raw.clone()),
            });
        }
        output.push(Artifact {
            evidence_id: format!("artifact:{index}"),
            relative_path: relative_path.to_string(),
            kind: object
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            size_bytes,
            sha256: sha256.to_ascii_lowercase(),
            exists,
            hash_verified,
            source: source.to_string(),
            raw: raw.clone(),
        });
    }
    output.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(output)
}

fn extract_target_hashes(
    target: &Value,
    host: &Value,
    guest: &Value,
    execution: &Value,
) -> Vec<HashIndicator> {
    let mut output = Vec::new();
    for (field, algorithm, length) in [
        ("sha256", "sha256", 64),
        ("sha1", "sha1", 40),
        ("md5", "md5", 32),
    ] {
        push_target_hash(
            &mut output,
            "host_report.target",
            target,
            field,
            algorithm,
            length,
        );
    }
    for (source, value) in [
        ("host_report", host),
        ("guest_result", guest),
        ("guest_result.execution", execution),
    ] {
        for (field, algorithm, length) in [
            ("target_sha256", "sha256", 64),
            ("target_sha1", "sha1", 40),
            ("target_md5", "md5", 32),
        ] {
            push_target_hash(&mut output, source, value, field, algorithm, length);
        }
    }
    output.sort_by(|left, right| {
        left.algorithm
            .cmp(&right.algorithm)
            .then_with(|| left.value.cmp(&right.value))
    });
    output.dedup_by(|left, right| left.algorithm == right.algorithm && left.value == right.value);
    output
}

fn push_target_hash(
    output: &mut Vec<HashIndicator>,
    source: &str,
    value: &Value,
    field: &str,
    algorithm: &str,
    length: usize,
) {
    if let Some(hash) = value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value, length))
    {
        output.push(HashIndicator {
            algorithm: algorithm.to_string(),
            value: hash.to_ascii_lowercase(),
            source: source.to_string(),
        });
    }
}

fn collect_limitations(
    host: &Map<String, Value>,
    guest: &Map<String, Value>,
    execution: &Value,
    coverage: &Value,
) -> Vec<String> {
    let mut output = Vec::new();
    append_strings(&mut output, host.get("limitations"));
    append_strings(&mut output, guest.get("warnings"));
    append_strings(&mut output, execution.get("monitor_warnings"));
    if let Some(object) = coverage.as_object() {
        for value in object.values() {
            append_strings(&mut output, value.get("warnings"));
        }
    }
    let mut seen = BTreeSet::new();
    output.retain(|value| seen.insert(value.clone()));
    output
}

fn append_strings(output: &mut Vec<String>, value: Option<&Value>) {
    if let Some(values) = value.and_then(Value::as_array) {
        output.extend(values.iter().filter_map(Value::as_str).map(str::to_string));
    }
}

fn associate_process(
    explicit_pid: Option<u32>,
    observed_at_ms: u64,
    processes: &[Process],
    root_pid: u32,
) -> ProcessAssociation {
    if let Some(pid) = explicit_pid {
        return association_for_pid(pid, false, "explicit_pid", processes);
    }
    let nearest = processes
        .iter()
        .filter(|process| process_contains(process, observed_at_ms))
        .map(|process| {
            let distance = process
                .observations
                .iter()
                .map(|observation| observation.observed_at_ms.abs_diff(observed_at_ms))
                .min()
                .unwrap_or(u64::MAX);
            (distance, process.pid)
        })
        .min();
    if let Some((_, pid)) = nearest {
        return association_for_pid(pid, true, "nearest_process_lifetime", processes);
    }
    association_for_pid(root_pid, true, "root_target_fallback", processes)
}

fn association_for_pid(
    pid: u32,
    inferred: bool,
    method: &str,
    processes: &[Process],
) -> ProcessAssociation {
    let process = processes.iter().find(|process| process.pid == pid);
    ProcessAssociation {
        pid,
        image: process
            .map(|process| process.image.clone())
            .unwrap_or_else(|| "<unknown>".to_string()),
        parent_pid: process.and_then(|process| process.parent_pid),
        inferred,
        method: method.to_string(),
    }
}

fn process_contains(process: &Process, observed_at_ms: u64) -> bool {
    let start = process
        .observations
        .iter()
        .filter(|observation| observation.status != "terminated")
        .map(|observation| observation.observed_at_ms)
        .min()
        .unwrap_or(process.observed_at_ms);
    let end = process
        .observations
        .iter()
        .filter(|observation| observation.status == "terminated")
        .map(|observation| observation.observed_at_ms)
        .min()
        .unwrap_or(u64::MAX);
    start <= observed_at_ms && observed_at_ms <= end
}

fn split_process_image(value: &str) -> (String, Option<String>, String) {
    if let Some(image) = value.strip_prefix("terminated | ") {
        return (image.to_string(), None, "terminated".to_string());
    }
    if let Some((image, command_line)) = value.split_once(" | ") {
        return (
            image.to_string(),
            (!command_line.is_empty()).then(|| command_line.to_string()),
            "observed".to_string(),
        );
    }
    (value.to_string(), None, "observed".to_string())
}

fn malformed(
    warnings: &mut Vec<ValidationWarning>,
    kind: &str,
    source: &str,
    index: usize,
    message: &str,
    raw: &Value,
) {
    warnings.push(ValidationWarning {
        code: format!("malformed_{kind}_event"),
        source: source.to_string(),
        event_index: Some(index),
        message: message.to_string(),
        raw: Some(raw.clone()),
    });
}

fn warn_invalid_optional_pid(
    object: &Map<String, Value>,
    raw: &Value,
    kind: &str,
    source: &str,
    index: usize,
    warnings: &mut Vec<ValidationWarning>,
) {
    if object.contains_key("pid") && parse_u32(object.get("pid")).is_none() {
        warnings.push(ValidationWarning {
            code: format!("invalid_{kind}_pid"),
            source: source.to_string(),
            event_index: Some(index),
            message: "explicit pid is invalid; the event was retained with an inferred process association"
                .to_string(),
            raw: Some(raw.clone()),
        });
    }
}

fn parse_u64(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn parse_u32(value: Option<&Value>) -> Option<u32> {
    parse_u64(value).and_then(|value| u32::try_from(value).ok())
}

fn parse_u16(value: Option<&Value>) -> Option<u16> {
    parse_u64(value)
        .filter(|value| *value != 0)
        .and_then(|value| u16::try_from(value).ok())
}

fn u32_at(value: &Value, path: &[&str]) -> Option<u32> {
    let mut cursor = value;
    for component in path {
        cursor = cursor.get(*component)?;
    }
    parse_u32(Some(cursor))
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cursor = value;
    for component in path {
        cursor = cursor.get(*component)?;
    }
    cursor.as_str()
}

fn valid_hash(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !value.contains(':')
}

fn valid_run_id(value: &str) -> bool {
    (16..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(
    path: &Path,
    maximum_bytes: u64,
    budget: &mut AnalysisInputBudget,
) -> io::Result<(u64, String)> {
    let mut file = crate::artifact::open_safe_regular_file(path)?;
    let expected_bytes = file.metadata()?.len();
    if expected_bytes > maximum_bytes {
        return Err(invalid_data(format!(
            "artifact exceeds the {maximum_bytes} byte analysis limit"
        )));
    }
    budget.charge(expected_bytes)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid_data("artifact size overflowed while hashing"))?;
        if total > maximum_bytes {
            return Err(invalid_data(format!(
                "artifact exceeds the {maximum_bytes} byte analysis limit"
            )));
        }
        hasher.update(&buffer[..count]);
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

fn source_for_events(source_base: &Path, path: &Path, result_path: &Path) -> String {
    if crate::artifact::open_safe_regular_file(path).is_ok() {
        display_relative(source_base, path)
    } else {
        display_relative(source_base, result_path)
    }
}

fn display_relative(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_process_observations_keep_image_command_line_and_status() {
        assert_eq!(
            split_process_image(r"C:\Windows\cmd.exe | cmd.exe /c test"),
            (
                r"C:\Windows\cmd.exe".to_string(),
                Some("cmd.exe /c test".to_string()),
                "observed".to_string()
            )
        );
        assert_eq!(
            split_process_image(r"terminated | C:\Windows\cmd.exe"),
            (
                r"C:\Windows\cmd.exe".to_string(),
                None,
                "terminated".to_string()
            )
        );
    }

    #[test]
    fn timestamps_accept_integers_and_integer_strings_only() {
        assert_eq!(parse_u64(Some(&Value::from(12))), Some(12));
        assert_eq!(parse_u64(Some(&Value::from("12"))), Some(12));
        assert_eq!(parse_u64(Some(&Value::from("not-a-time"))), None);
        assert_eq!(parse_u64(Some(&Value::from(-1))), None);
    }

    #[test]
    fn file_hashes_are_normalized_and_invalid_digests_are_rejected() {
        let values = vec![
            json!({
                "relative_path": "C:\\Users\\Foxhole\\Downloads\\payload.exe",
                "kind": "executable_create",
                "size_bytes": 123,
                "sha256": "AB".repeat(32),
                "hash_source": "sysmon_event",
                "observed_at_ms": 10
            }),
            json!({
                "relative_path": "C:\\Users\\Foxhole\\Downloads\\bad.exe",
                "kind": "create_or_overwrite",
                "size_bytes": 5,
                "sha256": "bad",
                "observed_at_ms": 11
            }),
        ];
        let mut warnings = Vec::new();
        let (events, count) =
            normalize_files(&values, "filesystem-events.json", &[], 42, &mut warnings);
        assert_eq!(count, 2);
        assert_eq!(events[0].sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(events[0].hash_source.as_deref(), Some("sysmon_event"));
        assert!(events[1].sha256.is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.code == "invalid_filesystem_sha256")
        );
    }

    #[test]
    fn discovered_runs_are_sorted_newest_first() {
        let run = |report_name: &str, generated_at_unix_ms| DiscoveredRun {
            report_path: PathBuf::from(report_name),
            run_directory: PathBuf::from(report_name),
            report_name: report_name.to_string(),
            target_name: "target.exe".to_string(),
            generated_at_unix_ms,
        };
        let mut runs = vec![
            run("fh_old.json", 10),
            run("fh_same_b.json", 20),
            run("fh_latest.json", 30),
            run("fh_same_a.json", 20),
        ];

        sort_runs_newest_first(&mut runs);

        assert_eq!(
            runs.iter()
                .map(|run| run.report_name.as_str())
                .collect::<Vec<_>>(),
            [
                "fh_latest.json",
                "fh_same_a.json",
                "fh_same_b.json",
                "fh_old.json"
            ]
        );
    }

    #[test]
    fn analyzer_input_limits_reject_oversized_json_and_invalid_run_ids() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-analysis-limit-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let oversized = root.join("oversized.json");
        fs::write(&oversized, br#"{"value":1}"#).unwrap();
        let mut budget = AnalysisInputBudget::new();
        let error = read_json(&oversized, "test JSON", 4, &mut budget)
            .expect_err("whole-file reads must stop at the configured bound");
        assert!(error.to_string().contains("input limit"));

        assert!(valid_run_id("0123456789abcdef"));
        for invalid in [
            "short",
            "../0123456789abcdef",
            r"C:\0123456789abcdef",
            "gggggggggggggggg",
        ] {
            assert!(!valid_run_id(invalid));
        }
        assert!(
            budget.charge(MAX_ANALYSIS_TOTAL_INPUT_BYTES + 1).is_err(),
            "aggregate bytes must also be bounded"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_manifest_is_bounded_and_duplicate_paths_are_hashed_once() {
        let excessive = Value::Array(vec![json!({}); MAX_ANALYSIS_INPUT_FILES as usize + 1]);
        let mut warnings = Vec::new();
        let mut budget = AnalysisInputBudget::new();
        assert!(
            normalize_artifacts(
                Some(&excessive),
                Path::new("unused"),
                "result.json",
                &mut warnings,
                &mut budget,
            )
            .is_err()
        );

        let root = std::env::temp_dir().join(format!(
            "foxhole-analysis-artifact-budget-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("sample.bin"), b"abc").unwrap();
        let entry = json!({
            "relative_path": "sample.bin",
            "kind": "sample",
            "size_bytes": 3,
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        });
        let manifest = Value::Array(vec![entry.clone(), entry]);
        let mut warnings = Vec::new();
        let mut budget = AnalysisInputBudget::new();
        let artifacts = normalize_artifacts(
            Some(&manifest),
            &root,
            "result.json",
            &mut warnings,
            &mut budget,
        )
        .unwrap();
        assert_eq!(artifacts.len(), 2);
        assert_eq!(budget.files, 1);
        assert_eq!(budget.bytes, 3);
        assert!(artifacts.iter().all(|artifact| artifact.hash_verified));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_events_warn_while_duplicates_and_unknown_fields_survive() {
        let values = vec![
            json!({
                "pid": 7,
                "parent_pid": 1,
                "image": "sample.exe | sample.exe --test",
                "observed_at_ms": 10,
                "future_field": {"kept": true}
            }),
            json!({
                "pid": 7,
                "parent_pid": 1,
                "image": "sample.exe | sample.exe --test",
                "observed_at_ms": 10,
                "future_field": {"kept": true}
            }),
            json!({"pid": 8, "image": "bad.exe", "observed_at_ms": "bad"}),
            json!({"image": "missing-pid.exe", "observed_at_ms": 12}),
        ];
        let mut warnings = Vec::new();
        let (processes, count) = normalize_processes(&values, "process-events.json", &mut warnings);
        assert_eq!(count, 2);
        assert_eq!(warnings.len(), 2);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].observations.len(), 2);
        assert_eq!(
            processes[0].observations[0].raw["future_field"]["kept"],
            true
        );
        assert!(warnings.iter().all(|warning| warning.raw.is_some()));
    }

    #[test]
    fn association_order_is_explicit_then_nearest_lifetime_then_root() {
        let values = vec![
            json!({"pid": 10, "parent_pid": 1, "image": "root.exe", "observed_at_ms": 0}),
            json!({"pid": 20, "parent_pid": 10, "image": "child.exe", "observed_at_ms": 90}),
            json!({"pid": 20, "parent_pid": 0, "image": "terminated | child.exe", "observed_at_ms": 110}),
            json!({"pid": 10, "parent_pid": 0, "image": "terminated | root.exe", "observed_at_ms": 200}),
        ];
        let (processes, _) = normalize_processes(&values, "process-events.json", &mut Vec::new());
        let explicit = associate_process(Some(20), 50, &processes, 10);
        assert_eq!(
            (explicit.pid, explicit.inferred, explicit.method.as_str()),
            (20, false, "explicit_pid")
        );
        let nearest = associate_process(None, 100, &processes, 10);
        assert_eq!(
            (nearest.pid, nearest.inferred, nearest.method.as_str()),
            (20, true, "nearest_process_lifetime")
        );
        let fallback = associate_process(None, 500, &processes, 10);
        assert_eq!(
            (fallback.pid, fallback.inferred, fallback.method.as_str()),
            (10, true, "root_target_fallback")
        );
    }
}
