use super::model::*;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct VerdictConfig {
    pub mass_file_threshold: usize,
    pub mass_file_window_ms: u64,
    pub mass_file_malicious_multiplier: usize,
}

impl Default for VerdictConfig {
    fn default() -> Self {
        Self {
            mass_file_threshold: 100,
            mass_file_window_ms: 10_000,
            mass_file_malicious_multiplier: 5,
        }
    }
}

pub fn build_verdict(
    run: &NormalizedRun,
    normalized_hash: &str,
    config: &VerdictConfig,
) -> VerdictReport {
    let mut findings = Vec::new();
    network_findings(run, &mut findings);
    child_process_finding(run, &mut findings);
    ads_finding(run, &mut findings);
    registry_autostart_finding(run, &mut findings);
    script_interpreter_network_finding(run, &mut findings);
    explicit_process_injection_finding(run, &mut findings);
    credential_access_finding(run, &mut findings);
    mass_file_finding(run, config, &mut findings);

    findings.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    let score = findings
        .iter()
        .map(|finding| finding.score_contribution)
        .sum::<u32>();
    let verdict = if findings
        .iter()
        .any(|finding| finding.severity == Severity::Malicious)
        || score >= 60
    {
        "malicious"
    } else if score >= 20 {
        "suspicious"
    } else if findings.is_empty() {
        "benign"
    } else {
        "informational"
    };
    let confidence = overall_confidence(run, &findings);
    let mut scoring_model = BTreeMap::new();
    scoring_model.insert("informational_points".to_string(), json!(0));
    scoring_model.insert("suspicious_points".to_string(), json!(30));
    scoring_model.insert("malicious_points".to_string(), json!(70));
    scoring_model.insert("suspicious_range".to_string(), json!([20, 59]));
    scoring_model.insert("malicious_minimum".to_string(), json!(60));
    scoring_model.insert(
        "calculation".to_string(),
        json!("sum one contribution per triggered rule; an explicit malicious rule is always malicious"),
    );

    VerdictReport {
        schema_version: VERDICT_SCHEMA_VERSION.to_string(),
        run_id: run.run_id.clone(),
        normalized_input_sha256: normalized_hash.to_string(),
        verdict: verdict.to_string(),
        score,
        confidence,
        scoring_model,
        findings,
        timeline: build_timeline(run),
        warnings: run.validation_warnings.clone(),
    }
}

fn network_findings(run: &NormalizedRun, findings: &mut Vec<Finding>) {
    let dns = run
        .network_events
        .iter()
        .filter(|event| event.protocol == "dns")
        .map(network_evidence)
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "network_dns_request",
        Severity::Informational,
        "DNS request observed",
        "The target process tree issued one or more DNS requests. DNS activity alone is not evidence of compromise.",
        dns,
        0.92,
    );

    let blocked = run
        .network_events
        .iter()
        .filter(|event| {
            let state = event.state.to_ascii_lowercase();
            state.contains("block")
                || state.contains("deny")
                || state.contains("unreachable")
                || state.contains("failed")
                || (state.contains("attempt")
                    && (state.contains("results=-") || state.contains("status=")))
        })
        .map(network_evidence)
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "blocked_outbound_connection",
        Severity::Informational,
        "Outbound connection was blocked or failed",
        "A network attempt did not complete successfully. This finding does not represent a successful connection or compromise.",
        blocked,
        0.88,
    );
}

fn child_process_finding(run: &NormalizedRun, findings: &mut Vec<Finding>) {
    let known = run
        .processes
        .iter()
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();
    let evidence = run
        .processes
        .iter()
        .filter(|process| process.parent_pid.is_some_and(|pid| known.contains(&pid)))
        .filter_map(|process| {
            process
                .observations
                .iter()
                .find(|observation| observation.status != "terminated")
                .map(process_evidence)
        })
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "child_process_created",
        Severity::Informational,
        "Child process created",
        "The target process tree created one or more child processes. Process creation alone is not malicious.",
        evidence,
        0.96,
    );
}

fn ads_finding(run: &NormalizedRun, findings: &mut Vec<Finding>) {
    let evidence = run
        .file_events
        .iter()
        .filter(|event| {
            event
                .action
                .to_ascii_lowercase()
                .contains("alternate_stream")
                || has_alternate_stream(&event.path)
        })
        .map(file_evidence)
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "ntfs_alternate_data_stream",
        Severity::Suspicious,
        "NTFS alternate data stream observed",
        "A file operation referenced an NTFS alternate data stream. Alternate streams can be legitimate, but are also used to conceal content.",
        evidence,
        0.90,
    );
}

fn registry_autostart_finding(run: &NormalizedRun, findings: &mut Vec<Finding>) {
    let evidence = run
        .registry_events
        .iter()
        .filter(|event| is_registry_write(&event.operation) && is_autostart_key(event))
        .map(registry_evidence)
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "suspicious_registry_autostart",
        Severity::Suspicious,
        "Registry autostart persistence write",
        "A write targeted a known Run/RunOnce or service persistence value.",
        evidence,
        0.91,
    );
}

fn script_interpreter_network_finding(run: &NormalizedRun, findings: &mut Vec<Finding>) {
    let interpreters = run
        .processes
        .iter()
        .filter(|process| is_script_interpreter(&process.image))
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();
    let evidence = run
        .network_events
        .iter()
        .filter(|event| interpreters.contains(&event.pid))
        .map(network_evidence)
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "script_interpreter_network",
        Severity::Suspicious,
        "Script interpreter initiated network activity",
        "A script interpreter process directly initiated network activity.",
        evidence,
        0.86,
    );
}

fn explicit_process_injection_finding(run: &NormalizedRun, findings: &mut Vec<Finding>) {
    let evidence = run
        .processes
        .iter()
        .flat_map(|process| process.observations.iter())
        .filter(|observation| raw_explicitly_names(&observation.raw, "process_injection"))
        .map(process_evidence)
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "process_injection",
        Severity::Malicious,
        "Explicit process injection observed",
        "Telemetry explicitly recorded a process injection event; this rule never fires from indirect behavioral inference.",
        evidence,
        0.99,
    );
}

fn credential_access_finding(run: &NormalizedRun, findings: &mut Vec<Finding>) {
    let evidence = run
        .registry_events
        .iter()
        .filter(|event| {
            let operation = event.operation.to_ascii_lowercase();
            let key = normalize_registry_key(&event.key);
            (operation.contains("read")
                || operation.contains("query")
                || operation.contains("open"))
                && (key.starts_with("hklm\\sam")
                    || key.starts_with("hklm\\security\\policy\\secrets")
                    || key.contains("\\credentials"))
        })
        .map(registry_evidence)
        .collect::<Vec<_>>();
    add_finding(
        findings,
        "credential_store_access",
        Severity::Suspicious,
        "Credential store access observed",
        "Telemetry explicitly recorded a read or query against a known credential store location.",
        evidence,
        0.89,
    );
}

fn mass_file_finding(run: &NormalizedRun, config: &VerdictConfig, findings: &mut Vec<Finding>) {
    if config.mass_file_threshold == 0 || run.file_events.len() < config.mass_file_threshold {
        return;
    }
    let mut events = run.file_events.iter().collect::<Vec<_>>();
    events.sort_by_key(|event| event.observed_at_ms);
    let mut best: &[&FileEvent] = &[];
    let mut start = 0;
    for end in 0..events.len() {
        while events[end]
            .observed_at_ms
            .saturating_sub(events[start].observed_at_ms)
            > config.mass_file_window_ms
        {
            start += 1;
        }
        let window = &events[start..=end];
        if window.len() > best.len() {
            best = window;
        }
    }
    if best.len() < config.mass_file_threshold {
        return;
    }
    let malicious_threshold = config
        .mass_file_threshold
        .saturating_mul(config.mass_file_malicious_multiplier.max(1));
    let severity = if best.len() >= malicious_threshold {
        Severity::Malicious
    } else {
        Severity::Suspicious
    };
    add_finding(
        findings,
        "mass_file_modification",
        severity,
        "Mass file modification observed",
        "The configured number of file changes occurred inside the configured short time window.",
        best.iter().map(|event| file_evidence(event)).collect(),
        0.94,
    );
}

fn add_finding(
    findings: &mut Vec<Finding>,
    rule_id: &str,
    severity: Severity,
    title: &str,
    explanation: &str,
    mut evidence: Vec<EvidenceReference>,
    confidence: f64,
) {
    if evidence.is_empty() {
        return;
    }
    evidence.sort_by(|left, right| {
        left.observed_at_ms
            .cmp(&right.observed_at_ms)
            .then_with(|| left.evidence_id.cmp(&right.evidence_id))
    });
    evidence.dedup_by(|left, right| left.evidence_id == right.evidence_id);
    findings.push(Finding {
        rule_id: rule_id.to_string(),
        severity,
        title: title.to_string(),
        explanation: explanation.to_string(),
        evidence,
        confidence,
        score_contribution: severity_points(severity),
    });
}

fn severity_points(severity: Severity) -> u32 {
    match severity {
        Severity::Informational => 0,
        Severity::Suspicious => 30,
        Severity::Malicious => 70,
    }
}

fn build_timeline(run: &NormalizedRun) -> Vec<TimelineEvent> {
    let mut timeline = Vec::new();
    for observation in run
        .processes
        .iter()
        .flat_map(|process| &process.observations)
    {
        let evidence = process_evidence(observation);
        timeline.push(timeline_from_evidence("process", evidence));
    }
    for event in &run.file_events {
        timeline.push(timeline_from_evidence("file", file_evidence(event)));
    }
    for event in &run.registry_events {
        timeline.push(timeline_from_evidence("registry", registry_evidence(event)));
    }
    for event in &run.network_events {
        timeline.push(timeline_from_evidence("network", network_evidence(event)));
    }
    timeline.sort_by(|left, right| {
        left.observed_at_ms
            .cmp(&right.observed_at_ms)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.evidence_id.cmp(&right.evidence_id))
    });
    timeline
}

fn timeline_from_evidence(kind: &str, evidence: EvidenceReference) -> TimelineEvent {
    TimelineEvent {
        observed_at_ms: evidence.observed_at_ms,
        kind: kind.to_string(),
        evidence_id: evidence.evidence_id,
        pid: evidence.pid,
        process_image: evidence.process_image,
        parent_pid: evidence.parent_pid,
        source_artifact: evidence.source_artifact,
        exact_value: evidence.exact_value,
        inferred: evidence.inferred,
    }
}

fn process_evidence(observation: &ProcessObservation) -> EvidenceReference {
    EvidenceReference {
        evidence_id: observation.evidence_id.clone(),
        kind: "process_observation".to_string(),
        pid: observation.pid,
        process_image: observation.image.clone(),
        parent_pid: observation.parent_pid,
        observed_at_ms: observation.observed_at_ms,
        source_artifact: observation.source.clone(),
        exact_value: observation
            .command_line
            .clone()
            .unwrap_or_else(|| observation.image.clone()),
        inferred: false,
    }
}

fn file_evidence(event: &FileEvent) -> EvidenceReference {
    EvidenceReference {
        evidence_id: event.evidence_id.clone(),
        kind: "file_event".to_string(),
        pid: event.pid,
        process_image: event.association.image.clone(),
        parent_pid: event.association.parent_pid,
        observed_at_ms: event.observed_at_ms,
        source_artifact: event.source.clone(),
        exact_value: format!("{} {}", event.action, event.path),
        inferred: event.association.inferred,
    }
}

fn registry_evidence(event: &RegistryEvent) -> EvidenceReference {
    EvidenceReference {
        evidence_id: event.evidence_id.clone(),
        kind: "registry_event".to_string(),
        pid: event.pid,
        process_image: event.association.image.clone(),
        parent_pid: event.association.parent_pid,
        observed_at_ms: event.observed_at_ms,
        source_artifact: event.source.clone(),
        exact_value: format!("{} {}", event.operation, event.key),
        inferred: event.association.inferred,
    }
}

fn network_evidence(event: &NetworkEvent) -> EvidenceReference {
    let remote = event.domain.as_deref().unwrap_or(&event.remote_address);
    EvidenceReference {
        evidence_id: event.evidence_id.clone(),
        kind: "network_event".to_string(),
        pid: event.pid,
        process_image: event.association.image.clone(),
        parent_pid: event.association.parent_pid,
        observed_at_ms: event.observed_at_ms,
        source_artifact: event.source.clone(),
        exact_value: format!(
            "{} {}:{} -> {}:{} {}",
            event.protocol,
            event.local_address,
            event.local_port.unwrap_or(0),
            remote,
            event.remote_port.unwrap_or(0),
            event.state
        ),
        inferred: event.association.inferred,
    }
}

fn has_alternate_stream(path: &str) -> bool {
    let normalized = path.replace('/', "\\");
    let start = if normalized.as_bytes().get(1) == Some(&b':') {
        2
    } else {
        0
    };
    normalized[start..].contains(':')
}

fn is_registry_write(operation: &str) -> bool {
    let operation = operation.to_ascii_lowercase();
    ["set", "write", "create", "add", "update"]
        .iter()
        .any(|needle| operation.contains(needle))
}

fn is_autostart_key(event: &RegistryEvent) -> bool {
    let key = normalize_registry_key(&event.key);
    if key.contains("\\software\\microsoft\\windows\\currentversion\\run\\")
        || key.ends_with("\\software\\microsoft\\windows\\currentversion\\run")
        || key.contains("\\software\\microsoft\\windows\\currentversion\\runonce\\")
        || key.ends_with("\\software\\microsoft\\windows\\currentversion\\runonce")
    {
        return true;
    }
    if !key.contains("\\system\\currentcontrolset\\services\\") {
        return false;
    }
    let value_name = event
        .value_name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["imagepath", "serviceDll", "start"]
        .iter()
        .any(|candidate| value_name.eq_ignore_ascii_case(candidate))
        || key.ends_with("\\imagepath")
        || key.ends_with("\\servicedll")
        || key.ends_with("\\start")
}

fn normalize_registry_key(value: &str) -> String {
    value
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn is_script_interpreter(image: &str) -> bool {
    let image = image.replace('/', "\\").to_ascii_lowercase();
    let name = image.rsplit('\\').next().unwrap_or(&image);
    matches!(
        name,
        "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "python.exe"
            | "python3.exe"
            | "bash.exe"
            | "sh.exe"
    )
}

fn raw_explicitly_names(value: &Value, expected: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    ["event_type", "event", "kind", "action", "operation"]
        .iter()
        .filter_map(|key| object.get(*key).and_then(Value::as_str))
        .any(|value| value.eq_ignore_ascii_case(expected))
}

fn overall_confidence(run: &NormalizedRun, findings: &[Finding]) -> f64 {
    let base = if findings.is_empty() {
        0.95
    } else {
        findings
            .iter()
            .map(|finding| finding.confidence)
            .sum::<f64>()
            / findings.len() as f64
    };
    let coverage_factor = run.coverage.as_object().map_or(0.8, |coverage| {
        let total = coverage.len();
        if total == 0 {
            return 0.8;
        }
        let complete = coverage
            .values()
            .filter(|value| value.get("complete").and_then(Value::as_bool) == Some(true))
            .count();
        0.6 + 0.4 * complete as f64 / total as f64
    });
    ((base * coverage_factor * 1000.0).round() / 1000.0).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn ads_detection_ignores_the_drive_colon() {
        assert!(!has_alternate_stream(r"C:\work\plain.txt"));
        assert!(has_alternate_stream(r"C:\work\plain.txt:hidden"));
    }

    #[test]
    fn service_rule_requires_a_persistence_value() {
        let base = RegistryEvent {
            evidence_id: "registry:0".to_string(),
            pid: 1,
            key: r"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters".to_string(),
            operation: "set_value".to_string(),
            value_name: None,
            value_data: None,
            observed_at_ms: 1,
            source: "registry-events.json".to_string(),
            association: ProcessAssociation {
                pid: 1,
                image: "sample.exe".to_string(),
                parent_pid: None,
                inferred: false,
                method: "explicit_pid".to_string(),
            },
            raw: Value::Null,
        };
        assert!(!is_autostart_key(&base));
        let mut persistence = base;
        persistence.value_name = Some("ImagePath".to_string());
        assert!(is_autostart_key(&persistence));
    }

    #[test]
    fn verdicts_cover_benign_suspicious_malicious_and_conflicting_rules() {
        let benign = empty_run();
        let report = build_verdict(&benign, "hash", &VerdictConfig::default());
        assert_eq!((report.verdict.as_str(), report.score), ("benign", 0));

        let mut suspicious = empty_run();
        suspicious
            .file_events
            .push(file_event(r"C:\temp\sample.txt:hidden"));
        let report = build_verdict(&suspicious, "hash", &VerdictConfig::default());
        assert_eq!((report.verdict.as_str(), report.score), ("suspicious", 30));

        let mut malicious = empty_run();
        malicious.processes.push(process_with_raw(json!({
            "event_type": "process_injection",
            "unknown_future_field": true
        })));
        let report = build_verdict(&malicious, "hash", &VerdictConfig::default());
        assert_eq!((report.verdict.as_str(), report.score), ("malicious", 70));

        malicious
            .file_events
            .push(file_event(r"C:\temp\sample.txt:hidden"));
        let report = build_verdict(&malicious, "hash", &VerdictConfig::default());
        assert_eq!((report.verdict.as_str(), report.score), ("malicious", 100));
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            ["ntfs_alternate_data_stream", "process_injection"]
        );
    }

    fn empty_run() -> NormalizedRun {
        NormalizedRun {
            schema_version: NORMALIZED_SCHEMA_VERSION.to_string(),
            run_id: "test-run".to_string(),
            target: json!({"path": "sample.exe"}),
            target_hashes: Vec::new(),
            sandbox: json!({}),
            execution: json!({"pid": 1}),
            coverage: json!({}),
            limitations: Vec::new(),
            raw_event_counts: RawEventCounts::default(),
            normalized_event_counts: RawEventCounts::default(),
            processes: Vec::new(),
            file_events: Vec::new(),
            registry_events: Vec::new(),
            network_events: Vec::new(),
            artifacts: Vec::new(),
            validation_warnings: Vec::new(),
            source_paths: Vec::new(),
            raw: BTreeMap::new(),
        }
    }

    fn association() -> ProcessAssociation {
        ProcessAssociation {
            pid: 1,
            image: "sample.exe".to_string(),
            parent_pid: None,
            inferred: false,
            method: "explicit_pid".to_string(),
        }
    }

    fn file_event(path: &str) -> FileEvent {
        FileEvent {
            evidence_id: "file:0".to_string(),
            pid: 1,
            path: path.to_string(),
            action: "create_or_overwrite".to_string(),
            size_bytes: Some(1),
            sha256: None,
            hash_source: None,
            observed_at_ms: 10,
            source: "filesystem-events.json".to_string(),
            association: association(),
            raw: json!({"path": path}),
        }
    }

    fn process_with_raw(raw: Value) -> Process {
        Process {
            pid: 1,
            parent_pid: None,
            image: "sample.exe".to_string(),
            command_line: Some("sample.exe".to_string()),
            status: "observed".to_string(),
            observed_at_ms: 1,
            observations: vec![ProcessObservation {
                evidence_id: "process:0".to_string(),
                pid: 1,
                parent_pid: None,
                image: "sample.exe".to_string(),
                command_line: Some("sample.exe".to_string()),
                status: "observed".to_string(),
                observed_at_ms: 1,
                source: "process-events.json".to_string(),
                raw: raw.clone(),
            }],
            raw,
        }
    }
}
