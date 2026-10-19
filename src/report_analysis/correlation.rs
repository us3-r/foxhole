//! Conservative, versioned temporal rules. Ordering alone never creates a causal edge.
use super::model::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub first: &'static str,
    pub second: &'static str,
    pub group: &'static str,
    pub attack: &'static str,
    pub score: u32,
    pub window: u64,
    pub relation: &'static str,
}
pub const RULES: &[Rule] = &[
    Rule {
        id: "FH-B001",
        title: "Created executable launched",
        first: "write_exe",
        second: "launch",
        group: "execution",
        attack: "T1204.002",
        score: 20,
        window: 120000,
        relation: "payload_child",
    },
    Rule {
        id: "FH-B002",
        title: "Executable write followed by persistence",
        first: "write_exe",
        second: "persistence",
        group: "persistence",
        attack: "T1547",
        score: 30,
        window: 120000,
        relation: "same_payload",
    },
    Rule {
        id: "FH-B003",
        title: "Service configuration changed and started",
        first: "service_modify",
        second: "service_start",
        group: "persistence",
        attack: "T1543.003",
        score: 30,
        window: 120000,
        relation: "same_object",
    },
    Rule {
        id: "FH-B004",
        title: "Scheduled task payload launched",
        first: "task_modify",
        second: "launch",
        group: "persistence",
        attack: "T1053.005",
        score: 30,
        window: 120000,
        relation: "payload_child",
    },
    Rule {
        id: "FH-B005",
        title: "Startup file written and executed",
        first: "startup_write",
        second: "launch",
        group: "persistence",
        attack: "T1547.001",
        score: 30,
        window: 120000,
        relation: "payload_child",
    },
    Rule {
        id: "FH-B006",
        title: "Cross-process access followed by injection evidence",
        first: "process_access",
        second: "injection",
        group: "injection",
        attack: "T1055",
        score: 50,
        window: 30000,
        relation: "same_object",
    },
    Rule {
        id: "FH-B007",
        title: "Correlated access to credential data",
        first: "credential_read",
        second: "credential_read",
        group: "credentials",
        attack: "T1555.003",
        score: 30,
        window: 30000,
        relation: "distinct_objects",
    },
    Rule {
        id: "FH-B008",
        title: "Anti-debugging with sandbox probing",
        first: "anti_debug",
        second: "sandbox_probe",
        group: "evasion",
        attack: "T1497",
        score: 20,
        window: 30000,
        relation: "same_process",
    },
    Rule {
        id: "FH-B009",
        title: "Security change with telemetry tampering",
        first: "security_change",
        second: "telemetry_tamper",
        group: "tampering",
        attack: "T1562.001",
        score: 40,
        window: 60000,
        relation: "same_process",
    },
    Rule {
        id: "FH-B010",
        title: "Suspicious process resolved and connected to an address",
        first: "dns_answer",
        second: "connect",
        group: "network",
        attack: "T1071.004",
        score: 10,
        window: 60000,
        relation: "dns_address",
    },
    Rule {
        id: "FH-B011",
        title: "Written script launched through an interpreter",
        first: "write_script",
        second: "script_launch",
        group: "execution",
        attack: "T1059",
        score: 20,
        window: 120000,
        relation: "payload_child",
    },
    Rule {
        id: "FH-B012",
        title: "Script interpreter launched a native payload",
        first: "interpreter",
        second: "launch",
        group: "execution",
        attack: "T1059",
        score: 20,
        window: 120000,
        relation: "parent_child",
    },
    Rule {
        id: "FH-B013",
        title: "Packed code with anti-analysis capability and suspicious runtime behavior",
        first: "packed_anti_analysis",
        second: "persistence",
        group: "evasion",
        attack: "T1027",
        score: 30,
        window: 120000,
        relation: "same_process",
    },
    Rule {
        id: "FH-B014",
        title: "Related processes communicated through a named pipe",
        first: "pipe_create",
        second: "pipe_connect",
        group: "ipc",
        attack: "T1559",
        score: 10,
        window: 30000,
        relation: "pipe_child",
    },
    Rule {
        id: "FH-B015",
        title: "Persistence followed by outbound communication",
        first: "persistence",
        second: "connect",
        group: "persistence",
        attack: "T1547",
        score: 30,
        window: 120000,
        relation: "same_process",
    },
    Rule {
        id: "FH-B016",
        title: "Child process exhibited stronger suspicious behavior",
        first: "launch",
        second: "injection",
        group: "injection",
        attack: "T1055",
        score: 40,
        window: 120000,
        relation: "child_behavior",
    },
];

#[derive(Clone, Debug)]
struct Activity {
    kind: String,
    pid: u32,
    parent: Option<u32>,
    time: u64,
    object: String,
    auxiliary: String,
    evidence: EvidenceReference,
}
fn path(value: &str) -> String {
    value
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}
fn executable(value: &str) -> bool {
    [".exe", ".dll", ".sys", ".com"]
        .iter()
        .any(|s| path(value).ends_with(s))
}
fn interpreter(value: &str) -> bool {
    [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "python.exe",
    ]
    .contains(&path(value).rsplit('\\').next().unwrap_or_default())
}
fn script(value: &str) -> bool {
    [".ps1", ".bat", ".cmd", ".vbs", ".js", ".py"]
        .iter()
        .any(|s| path(value).ends_with(s))
}
fn write(value: &str) -> bool {
    ["write", "create", "modify", "set", "add", "update"]
        .iter()
        .any(|s| value.to_ascii_lowercase().contains(s))
}
#[allow(clippy::too_many_arguments)]
fn evidence(
    id: &str,
    pid: u32,
    parent: Option<u32>,
    time: u64,
    source: &str,
    value: &str,
    inferred: bool,
    kind: &str,
    image: &str,
) -> EvidenceReference {
    EvidenceReference {
        evidence_id: id.into(),
        kind: kind.into(),
        pid,
        parent_pid: parent,
        observed_at_ms: time,
        source_artifact: source.into(),
        exact_value: value.into(),
        inferred,
        process_image: image.into(),
    }
}
fn add(
    events: &mut Vec<Activity>,
    kind: &str,
    object: &str,
    auxiliary: &str,
    e: EvidenceReference,
) {
    events.push(Activity {
        kind: kind.into(),
        pid: e.pid,
        parent: e.parent_pid,
        time: e.observed_at_ms,
        object: path(object),
        auxiliary: path(auxiliary),
        evidence: e,
    });
}
fn activities(run: &NormalizedRun) -> Vec<Activity> {
    let mut out = vec![];
    for p in &run.processes {
        for o in &p.observations {
            if o.status == "terminated" {
                continue;
            }
            let e = evidence(
                &o.evidence_id,
                o.pid,
                o.parent_pid,
                o.observed_at_ms,
                &o.source,
                &o.image,
                false,
                "process_observation",
                &o.image,
            );
            if o.status != "security_observation" && executable(&o.image) {
                add(&mut out, "launch", &o.image, "", e.clone());
            }
            if o.status != "security_observation" && interpreter(&o.image) {
                add(&mut out, "interpreter", &o.image, "", e.clone());
                // Exact argv token equality, never substring matching a payload path.
                if let Some(command) = &o.command_line {
                    for token in command_tokens(command) {
                        if script(&token) {
                            add(&mut out, "script_launch", &token, "", e.clone());
                        }
                    }
                }
            }
            let raw = o.raw.as_object();
            let event_type = raw
                .and_then(|v| v.get("event_type"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let kind = match event_type {
                "process_access" => "process_access",
                "process_injection" | "remote_thread" => "injection",
                "anti_debug" => "anti_debug",
                "sandbox_probe" => "sandbox_probe",
                "telemetry_tamper" => "telemetry_tamper",
                "security_change" => "security_change",
                "service_start" => "service_start",
                "service_modify" => "service_modify",
                "task_modify" => "task_modify",
                "credential_read" => "credential_read",
                _ => continue,
            };
            let object = raw
                .and_then(|v| v.get("object"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let payload = raw
                .and_then(|v| v.get("payload"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            add(
                &mut out,
                kind,
                if kind == "task_modify" {
                    payload
                } else {
                    object
                },
                payload,
                e,
            );
        }
    }
    for f in &run.file_events {
        let e = evidence(
            &f.evidence_id,
            f.pid,
            f.association.parent_pid,
            f.observed_at_ms,
            &f.source,
            &format!("{} {}", f.action, f.path),
            f.association.inferred,
            "file_event",
            &f.association.image,
        );
        if write(&f.action) {
            if executable(&f.path) {
                add(&mut out, "write_exe", &f.path, "", e.clone());
            }
            if script(&f.path) {
                add(&mut out, "write_script", &f.path, "", e.clone());
            }
            if path(&f.path).contains("\\start menu\\programs\\startup\\") {
                add(&mut out, "startup_write", &f.path, "", e.clone());
                add(&mut out, "persistence", &f.path, &f.path, e.clone());
            }
        }
        let p = path(&f.path);
        if ["read", "open", "access"]
            .iter()
            .any(|s| f.action.contains(s))
            && ([
                "\\login data",
                "\\cookies",
                "\\local state",
                "\\logins.json",
                "\\key4.db",
            ]
            .iter()
            .any(|s| p.ends_with(s))
                || p.contains("\\microsoft\\credentials\\"))
        {
            add(&mut out, "credential_read", &f.path, "", e.clone());
        }
        if f.action == "named_pipe_create" {
            add(&mut out, "pipe_create", &f.path, "", e.clone());
        }
        if f.action == "named_pipe_connect" {
            add(&mut out, "pipe_connect", &f.path, "", e);
        }
    }
    for r in &run.registry_events {
        let e = evidence(
            &r.evidence_id,
            r.pid,
            r.association.parent_pid,
            r.observed_at_ms,
            &r.source,
            &format!("{} {}", r.operation, r.key),
            r.association.inferred,
            "registry_event",
            &r.association.image,
        );
        let key = path(&r.key);
        let data = r.value_data.as_deref().unwrap_or_default();
        if write(&r.operation) {
            if key.contains("\\currentversion\\run")
                || (key.contains("\\currentcontrolset\\services\\")
                    && r.value_name
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("imagepath")))
            {
                add(&mut out, "persistence", data, data, e.clone());
            }
            if key.contains("\\currentcontrolset\\services\\")
                && r.value_name
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case("imagepath"))
            {
                add(
                    &mut out,
                    "service_modify",
                    key.rsplit('\\').next().unwrap_or_default(),
                    data,
                    e.clone(),
                );
            }
            if key.contains("\\windows defender")
                || key.contains("\\eventlog\\")
                || key.contains("\\sysmon")
            {
                add(&mut out, "security_change", &key, data, e.clone());
            }
        } else if ["read", "query", "open"]
            .iter()
            .any(|v| r.operation.contains(v))
            && (key.starts_with("hklm\\sam") || key.contains("\\security\\policy\\secrets"))
        {
            add(&mut out, "credential_read", &key, "", e);
        }
    }
    for n in &run.network_events {
        let e = evidence(
            &n.evidence_id,
            n.pid,
            n.association.parent_pid,
            n.observed_at_ms,
            &n.source,
            &format!("{} {}", n.protocol, n.remote_address),
            n.association.inferred,
            "network_event",
            &n.association.image,
        );
        if n.protocol == "dns" {
            if let Some(domain) = &n.domain
                && crate::detection::observables::valid_domain(domain)
            {
                let answers = n.raw.get("answers").and_then(serde_json::Value::as_array);
                for answer in answers
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                {
                    if let Ok(ip) = answer.parse::<std::net::IpAddr>() {
                        add(&mut out, "dns_answer", &ip.to_string(), domain, e.clone());
                    }
                }
            }
        } else if ["outbound", "out"].contains(&n.direction.as_str())
            && ["connected", "established", "success"]
                .iter()
                .any(|s| n.state.eq_ignore_ascii_case(s))
            && let Ok(ip) = n.remote_address.parse::<std::net::IpAddr>()
        {
            add(&mut out, "connect", &ip.to_string(), "", e);
        }
    }
    // Capabilities bind only to the host-hashed primary process, never a same-named child.
    let hash = run
        .target
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let root = run
        .execution
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    let packed = run.detection.stages.iter().any(|s| {
        s.target == "primary"
            && s.target_sha256 == hash
            && s.pe.as_ref().is_some_and(|p| !p.packer_compiler.is_empty())
    });
    if packed {
        let root_observation = run.processes.iter().find(|p| p.pid == root).and_then(|p| {
            p.observations
                .iter()
                .min_by_key(|o| o.observed_at_ms)
                .map(|o| (p, o))
        });
        for stage in &run.detection.stages {
            if stage.scanner != "capa" || stage.target != "primary" || stage.target_sha256 != hash {
                continue;
            }
            for f in &stage.findings {
                if !f
                    .attack
                    .iter()
                    .any(|t| t.starts_with("T1497") || t == "T1622")
                {
                    continue;
                }
                if let Some((p, o)) = root_observation {
                    let mut e = evidence(
                        &f.evidence_ids[0],
                        root,
                        p.parent_pid,
                        o.observed_at_ms,
                        "",
                        &f.rule,
                        false,
                        "static_capability",
                        &p.image,
                    );
                    e.exact_value = format!("{} {}", hash, f.rule);
                    add(&mut out, "packed_anti_analysis", hash, "", e);
                }
            }
        }
    }
    out.sort_by(|a, b| {
        (a.time, a.pid, &a.kind, &a.object, &a.evidence.evidence_id).cmp(&(
            b.time,
            b.pid,
            &b.kind,
            &b.object,
            &b.evidence.evidence_id,
        ))
    });
    out
}
fn command_tokens(value: &str) -> Vec<String> {
    let mut tokens = vec![];
    let mut token = String::new();
    let mut quoted = false;
    for c in value.chars().take(32768) {
        if c == '"' {
            quoted = !quoted;
        } else if c.is_whitespace() && !quoted {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(c);
        }
    }
    if !quoted && !token.is_empty() {
        tokens.push(token);
    }
    tokens
}
type ProcessInstance = (u64, String);
type InstanceHistory = Vec<(u64, Option<ProcessInstance>)>;

/// Build lifetimes and suspicious-event lookups once. The pair budget must not
/// hide a fresh scan/sort of all process observations or activities per pair.
struct CorrelationIndex {
    histories: BTreeMap<u32, InstanceHistory>,
    suspicious: BTreeMap<u32, BTreeMap<ProcessInstance, Vec<u64>>>,
}

impl CorrelationIndex {
    fn new(run: &NormalizedRun, events: &[Activity]) -> Self {
        let mut histories = BTreeMap::new();
        for process in &run.processes {
            let std::collections::btree_map::Entry::Vacant(entry) = histories.entry(process.pid)
            else {
                continue;
            };
            let history = entry.insert(Vec::new());
            let mut observations = process
                .observations
                .iter()
                .filter(|o| o.observed_at_ms > 0)
                .collect::<Vec<_>>();
            observations.sort_by(|a, b| {
                (a.observed_at_ms, &a.status, &a.image).cmp(&(
                    b.observed_at_ms,
                    &b.status,
                    &b.image,
                ))
            });
            let mut start: Option<ProcessInstance> = None;
            let mut guid = String::new();
            for observation in observations {
                let next_guid = observation
                    .raw
                    .get("process_guid")
                    .or_else(|| observation.raw.get("ProcessGuid"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if observation.status == "terminated" {
                    start = None;
                    guid.clear();
                } else if (!guid.is_empty() && !next_guid.is_empty() && guid != next_guid)
                    || start
                        .as_ref()
                        .is_none_or(|(_, image)| *image != path(&observation.image))
                {
                    start = Some((observation.observed_at_ms, path(&observation.image)));
                }
                if !next_guid.is_empty() {
                    guid = next_guid;
                }
                history.push((observation.observed_at_ms, start.clone()));
            }
        }
        let mut index = Self {
            histories,
            suspicious: BTreeMap::new(),
        };
        for event in events.iter().filter(|e| {
            [
                "injection",
                "credential_read",
                "persistence",
                "telemetry_tamper",
            ]
            .contains(&e.kind.as_str())
        }) {
            if let Some(instance) = index.instance(event.pid, event.time).cloned() {
                index
                    .suspicious
                    .entry(event.pid)
                    .or_default()
                    .entry(instance)
                    .or_default()
                    .push(event.time);
            }
        }
        for instances in index.suspicious.values_mut() {
            for times in instances.values_mut() {
                times.sort_unstable();
            }
        }
        index
    }

    fn instance(&self, pid: u32, time: u64) -> Option<&ProcessInstance> {
        if pid == 0 || time == 0 {
            return None;
        }
        let history = self.histories.get(&pid)?;
        let end = history.partition_point(|(at, _)| *at <= time);
        history.get(end.checked_sub(1)?)?.1.as_ref()
    }

    fn suspicious(&self, pid: u32, time: u64) -> bool {
        let Some(instance) = self.instance(pid, time) else {
            return false;
        };
        let Some(times) = self
            .suspicious
            .get(&pid)
            .and_then(|instances| instances.get(instance))
        else {
            return false;
        };
        let end = times.partition_point(|at| *at <= time);
        end.checked_sub(1)
            .is_some_and(|last| time - times[last] <= 120000)
    }
}
fn same(index: &CorrelationIndex, a: &Activity, b: &Activity) -> bool {
    a.pid == b.pid
        && index.instance(a.pid, a.time).is_some()
        && index.instance(a.pid, a.time) == index.instance(b.pid, b.time)
}
fn related(index: &CorrelationIndex, a: &Activity, b: &Activity) -> bool {
    b.parent == Some(a.pid)
        && index.instance(a.pid, a.time).is_some()
        && index.instance(a.pid, a.time) == index.instance(a.pid, b.time)
        && index.instance(b.pid, b.time).is_some()
}
fn matches(rule: &Rule, a: &Activity, b: &Activity, index: &CorrelationIndex) -> bool {
    if a.time == 0
        || b.time <= a.time
        || b.time - a.time > rule.window
        || a.evidence.evidence_id == b.evidence.evidence_id
    {
        return false;
    }
    match rule.relation {
        "payload_child" => related(index, a, b) && !a.object.is_empty() && a.object == b.object,
        "parent_child" => related(index, a, b),
        "child_behavior" => {
            a.pid == b.pid
                && same(index, a, b)
                && a.parent.is_some_and(|p| !index.suspicious(p, b.time))
                && index.suspicious(b.pid, b.time)
        }
        "pipe_child" => {
            !a.object.is_empty()
                && a.object == b.object
                && a.pid != b.pid
                && (related(index, a, b)
                    || (a.parent == b.parent
                        && a.parent.is_some()
                        && index.instance(a.parent.unwrap_or(0), a.time).is_some()
                        && index.instance(a.parent.unwrap_or(0), a.time)
                            == index.instance(a.parent.unwrap_or(0), b.time)))
        }
        "same_object" | "same_payload" => {
            same(index, a, b) && !a.object.is_empty() && a.object == b.object
        }
        "distinct_objects" => {
            same(index, a, b)
                && !a.object.is_empty()
                && !b.object.is_empty()
                && a.object != b.object
        }
        "dns_address" => {
            same(index, a, b)
                && a.object == b.object
                && !a.auxiliary.is_empty()
                && index.suspicious(a.pid, a.time)
        }
        "same_process" => same(index, a, b),
        _ => false,
    }
}
pub fn build(run: &NormalizedRun) -> Vec<Finding> {
    if !run.detection.effective_config.behavioral {
        return vec![];
    }
    let events = activities(run);
    build_from_events(run, &events)
}
fn build_from_events(run: &NormalizedRun, events: &[Activity]) -> Vec<Finding> {
    let mut ordered = events.to_vec();
    ordered.sort_by(|a, b| {
        (a.time, a.pid, &a.kind, &a.object, &a.evidence.evidence_id).cmp(&(
            b.time,
            b.pid,
            &b.kind,
            &b.object,
            &b.evidence.evidence_id,
        ))
    });
    let events = ordered.as_slice();
    let index = CorrelationIndex::new(run, events);
    let complete = super::detection::telemetry_complete(run);
    let mut findings = vec![];
    let mut checks = 0usize;
    for rule in RULES {
        let mut evidence = BTreeMap::new();
        let seconds = events
            .iter()
            .filter(|e| e.kind == rule.second)
            .collect::<Vec<_>>();
        for a in events.iter().filter(|e| e.kind == rule.first) {
            let lower = seconds.partition_point(|e| e.time <= a.time);
            let upper = seconds.partition_point(|e| e.time <= a.time.saturating_add(rule.window));
            for b in &seconds[lower..upper] {
                checks += 1;
                if checks > 1_000_000 {
                    break;
                }
                if matches(rule, a, b, &index) {
                    if evidence.len() >= 256 {
                        checks = 1_000_001;
                        break;
                    }
                    evidence.insert(a.evidence.evidence_id.clone(), a.evidence.clone());
                    evidence.insert(b.evidence.evidence_id.clone(), b.evidence.clone());
                }
            }
            if checks > 1_000_000 {
                break;
            }
        }
        if evidence.is_empty() {
            continue;
        }
        let inferred = evidence.values().any(|e| e.inferred);
        findings.push(Finding {rule_id:rule.id.into(),severity:Severity::Suspicious,title:rule.title.into(),
            explanation:format!("{} followed by {} within {} ms; {} association and object conditions matched. Timing alone is insufficient.",rule.first,rule.second,rule.window,rule.relation),
            evidence:evidence.into_values().collect(),confidence:if inferred {0.5} else if complete {0.95} else {0.75},score_contribution:rule.score,
            details:Some(FindingDetails {version:"1".into(),source:"behavioral".into(),namespace:"foxhole/behavior".into(),file_sha256:None,
                attack:vec![rule.attack.into()],required_events:vec![rule.first.into(),rule.second.into()],window_ms:Some(rule.window),
                association:if inferred {"inferred"} else if ["payload_child","parent_child","pipe_child"].contains(&rule.relation) {"inherited"} else {"direct"}.into(),
                false_positive_guidance:"Installers, administrative tools, debuggers and test harnesses can produce this chain. Review the exact objects, process lifetime and purpose.".into(),score_group:rule.group.into()})});
    }
    if checks > 1_000_000
        && let Some(e) = events.first()
    {
        findings.push(Finding {details:None,rule_id:"FH-COVERAGE-001".into(),severity:Severity::Informational,title:"Behavioral correlation budget exhausted".into(),explanation:"Correlation was partial because the fixed pair or evidence limit was reached; unmatched rules are not a clean result.".into(),evidence:vec![e.evidence.clone()],confidence:0.3,score_contribution:0});
    }
    static_confirmation(run, events, &index, &mut findings);
    findings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    findings
}
fn static_confirmation(
    run: &NormalizedRun,
    events: &[Activity],
    index: &CorrelationIndex,
    findings: &mut Vec<Finding>,
) {
    let hash = run
        .target
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let root = run
        .execution
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    let root_start = run.processes.iter().find(|p| p.pid == root).and_then(|p| {
        p.observations
            .iter()
            .filter(|o| o.observed_at_ms > 0)
            .map(|o| o.observed_at_ms)
            .min()
    });
    // Retain the first matching activity in input order for each confirmation
    // family. Capabilities query these four candidates rather than all events.
    let mut confirmations = BTreeMap::new();
    if let Some(start) = root_start {
        let root_instance = index.instance(root, start);
        for (order, event) in events.iter().enumerate() {
            let prefix = match event.kind.as_str() {
                "injection" => "T1055",
                "persistence" => "T154",
                "credential_read" => "T1555",
                "telemetry_tamper" => "T1562",
                _ => continue,
            };
            if event.pid == root
                && event.time >= start
                && event.time - start <= 120000
                && root_instance.is_some()
                && root_instance == index.instance(root, event.time)
            {
                confirmations.entry(prefix).or_insert((order, event));
            }
        }
    }
    for stage in &run.detection.stages {
        if stage.scanner != "capa" || stage.target != "primary" || stage.target_sha256 != hash {
            continue;
        }
        for capability in &stage.findings {
            let confirmation = confirmations
                .iter()
                .filter(|(prefix, _)| {
                    capability.attack.iter().any(|t| {
                        if **prefix == "T154" {
                            t.starts_with("T1547") || t.starts_with("T1543")
                        } else {
                            t.starts_with(**prefix)
                        }
                    })
                })
                .map(|(_, &(order, event))| (order, event))
                .min_by_key(|(order, _)| *order)
                .map(|(_, event)| event);
            let mut refs = capability
                .evidence_ids
                .iter()
                .map(|id| {
                    evidence(
                        id,
                        0,
                        None,
                        0,
                        "",
                        &capability.rule,
                        false,
                        "static_capability",
                        "",
                    )
                })
                .collect::<Vec<_>>();
            if let Some(e) = confirmation {
                refs.push(e.evidence.clone());
            }
            findings.push(Finding {rule_id:format!("{}:{}",if confirmation.is_some(){"FH-B017"}else{"FH-B018"},capability.id),
                severity:Severity::Informational,title:if confirmation.is_some(){"Runtime evidence confirms static capability"}else{"Static capability not confirmed by available telemetry"}.into(),
                explanation:if confirmation.is_some(){"The host-hashed primary file has a mapped capability and matching runtime evidence. This adds no duplicate behavior score."}else{"No matching runtime evidence was available. This does not establish that the capability was absent, contradicted, or safe."}.into(),
                evidence:refs,confidence:if confirmation.is_some_and(|e|e.evidence.inferred){0.5}else if confirmation.is_some() && super::detection::telemetry_complete(run){0.85}else if confirmation.is_some(){0.65}else{0.4},score_contribution:0,
                details:Some(FindingDetails {version:"1".into(),source:"behavioral".into(),namespace:"foxhole/capability".into(),file_sha256:Some(hash.into()),
                    attack:capability.attack.clone(),required_events:vec!["static_capability".into(),"mapped_runtime_event".into()],window_ms:Some(120000),association:if confirmation.is_some_and(|e|e.evidence.inferred){"inferred"}else{"direct"}.into(),
                    false_positive_guidance:"Capabilities describe possible code behavior; missing telemetry is not evidence of safety.".into(),score_group:String::new()})});
        }
    }
}
/// Max once per behavior family across old rules, new chains and duplicate telemetry sources.
pub fn deduplicate_scores(findings: &mut [Finding]) {
    let mut winners = BTreeMap::<String, (u32, String)>::new();
    for f in findings.iter() {
        let group = score_group(f);
        if f.score_contribution == 0 {
            continue;
        }
        let candidate = (f.score_contribution, f.rule_id.clone());
        let prior = winners.entry(group).or_insert(candidate.clone());
        if candidate.0 > prior.0 || (candidate.0 == prior.0 && candidate.1 < prior.1) {
            *prior = candidate;
        }
    }
    let mut scored_evidence = BTreeSet::new();
    // Stronger scores own overlapping evidence first. Results are independent of arrival order.
    let mut order = (0..findings.len()).collect::<Vec<_>>();
    order.sort_by(|a, b| {
        findings[*b]
            .score_contribution
            .cmp(&findings[*a].score_contribution)
            .then_with(|| findings[*a].rule_id.cmp(&findings[*b].rule_id))
    });
    for i in order {
        let group = score_group(&findings[i]);
        let f = &mut findings[i];
        if f.score_contribution == 0 {
            continue;
        }
        if winners.get(&group).is_none_or(|(_, id)| id != &f.rule_id)
            || f.evidence
                .iter()
                .any(|e| scored_evidence.contains(&e.evidence_id))
        {
            f.score_contribution = 0;
            f.explanation.push_str(
                " Score suppressed because the same underlying behavior is already scored.",
            );
        } else {
            scored_evidence.extend(f.evidence.iter().map(|e| e.evidence_id.clone()));
        }
    }
}
fn score_group(f: &Finding) -> String {
    if let Some(d) = &f.details
        && !d.score_group.is_empty()
    {
        return d.score_group.clone();
    }
    match f.rule_id.as_str() {
        "process_injection" => "injection",
        "credential_store_access" => "credentials",
        "suspicious_registry_autostart" => "persistence",
        "script_interpreter_network" => "execution",
        _ => &f.rule_id,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn indexed_instances_preserve_guid_changes_termination_and_suspicious_windows() {
        let mut run = run();
        let first = run.processes[0].observations[0].clone();
        let observation = |time, status: &str, guid: &str, image: &str| {
            let mut row = first.clone();
            row.observed_at_ms = time;
            row.status = status.into();
            row.image = image.into();
            row.raw = json!({"ProcessGuid":guid});
            row
        };
        run.processes[0].observations = vec![
            observation(10, "observed", "A", "C:\\one.exe"),
            observation(20, "observed", "a", "C:\\one.exe"),
            observation(30, "observed", "B", "C:\\one.exe"),
            observation(40, "terminated", "B", "C:\\one.exe"),
            observation(40, "observed", "C", "C:\\two.exe"),
            observation(50, "observed", "C", "C:\\two.exe"),
        ];
        let events = vec![
            event("injection", 1, 20, "", "first"),
            event("persistence", 1, 50, "", "second"),
        ];
        let index = CorrelationIndex::new(&run, &events);
        assert_eq!(index.instance(1, 9), None);
        assert_eq!(index.instance(1, 29).map(|v| v.0), Some(10));
        assert_eq!(index.instance(1, 30).map(|v| v.0), Some(30));
        // Same-time observations retain the old status/image ordering: termination wins.
        assert_eq!(index.instance(1, 40), None);
        assert_eq!(index.instance(1, 50).map(|v| v.0), Some(50));
        assert!(!index.suspicious(1, 19));
        assert!(index.suspicious(1, 29));
        assert!(!index.suspicious(1, 30));
        assert!(index.suspicious(1, 120050));
        assert!(!index.suspicious(1, 120051));
        assert_eq!(index.instance(0, 50), None);
        assert_eq!(index.instance(1, 0), None);
    }

    #[test]
    fn capability_confirmation_preserves_first_matching_event_order() {
        let mut run = run();
        let mut stage: crate::detection::ScannerResult =
            serde_json::from_str(include_str!("../../tests/fixtures/detection/capa.json")).unwrap();
        stage.target_sha256 = "cd".repeat(32);
        let mut capability = stage.findings[0].clone();
        capability.attack = vec!["T1055".into(), "T1547".into()];
        stage.findings = vec![capability];
        run.detection.stages.push(stage);
        let events = vec![
            event("persistence", 1, 150, "", "first-input-event"),
            event("injection", 1, 100, "", "earlier-time"),
        ];
        let index = CorrelationIndex::new(&run, &events);
        let mut findings = vec![];
        static_confirmation(&run, &events, &index, &mut findings);
        assert_eq!(
            findings[0].evidence.last().unwrap().evidence_id,
            "first-input-event"
        );
        assert!(findings[0].rule_id.starts_with("FH-B017:"));
    }

    #[test]
    fn many_unconfirmed_capabilities_do_not_rescan_launch_observations() {
        let mut run = run();
        let first = run.processes[0].observations[0].clone();
        run.processes[0].observations = (1..=50_000)
            .map(|time| {
                let mut row = first.clone();
                row.observed_at_ms = time;
                row.evidence_id = format!("launch:{time}");
                row
            })
            .collect();
        let mut stage: crate::detection::ScannerResult =
            serde_json::from_str(include_str!("../../tests/fixtures/detection/capa.json")).unwrap();
        stage.target_sha256 = "cd".repeat(32);
        let mut capability = stage.findings[0].clone();
        capability.attack = vec!["T1055".into()];
        stage.findings = (0..4096)
            .map(|id| {
                let mut finding = capability.clone();
                finding.id = format!("capability:{id}");
                finding
            })
            .collect();
        run.detection.stages.push(stage);
        let findings = build(&run);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule_id.starts_with("FH-B018:"))
                .count(),
            4096
        );
        assert!(!findings.iter().any(|f| f.rule_id.starts_with("FH-B017:")));
    }

    #[test]
    fn repeated_process_instance_queries_use_one_bounded_history() {
        let mut run = run();
        let first = run.processes[0].observations[0].clone();
        run.processes[0].observations = (1..=50_000)
            .map(|time| {
                let mut row = first.clone();
                row.observed_at_ms = time;
                row
            })
            .collect();
        let events = vec![event("injection", 1, 1, "", "first")];
        let index = CorrelationIndex::new(&run, &events);
        assert_eq!(index.histories[&1].len(), 50_000);
        for time in 1..=50_000 {
            assert_eq!(index.instance(1, time).map(|v| v.0), Some(1));
            assert!(index.suspicious(1, time));
        }
    }
    fn run() -> NormalizedRun {
        let mut run:NormalizedRun=serde_json::from_value(json!({"schema_version":"1.0","run_id":"fixture","target":{"sha256":"cd".repeat(32),"size_bytes":1024},"target_hashes":[],"sandbox":{},"execution":{"pid":1},"coverage":{},"limitations":[],"raw_event_counts":{"process":0,"network":0,"filesystem":0,"registry":0},"normalized_event_counts":{"process":0,"network":0,"filesystem":0,"registry":0},"processes":[],"file_events":[],"registry_events":[],"network_events":[],"artifacts":[],"validation_warnings":[],"source_paths":[],"raw":{}})).unwrap();
        for name in ["processes", "network", "filesystem", "registry"] {
            run.coverage[name] = json!({"complete":true});
        }
        for pid in 1..=3 {
            let o = ProcessObservation {
                evidence_id: format!("start:{pid}"),
                pid,
                parent_pid: if pid == 1 { None } else { Some(1) },
                image: format!("C:\\work\\p{pid}.exe"),
                command_line: None,
                status: "started".into(),
                observed_at_ms: 1,
                source: "fixture".into(),
                raw: json!({}),
            };
            run.processes.push(Process {
                pid,
                parent_pid: o.parent_pid,
                image: o.image.clone(),
                command_line: None,
                status: "started".into(),
                observed_at_ms: 1,
                observations: vec![o],
                raw: json!({}),
            });
        }
        run
    }
    fn event(kind: &str, pid: u32, time: u64, object: &str, id: &str) -> Activity {
        Activity {
            kind: kind.into(),
            pid,
            parent: if pid == 1 { None } else { Some(1) },
            time,
            object: object.into(),
            auxiliary: "example.com".into(),
            evidence: evidence(
                id,
                pid,
                if pid == 1 { None } else { Some(1) },
                time,
                "fixture",
                object,
                false,
                "fixture",
                "p.exe",
            ),
        }
    }
    fn pair(rule: &Rule) -> Vec<Activity> {
        let mut a = event(rule.first, 1, 100, "object", "a");
        let mut b = event(rule.second, 1, 200, "object", "b");
        if ["payload_child", "parent_child", "pipe_child"].contains(&rule.relation) {
            b.pid = 2;
            b.parent = Some(1);
            b.evidence.pid = 2;
            b.evidence.parent_pid = Some(1);
        }
        if rule.relation == "child_behavior" {
            a.pid = 2;
            a.parent = Some(1);
            a.evidence.pid = 2;
            b.pid = 2;
            b.parent = Some(1);
            b.evidence.pid = 2;
        }
        if rule.relation == "distinct_objects" {
            b.object = "different-object".into();
        }
        let mut events = vec![a, b];
        if rule.id == "FH-B010" {
            events.push(event("persistence", 1, 50, "payload", "c"));
        }
        events
    }
    #[test]
    fn every_temporal_rule_has_positive_near_miss_duplicate_and_incomplete_cases() {
        for rule in RULES {
            let run = run();
            let mut events = pair(rule);
            let positive = build_from_events(&run, &events)
                .into_iter()
                .find(|f| f.rule_id == rule.id)
                .unwrap_or_else(|| panic!("positive {}", rule.id));
            let mut incomplete = run.clone();
            incomplete.coverage = json!({});
            let lower = build_from_events(&incomplete, &events)
                .into_iter()
                .find(|f| f.rule_id == rule.id)
                .unwrap();
            assert!(lower.confidence < positive.confidence, "{}", rule.id);
            events.extend(events.clone());
            let duplicate = build_from_events(&run, &events)
                .into_iter()
                .find(|f| f.rule_id == rule.id)
                .unwrap();
            assert_eq!(positive, duplicate, "duplicate {}", rule.id);
            let mut near = pair(rule);
            near[1].time = near[0].time + rule.window + 1;
            assert!(
                !build_from_events(&run, &near)
                    .iter()
                    .any(|f| f.rule_id == rule.id),
                "near miss {}",
                rule.id
            );
        }
    }
    #[test]
    fn event_order_pid_reuse_missing_times_inference_and_score_dedup_are_safe() {
        let mut run = run();
        let rule = &RULES[1];
        let events = pair(rule);
        let expected = build_from_events(&run, &events);
        let mut reversed = events.clone();
        reversed.reverse();
        assert_eq!(expected, build_from_events(&run, &reversed));
        let mut missing = events.clone();
        missing[0].time = 0;
        assert!(build_from_events(&run, &missing).is_empty());
        let mut inferred = events.clone();
        inferred[0].evidence.inferred = true;
        assert!(build_from_events(&run, &inferred)[0].confidence < expected[0].confidence);
        let mut terminated = run.processes[0].observations[0].clone();
        terminated.status = "terminated".into();
        terminated.observed_at_ms = 150;
        terminated.evidence_id = "end".into();
        let mut reused = terminated.clone();
        reused.status = "started".into();
        reused.observed_at_ms = 160;
        reused.evidence_id = "restart".into();
        run.processes[0].observations.extend([terminated, reused]);
        assert!(build_from_events(&run, &events).is_empty());
        run.processes[0].observations.truncate(1);
        run.processes[0].observations[0].raw = json!({"process_guid":"original"});
        let mut reused = run.processes[0].observations[0].clone();
        reused.observed_at_ms = 150;
        reused.evidence_id = "reuse-without-termination".into();
        reused.raw = json!({"process_guid":"new"});
        run.processes[0].observations.push(reused);
        assert!(build_from_events(&run, &events).is_empty());
        let mut scored = expected.clone();
        let mut another = expected[0].clone();
        another.rule_id = "other".into();
        scored.push(another);
        deduplicate_scores(&mut scored);
        assert_eq!(
            scored.iter().map(|f| f.score_contribution).sum::<u32>(),
            expected[0].score_contribution
        );
    }
    #[test]
    fn normalized_file_creation_requires_exact_child_payload() {
        let mut run = run();
        run.processes[1].observations[0].observed_at_ms = 200;
        let a = ProcessAssociation {
            pid: 1,
            image: run.processes[0].image.clone(),
            parent_pid: None,
            inferred: false,
            method: "explicit_pid".into(),
        };
        run.file_events.push(FileEvent {
            evidence_id: "file:one".into(),
            pid: 1,
            path: run.processes[1].image.clone(),
            action: "write".into(),
            size_bytes: Some(10),
            sha256: None,
            hash_source: None,
            observed_at_ms: 100,
            source: "fixture".into(),
            association: a,
            raw: json!({}),
        });
        assert!(build(&run).iter().any(|f| f.rule_id == "FH-B001"));
        run.file_events[0].path = "C:\\work\\p2.exe.bak".into();
        assert!(!build(&run).iter().any(|f| f.rule_id == "FH-B001"));
    }
    #[test]
    fn static_confirmation_and_nonconfirmation_never_add_duplicate_score() {
        let mut run = run();
        let mut stage: crate::detection::ScannerResult =
            serde_json::from_str(include_str!("../../tests/fixtures/detection/capa.json")).unwrap();
        stage.target_sha256 = "cd".repeat(32);
        stage.findings[0].attack = vec!["T1055".into()];
        run.detection.stages.push(stage);
        let mut findings = vec![];
        let index = CorrelationIndex::new(&run, &[]);
        static_confirmation(&run, &[], &index, &mut findings);
        assert!(findings[0].rule_id.starts_with("FH-B018"));
        assert_eq!(findings[0].score_contribution, 0);
        let confirmed = findings.clone();
        findings.clear();
        static_confirmation(
            &run,
            &[event("injection", 1, 120002, "target", "late")],
            &index,
            &mut findings,
        );
        assert!(findings[0].rule_id.starts_with("FH-B018"));
        findings.clear();
        run.coverage = json!({});
        static_confirmation(
            &run,
            &[event("injection", 1, 100, "target", "inject")],
            &index,
            &mut findings,
        );
        assert!(findings[0].confidence < 0.85);
        assert!(confirmed.iter().all(|f| f.score_contribution == 0));
        findings.clear();
        static_confirmation(
            &run,
            &[event("injection", 1, 100, "target", "inject")],
            &index,
            &mut findings,
        );
        assert!(findings[0].rule_id.starts_with("FH-B017"));
        assert_eq!(findings[0].score_contribution, 0);
    }
}
