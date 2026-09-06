use super::model::*;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
struct Candidate {
    ioc_type: String,
    value: String,
    normalized_value: String,
    observed_at_ms: u64,
    contextual: bool,
    likely_benign: bool,
    source: IocSource,
}

pub fn extract_iocs(run: &NormalizedRun, normalized_hash: &str) -> IocReport {
    let mut candidates = Vec::new();
    extract_hashes(run, &mut candidates);
    extract_process_iocs(run, &mut candidates);
    extract_file_iocs(run, &mut candidates);
    extract_registry_iocs(run, &mut candidates);
    extract_network_iocs(run, &mut candidates);

    let mut by_key: BTreeMap<(String, String), IocRecord> = BTreeMap::new();
    for candidate in candidates {
        let key = (
            candidate.ioc_type.clone(),
            candidate.normalized_value.clone(),
        );
        match by_key.get_mut(&key) {
            Some(record) => {
                if candidate.observed_at_ms < record.first_seen_ms {
                    record.value = candidate.value.clone();
                }
                record.first_seen_ms = record.first_seen_ms.min(candidate.observed_at_ms);
                record.last_seen_ms = record.last_seen_ms.max(candidate.observed_at_ms);
                record.contextual |= candidate.contextual;
                record.likely_benign |= candidate.likely_benign;
                if !record.sources.contains(&candidate.source) {
                    record.sources.push(candidate.source);
                    record.sources.sort();
                }
            }
            None => {
                by_key.insert(
                    key,
                    IocRecord {
                        ioc_type: candidate.ioc_type,
                        value: candidate.value,
                        normalized_value: candidate.normalized_value,
                        first_seen_ms: candidate.observed_at_ms,
                        last_seen_ms: candidate.observed_at_ms,
                        contextual: candidate.contextual,
                        likely_benign: candidate.likely_benign,
                        sources: vec![candidate.source],
                    },
                );
            }
        }
    }
    let mut indicators = by_key.into_values().collect::<Vec<_>>();
    indicators.sort_by(|left, right| {
        left.ioc_type
            .cmp(&right.ioc_type)
            .then_with(|| left.normalized_value.cmp(&right.normalized_value))
            .then_with(|| left.first_seen_ms.cmp(&right.first_seen_ms))
    });
    let mut counts_by_type = BTreeMap::new();
    for indicator in &indicators {
        *counts_by_type
            .entry(indicator.ioc_type.clone())
            .or_insert(0) += 1;
    }
    let mut extraction_warnings = run.validation_warnings.clone();
    if run.target_hashes.is_empty() {
        extraction_warnings.push(ValidationWarning {
            code: "target_hash_unavailable".to_string(),
            source: "host_report.target".to_string(),
            event_index: None,
            message: "the archived run does not expose the original target hash; no target hash IOC was fabricated".to_string(),
            raw: None,
        });
    }
    IocReport {
        schema_version: IOC_SCHEMA_VERSION.to_string(),
        run_id: run.run_id.clone(),
        normalized_input_sha256: normalized_hash.to_string(),
        counts_by_type,
        indicators,
        extraction_warnings,
    }
}

fn extract_hashes(run: &NormalizedRun, output: &mut Vec<Candidate>) {
    for hash in &run.target_hashes {
        output.push(Candidate {
            ioc_type: hash.algorithm.clone(),
            value: hash.value.clone(),
            normalized_value: hash.value.to_ascii_lowercase(),
            observed_at_ms: 0,
            contextual: false,
            likely_benign: false,
            source: IocSource {
                kind: "target_metadata".to_string(),
                pid: None,
                artifact: hash.source.clone(),
                evidence_id: None,
            },
        });
    }
    for artifact in &run.artifacts {
        if !artifact.hash_verified {
            continue;
        }
        output.push(Candidate {
            ioc_type: "sha256".to_string(),
            value: artifact.sha256.clone(),
            normalized_value: artifact.sha256.to_ascii_lowercase(),
            observed_at_ms: 0,
            contextual: false,
            likely_benign: false,
            source: IocSource {
                kind: "validated_artifact".to_string(),
                pid: None,
                artifact: artifact.relative_path.clone(),
                evidence_id: Some(artifact.evidence_id.clone()),
            },
        });
    }
    for event in &run.file_events {
        let Some(digest) = event.sha256.as_deref() else {
            continue;
        };
        output.push(Candidate {
            ioc_type: "sha256".to_string(),
            value: digest.to_string(),
            normalized_value: digest.to_ascii_lowercase(),
            observed_at_ms: event.observed_at_ms,
            contextual: false,
            likely_benign: false,
            source: IocSource {
                kind: "created_file_hash".to_string(),
                pid: Some(event.pid),
                artifact: event.path.clone(),
                evidence_id: Some(event.evidence_id.clone()),
            },
        });
    }
}

fn extract_process_iocs(run: &NormalizedRun, output: &mut Vec<Candidate>) {
    for process in &run.processes {
        for observation in &process.observations {
            if observation.status == "terminated" {
                continue;
            }
            let system_binary = is_windows_system_binary(&observation.image);
            add(
                output,
                "process_image",
                &observation.image,
                observation.observed_at_ms,
                system_binary,
                system_binary,
                source("process_image", Some(observation.pid), observation),
            );
            if looks_like_path(&observation.image) {
                add(
                    output,
                    "file_path",
                    &observation.image,
                    observation.observed_at_ms,
                    system_binary,
                    system_binary,
                    source("process_image", Some(observation.pid), observation),
                );
            }
            let Some(command_line) = observation.command_line.as_deref() else {
                continue;
            };
            let urls = extract_urls(command_line);
            let domains = extract_domains(command_line);
            let ips = extract_ips(command_line);
            let paths = extract_paths(command_line);
            if meaningful_command_line(command_line, &urls, &domains, &ips) {
                add(
                    output,
                    "command_line",
                    command_line,
                    observation.observed_at_ms,
                    false,
                    system_binary && !has_suspicious_argument(command_line),
                    source("process_command_line", Some(observation.pid), observation),
                );
            }
            for url in urls {
                let contextual = url_domain(&url).is_some_and(contextual_domain);
                add(
                    output,
                    "url",
                    &url,
                    observation.observed_at_ms,
                    contextual,
                    contextual,
                    source("process_command_line", Some(observation.pid), observation),
                );
            }
            for domain in domains {
                let contextual = contextual_domain(&domain);
                add(
                    output,
                    "domain",
                    &domain,
                    observation.observed_at_ms,
                    contextual,
                    contextual,
                    source("process_command_line", Some(observation.pid), observation),
                );
            }
            for ip in ips {
                add_ip(
                    output,
                    ip,
                    observation.observed_at_ms,
                    source("process_command_line", Some(observation.pid), observation),
                );
            }
            for path in paths {
                let contextual = is_windows_system_binary(&path);
                add(
                    output,
                    "file_path",
                    &path,
                    observation.observed_at_ms,
                    contextual,
                    contextual,
                    source("process_command_line", Some(observation.pid), observation),
                );
            }
        }
    }
}

fn extract_file_iocs(run: &NormalizedRun, output: &mut Vec<Candidate>) {
    for event in &run.file_events {
        add(
            output,
            "file_path",
            &event.path,
            event.observed_at_ms,
            false,
            false,
            IocSource {
                kind: "filesystem_event".to_string(),
                pid: Some(event.pid),
                artifact: event.source.clone(),
                evidence_id: Some(event.evidence_id.clone()),
            },
        );
    }
}

fn extract_registry_iocs(run: &NormalizedRun, output: &mut Vec<Candidate>) {
    for event in &run.registry_events {
        let contextual = contextual_registry_key(&event.key);
        add(
            output,
            "registry_key",
            &event.key,
            event.observed_at_ms,
            contextual,
            contextual,
            IocSource {
                kind: "registry_event".to_string(),
                pid: Some(event.pid),
                artifact: event.source.clone(),
                evidence_id: Some(event.evidence_id.clone()),
            },
        );
    }
}

fn extract_network_iocs(run: &NormalizedRun, output: &mut Vec<Candidate>) {
    for event in &run.network_events {
        let source = IocSource {
            kind: "network_event".to_string(),
            pid: Some(event.pid),
            artifact: event.source.clone(),
            evidence_id: Some(event.evidence_id.clone()),
        };
        if let Some(domain) = event
            .domain
            .as_deref()
            .filter(|domain| valid_domain(domain))
        {
            let contextual = contextual_domain(domain);
            add(
                output,
                "domain",
                domain,
                event.observed_at_ms,
                contextual,
                contextual,
                source.clone(),
            );
            if let Some(port) = event.remote_port {
                add_endpoint(
                    output,
                    domain,
                    port,
                    event.observed_at_ms,
                    contextual,
                    source.clone(),
                );
            }
        }
        for (address, port, local) in [
            (&event.local_address, event.local_port, true),
            (&event.remote_address, event.remote_port, false),
        ] {
            let Some(ip) = parse_ip_from_value(address) else {
                continue;
            };
            let contextual = local || contextual_ip(ip);
            add_ip_with_context(output, ip, event.observed_at_ms, contextual, source.clone());
            if let Some(port) = port {
                add_endpoint(
                    output,
                    &ip.to_string(),
                    port,
                    event.observed_at_ms,
                    contextual,
                    source.clone(),
                );
            }
        }
    }
}

fn add(
    output: &mut Vec<Candidate>,
    ioc_type: &str,
    value: &str,
    observed_at_ms: u64,
    contextual: bool,
    likely_benign: bool,
    source: IocSource,
) {
    let value = value.trim().trim_matches(['"', '\'', ',', ';']);
    if value.is_empty() {
        return;
    }
    output.push(Candidate {
        ioc_type: ioc_type.to_string(),
        value: value.to_string(),
        normalized_value: normalize_value(ioc_type, value),
        observed_at_ms,
        contextual,
        likely_benign,
        source,
    });
}

fn add_ip(output: &mut Vec<Candidate>, ip: IpAddr, time: u64, source: IocSource) {
    add_ip_with_context(output, ip, time, contextual_ip(ip), source);
}

fn add_ip_with_context(
    output: &mut Vec<Candidate>,
    ip: IpAddr,
    time: u64,
    contextual: bool,
    source: IocSource,
) {
    let ioc_type = match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    };
    add(
        output,
        ioc_type,
        &ip.to_string(),
        time,
        contextual,
        contextual,
        source,
    );
}

fn add_endpoint(
    output: &mut Vec<Candidate>,
    host: &str,
    port: u16,
    time: u64,
    contextual: bool,
    source: IocSource,
) {
    let endpoint = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    add(
        output,
        "network_endpoint",
        &endpoint,
        time,
        contextual,
        contextual,
        source,
    );
}

fn source(kind: &str, pid: Option<u32>, observation: &ProcessObservation) -> IocSource {
    IocSource {
        kind: kind.to_string(),
        pid,
        artifact: observation.source.clone(),
        evidence_id: Some(observation.evidence_id.clone()),
    }
}

fn normalize_value(ioc_type: &str, value: &str) -> String {
    match ioc_type {
        "domain" | "process_image" | "file_path" | "registry_key" | "network_endpoint" => value
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase(),
        "url" => normalize_url(value),
        "sha256" | "sha1" | "md5" | "ipv4" | "ipv6" => value.to_ascii_lowercase(),
        _ => value.to_string(),
    }
}

fn normalize_url(value: &str) -> String {
    let value = value.trim_end_matches(['.', ',', ';', ')', ']', '}']);
    let Some((scheme, rest)) = value.split_once("://") else {
        return value.to_string();
    };
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    format!(
        "{}://{}{}",
        scheme.to_ascii_lowercase(),
        rest[..host_end].to_ascii_lowercase(),
        &rest[host_end..]
    )
}

fn extract_urls(value: &str) -> Vec<String> {
    let mut output = Vec::new();
    for prefix in ["http://", "https://"] {
        let mut offset = 0;
        let lower = value.to_ascii_lowercase();
        while let Some(index) = lower[offset..].find(prefix) {
            let start = offset + index;
            let end = value[start..]
                .find(|character: char| {
                    character.is_whitespace() || matches!(character, '"' | '\'' | '<' | '>')
                })
                .map(|length| start + length)
                .unwrap_or(value.len());
            let url = value[start..end].trim_end_matches(['.', ',', ';', ')', ']', '}']);
            if url.len() > prefix.len() {
                output.push(url.to_string());
            }
            offset = end.max(start + prefix.len());
            if offset >= value.len() {
                break;
            }
        }
    }
    output.sort();
    output.dedup();
    output
}

fn extract_domains(value: &str) -> Vec<String> {
    let mut output = extract_urls(value)
        .iter()
        .filter_map(|url| url_domain(url).map(str::to_string))
        .filter(|domain| valid_domain(domain))
        .collect::<Vec<_>>();
    for token in tokens(value) {
        let candidate = token
            .strip_prefix("http://")
            .or_else(|| token.strip_prefix("https://"))
            .unwrap_or(token)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .trim_end_matches('.');
        if valid_domain(candidate) {
            output.push(candidate.to_string());
        }
    }
    output.sort_by_key(|value| value.to_ascii_lowercase());
    output.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    output
}

fn extract_ips(value: &str) -> Vec<IpAddr> {
    let mut output = tokens(value)
        .filter_map(parse_ip_from_value)
        .collect::<Vec<_>>();
    output.sort();
    output.dedup();
    output
}

fn extract_paths(value: &str) -> Vec<String> {
    let mut output = tokens(value)
        .filter(|token| looks_like_path(token))
        .map(|token| token.trim_matches(['"', '\'', ',', ';']).to_string())
        .collect::<Vec<_>>();
    output.sort_by_key(|value| value.to_ascii_lowercase());
    output.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    output
}

fn tokens(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
                )
        })
        .filter(|token| !token.is_empty())
}

fn url_domain(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    if host.starts_with('[') {
        return None;
    }
    Some(host.split(':').next().unwrap_or(host))
}

fn valid_domain(value: &str) -> bool {
    if value.len() > 253 || !value.contains('.') || value.parse::<IpAddr>().is_ok() {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".json", ".txt", ".etl", ".pcapng",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn parse_ip_from_value(value: &str) -> Option<IpAddr> {
    let value = value
        .trim()
        .trim_matches(['"', '\'', '(', ')', '[', ']', ',', ';'])
        .split_whitespace()
        .next()?;
    if let Ok(ip) = value.parse() {
        return Some(ip);
    }
    if value.matches(':').count() == 1 {
        return value.rsplit_once(':')?.0.parse().ok();
    }
    let value = value
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = value.split(['/', '?', '#']).next()?;
    if let Ok(ip) = host.parse() {
        return Some(ip);
    }
    if host.matches(':').count() == 1 {
        return host.rsplit_once(':')?.0.parse().ok();
    }
    None
}

fn contextual_domain(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value == "example.com"
        || value.ends_with(".example.com")
        || value.ends_with(".invalid")
        || value == "localhost"
}

fn contextual_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_link_local()
                || ip == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified() || is_ipv6_link_local(ip),
    }
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn contextual_registry_key(value: &str) -> bool {
    let value = value.replace('/', "\\").to_ascii_lowercase();
    value.contains("\\services\\bam\\state\\usersettings\\")
        || value.starts_with("hklm\\system\\currentcontrolset\\services\\tcpip\\parameters")
}

fn is_windows_system_binary(value: &str) -> bool {
    let value = value.replace('/', "\\").to_ascii_lowercase();
    value.starts_with("c:\\windows\\system32\\")
        || value.starts_with("c:\\windows\\syswow64\\")
        || value.starts_with(r"\??\c:\windows\system32\")
}

fn looks_like_path(value: &str) -> bool {
    let value = value.trim_matches(['"', '\'']);
    (value.len() >= 3
        && value.as_bytes().get(1) == Some(&b':')
        && matches!(value.as_bytes().get(2), Some(b'\\' | b'/')))
        || value.starts_with(r"\\")
        || value.starts_with(r"\??\")
}

fn meaningful_command_line(
    command_line: &str,
    urls: &[String],
    domains: &[String],
    ips: &[IpAddr],
) -> bool {
    !urls.is_empty()
        || !domains.is_empty()
        || !ips.is_empty()
        || has_suspicious_argument(command_line)
        || command_line.split_whitespace().next().is_some_and(|value| {
            let value = value.trim_matches('"').to_ascii_lowercase();
            value.ends_with(".exe")
                || value.ends_with(".bat")
                || value.ends_with(".cmd")
                || value.ends_with(".ps1")
        })
}

fn has_suspicious_argument(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "-encodedcommand",
        "-enc ",
        "frombase64string",
        "downloadstring",
        "invoke-expression",
        " /create ",
        "regsvr32",
        "rundll32",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn extracts_expected_command_line_network_values() {
        let command =
            r#"curl.exe http://example.com/telemetry http://1.1.1.1:81/ foxhole-telemetry.invalid"#;
        assert!(extract_urls(command).contains(&"http://example.com/telemetry".to_string()));
        assert!(extract_domains(command).contains(&"example.com".to_string()));
        assert!(extract_domains(command).contains(&"foxhole-telemetry.invalid".to_string()));
        assert!(extract_ips(command).contains(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn context_controls_keep_but_classify_test_values() {
        assert!(contextual_domain("example.com"));
        assert!(contextual_domain("foxhole-telemetry.invalid"));
        assert!(contextual_ip("127.0.0.1".parse().unwrap()));
        assert!(!contextual_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn duplicate_indicators_merge_time_range_and_all_provenance() {
        let mut run = empty_run();
        run.network_events = vec![dns_event("network:0", 10), dns_event("network:1", 25)];
        let report = extract_iocs(&run, "normalized-hash");
        let domain = report
            .indicators
            .iter()
            .find(|indicator| {
                indicator.ioc_type == "domain" && indicator.normalized_value == "example.com"
            })
            .expect("deduplicated domain");
        assert_eq!((domain.first_seen_ms, domain.last_seen_ms), (10, 25));
        assert_eq!(domain.sources.len(), 2);
        assert!(domain.contextual && domain.likely_benign);
    }

    #[test]
    fn target_created_file_hashes_become_sha256_indicators() {
        let mut run = empty_run();
        run.file_events.push(FileEvent {
            evidence_id: "file:7".to_string(),
            pid: 7,
            path: r"C:\Users\Foxhole\Downloads\payload.exe".to_string(),
            action: "executable_create".to_string(),
            size_bytes: Some(123),
            sha256: Some("ab".repeat(32)),
            hash_source: Some("sysmon_event".to_string()),
            observed_at_ms: 22,
            source: "filesystem-events.json".to_string(),
            association: ProcessAssociation {
                pid: 7,
                image: "downloader.exe".to_string(),
                parent_pid: None,
                inferred: false,
                method: "explicit_pid".to_string(),
            },
            raw: json!({}),
        });
        let report = extract_iocs(&run, "normalized-hash");
        let indicator = report
            .indicators
            .iter()
            .find(|indicator| {
                indicator.ioc_type == "sha256" && indicator.normalized_value == "ab".repeat(32)
            })
            .expect("created file SHA-256 IOC");
        assert!(indicator.sources.iter().any(|source| {
            source.kind == "created_file_hash"
                && source.artifact.ends_with("payload.exe")
                && source.evidence_id.as_deref() == Some("file:7")
        }));
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

    fn dns_event(evidence_id: &str, observed_at_ms: u64) -> NetworkEvent {
        NetworkEvent {
            evidence_id: evidence_id.to_string(),
            pid: 1,
            protocol: "dns".to_string(),
            direction: "outbound".to_string(),
            local_address: String::new(),
            local_port: None,
            remote_address: String::new(),
            remote_port: Some(53),
            domain: Some("example.com".to_string()),
            state: "attempt".to_string(),
            observed_at_ms,
            source: "network-events.json".to_string(),
            association: ProcessAssociation {
                pid: 1,
                image: "sample.exe".to_string(),
                parent_pid: None,
                inferred: false,
                method: "explicit_pid".to_string(),
            },
            raw: json!({"domain": "example.com"}),
        }
    }
}
