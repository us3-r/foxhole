use super::model::*;
use crate::detection::{validation::*, *};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

pub fn import(run: &NormalizedRun, output: &Path) -> DetectionReport {
    let mut report = DetectionReport::default();
    if run
        .raw
        .get("guest_result")
        .and_then(|v| v.get("warnings"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|s| {
                    s.contains("detection")
                        || s.contains("target-written file")
                        || s.contains("target file collection")
                })
        })
    {
        report
            .warnings
            .push(warning("guest_detection_collection_incomplete"));
    }
    if let Some(config) = run
        .raw
        .get("guest_result")
        .and_then(|v| v.get("detection_config"))
    {
        match serde_json::from_value::<DetectionConfig>(config.clone()) {
            Ok(config)
                if config.schema_version == 1
                    && config
                        .stages()
                        .iter()
                        .all(|(_, s)| s.limits.validate().is_ok()) =>
            {
                report.effective_config = config.public()
            }
            _ => report
                .warnings
                .push(warning("invalid_detection_configuration")),
        }
    }
    report.behavioral_status = if !report.effective_config.behavioral {
        Status::Disabled
    } else if telemetry_complete(run) {
        Status::Completed
    } else {
        Status::Partial
    };
    if report.behavioral_status == Status::Partial {
        report
            .warnings
            .push(warning("telemetry_incomplete_absence_is_not_safety"));
    }
    let mut aliases = BTreeMap::new();
    if let Some(hash) = run
        .target
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|h| sha256(h))
    {
        aliases.insert(
            "primary".to_string(),
            format!("sha256:{}", hash.to_ascii_lowercase()),
        );
    }
    for a in &run.artifacts {
        if a.hash_verified && a.exists {
            aliases.insert(a.relative_path.clone(), a.evidence_id.clone());
        }
    }
    let available = aliases.keys().cloned().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    let mut artifacts = run.artifacts.iter().collect::<Vec<_>>();
    artifacts.sort_by(|a, b| (&a.relative_path, &a.sha256).cmp(&(&b.relative_path, &b.sha256)));
    for artifact in artifacts {
        let Some(scanner) = artifact
            .kind
            .strip_prefix("detection_")
            .filter(|s| ["yara", "pe", "capa", "network"].contains(s))
        else {
            continue;
        };
        let config = report
            .effective_config
            .stages()
            .into_iter()
            .find(|(name, _)| *name == scanner)
            .map(|(_, s)| s.clone())
            .unwrap_or_default();
        total = total.saturating_add(artifact.size_bytes);
        let parsed = (|| {
            if total > report.effective_config.max_total_output_bytes
                || !artifact.hash_verified
                || !artifact.exists
                || !relative_path(&artifact.relative_path)
                || artifact.size_bytes > config.limits.output_bytes
            {
                return Err("unverified_or_oversized_scanner_artifact");
            }
            let path = output.join(&artifact.relative_path);
            let pins = crate::artifact::pin_safe_directory_tree(
                path.parent().ok_or("invalid_scanner_artifact_path")?,
                false,
            )
            .map_err(|_| "unsafe_scanner_artifact_path")?;
            let file = crate::artifact::open_safe_regular_file(&path)
                .map_err(|_| "unsafe_scanner_artifact")?;
            let mut bytes = vec![];
            file.take(config.limits.output_bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "scanner_artifact_read_failed")?;
            drop(pins);
            use sha2::{Digest, Sha256};
            if format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256 {
                return Err("scanner_artifact_changed");
            }
            let value = bounded_json(&bytes, &config.limits)?;
            let target = value
                .get("target")
                .and_then(serde_json::Value::as_str)
                .ok_or("missing_scanner_target")?;
            let (hash, size) = if target == "primary" {
                (
                    run.target
                        .get("sha256")
                        .and_then(serde_json::Value::as_str)
                        .ok_or("missing_host_target_hash")?,
                    run.target
                        .get("size_bytes")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or("missing_host_target_size")?,
                )
            } else {
                let a = run
                    .artifacts
                    .iter()
                    .find(|a| a.relative_path == target && a.hash_verified)
                    .ok_or("unknown_scanner_target")?;
                (a.sha256.as_str(), a.size_bytes)
            };
            let mut result = parse_result(
                &bytes,
                scanner,
                TrustedTarget {
                    id: target,
                    sha256: hash,
                    size,
                },
                &config,
                &available,
            )?;
            if !seen.insert((scanner.to_string(), target.to_string())) {
                return Err("duplicate_scanner_execution");
            }
            result.original = Some(OriginalResult {
                path: artifact.relative_path.clone(),
                sha256: artifact.sha256.clone(),
            });
            let remap = |ids: &mut Vec<String>| {
                *ids = ids
                    .iter()
                    .filter_map(|id| aliases.get(id).cloned())
                    .chain(std::iter::once(artifact.evidence_id.clone()))
                    .collect();
                ids.sort();
                ids.dedup();
            };
            remap(&mut result.evidence_ids);
            for f in &mut result.findings {
                remap(&mut f.evidence_ids);
            }
            for p in &mut result.packets {
                remap(&mut p.evidence_ids);
            }
            Ok(result)
        })();
        match parsed {
            Ok(result) => report.stages.push(result),
            Err(code) => {
                let mut failure = ScannerResult::empty(
                    scanner,
                    &artifact.relative_path,
                    &artifact.sha256,
                    Status::InvalidOutput,
                    config.limits,
                    code,
                );
                failure.evidence_ids = vec![artifact.evidence_id.clone()];
                report.stages.push(failure);
            }
        }
    }
    for (name, config) in report.effective_config.stages() {
        report.coverage.insert(
            name.to_string(),
            if !config.enabled {
                Status::Disabled
            } else if let Some(status) = report
                .stages
                .iter()
                .filter(|s| s.scanner == name)
                .map(|s| s.status)
                .max_by_key(|s| match s {
                    Status::InvalidOutput => 7,
                    Status::Failed => 6,
                    Status::TimedOut => 5,
                    Status::Unavailable => 4,
                    Status::Partial => 3,
                    Status::Skipped => 2,
                    Status::Disabled => 1,
                    Status::Completed => 0,
                })
            {
                status
            } else {
                Status::Unavailable
            },
        );
        if !report.stages.iter().any(|s| s.scanner == name) {
            let hash = run
                .target
                .get("sha256")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if !sha256(hash) {
                report.warnings.push(warning(&format!(
                    "{name}_unavailable_without_verified_target"
                )));
                continue;
            }
            let mut result = ScannerResult::empty(
                name,
                "primary",
                hash,
                if config.enabled {
                    Status::Unavailable
                } else {
                    Status::Disabled
                },
                config.limits.clone(),
                if config.enabled {
                    "no_collected_scanner_result"
                } else {
                    "stage_disabled"
                },
            );
            result.evidence_ids = aliases.get("primary").cloned().into_iter().collect();
            report.stages.push(result);
        }
    }
    report
        .stages
        .sort_by(|a, b| (&a.scanner, &a.target).cmp(&(&b.scanner, &b.target)));
    summarize_network(run, &mut report);
    report
}

fn summarize_network(run: &NormalizedRun, report: &mut DetectionReport) {
    type Key = (String, String, String, u16, u16);
    let mut index = BTreeMap::<Key, Vec<(u64, &NetworkEvent)>>::new();
    for n in &run.network_events {
        if n.association.inferred || n.pid == 0 {
            continue;
        }
        let Some(time) = n
            .raw
            .get("capture_epoch_ms")
            .and_then(serde_json::Value::as_u64)
            .and_then(|t| t.checked_add(n.observed_at_ms))
        else {
            continue;
        };
        let (Some(local), Some(remote)) = (n.local_port, n.remote_port) else {
            continue;
        };
        index
            .entry((
                n.protocol.clone(),
                n.local_address.clone(),
                n.remote_address.clone(),
                local,
                remote,
            ))
            .or_default()
            .push((time, n));
    }
    for values in index.values_mut() {
        values.sort_by(|a, b| (a.0, &a.1.evidence_id).cmp(&(b.0, &b.1.evidence_id)));
    }
    let mut flows = BTreeMap::<(String, String), NetworkFlow>::new();
    let mut truncated = false;
    let mut checks = 0usize;
    for stage in &report.stages {
        for packet in &stage.packets {
            let flow = flows
                .entry((stage.target_sha256.clone(), packet.flow.clone()))
                .or_insert_with(|| NetworkFlow {
                    capture_sha256: stage.target_sha256.clone(),
                    flow: packet.flow.clone(),
                    source: packet.source.clone(),
                    destination: packet.destination.clone(),
                    source_port: packet.source_port,
                    destination_port: packet.destination_port,
                    protocol: packet.protocol.clone(),
                    first_timestamp_us: packet.timestamp_us,
                    last_timestamp_us: packet.timestamp_us,
                    packet_count: 0,
                    captured_bytes: 0,
                    evidence_ids: packet.evidence_ids.clone(),
                });
            flow.packet_count += 1;
            flow.captured_bytes = flow.captured_bytes.saturating_add(packet.bytes);
            if let Some(time) = packet.timestamp_us {
                flow.first_timestamp_us = Some(flow.first_timestamp_us.unwrap_or(time).min(time));
                flow.last_timestamp_us = Some(flow.last_timestamp_us.unwrap_or(time).max(time));
            }
            let Some(time) = packet.timestamp_us.map(|t| t / 1000) else {
                continue;
            };
            // A shared remote IP is insufficient: exact endpoints, ports, protocol, clock
            // window and an unambiguous process lifetime are required. Association remains inferred.
            let Some(values) = index.get(&(
                packet.protocol.clone(),
                packet.source.clone(),
                packet.destination.clone(),
                packet.source_port,
                packet.destination_port,
            )) else {
                continue;
            };
            let lower = values.partition_point(|(t, _)| *t < time.saturating_sub(1000));
            let upper = values.partition_point(|(t, _)| *t <= time.saturating_add(1000));
            checks = checks.saturating_add(upper - lower);
            if checks > 1_000_000 || report.packet_correlations.len() >= 4096 || upper - lower > 256
            {
                truncated = true;
                continue;
            }
            let matches = &values[lower..upper];
            let identities = matches
                .iter()
                .map(|(_, n)| {
                    (
                        n.pid,
                        n.raw
                            .get("process_guid")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default(),
                    )
                })
                .collect::<BTreeSet<_>>();
            if identities.len() == 1 {
                let mut ids = packet.evidence_ids.clone();
                ids.extend(matches.iter().map(|(_, n)| n.evidence_id.clone()));
                ids.sort();
                ids.dedup();
                report.packet_correlations.push(PacketCorrelation {
                    capture_sha256: stage.target_sha256.clone(),
                    packet_id: packet.id.clone(),
                    flow: packet.flow.clone(),
                    pid: identities.first().map_or(0, |i| i.0),
                    method: "inferred_exact_five_tuple_and_clock_window".into(),
                    confidence: 70,
                    evidence_ids: ids,
                });
            }
        }
    }
    if truncated {
        report
            .warnings
            .push(warning("packet_process_correlation_budget_exhausted"));
    }
    report.network_flows = flows.into_values().collect();
    report.packet_correlations.sort_by(|a, b| {
        (&a.capture_sha256, &a.packet_id, a.pid).cmp(&(&b.capture_sha256, &b.packet_id, b.pid))
    });
}

pub fn telemetry_complete(run: &NormalizedRun) -> bool {
    ["processes", "network", "filesystem", "registry"]
        .iter()
        .all(|name| {
            run.coverage
                .get(name)
                .and_then(|v| v.get("complete"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        })
        && run.validation_warnings.is_empty()
}
fn warning(code: &str) -> Warning {
    Warning {
        code: code.into(),
        message: code.replace('_', " "),
    }
}

pub fn scanner_findings(run: &NormalizedRun) -> Vec<Finding> {
    let mut findings = vec![];
    for stage in &run.detection.stages {
        for f in &stage.findings {
            findings.push(Finding {
                rule_id: format!("{}:{}:{}", stage.scanner, stage.target_sha256, f.id),
                severity: Severity::Informational,
                title: f.title.clone(),
                explanation: if stage.scanner == "capa" {
                    "Static capability; this does not establish that the action executed."
                } else {
                    "Deterministic scanner finding; no independent verdict score."
                }
                .into(),
                evidence: f
                    .evidence_ids
                    .iter()
                    .map(|id| EvidenceReference {
                        evidence_id: id.clone(),
                        kind: "scanner_artifact".into(),
                        pid: 0,
                        process_image: String::new(),
                        parent_pid: None,
                        observed_at_ms: 0,
                        source_artifact: stage
                            .original
                            .as_ref()
                            .map(|v| v.path.clone())
                            .unwrap_or_default(),
                        exact_value: format!("{} {}", stage.target_sha256, f.rule),
                        inferred: false,
                    })
                    .collect(),
                confidence: 0.8,
                score_contribution: 0,
                details: Some(FindingDetails {
                    version: "1".into(),
                    source: stage.scanner.clone(),
                    namespace: f.namespace.clone(),
                    file_sha256: Some(stage.target_sha256.clone()),
                    attack: f.attack.clone(),
                    required_events: vec![],
                    window_ms: None,
                    association: "static".into(),
                    false_positive_guidance:
                        "A rule or capability match is context, not proof of malicious execution."
                            .into(),
                    score_group: String::new(),
                }),
            });
        }
    }
    let mut by_id = BTreeMap::<String, Finding>::new();
    for finding in findings {
        if let Some(existing) = by_id.get_mut(&finding.rule_id) {
            existing.evidence.extend(finding.evidence);
            existing.evidence.sort_by(|a, b| {
                (&a.evidence_id, &a.source_artifact).cmp(&(&b.evidence_id, &b.source_artifact))
            });
            existing
                .evidence
                .dedup_by(|a, b| a.evidence_id == b.evidence_id);
        } else {
            by_id.insert(finding.rule_id.clone(), finding);
        }
    }
    by_id.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fs;
    fn normalized() -> NormalizedRun {
        serde_json::from_value(json!({"schema_version":"1.0","run_id":"fixture","target":{"sha256":format!("{:x}",Sha256::digest(include_bytes!("../../tests/fixtures/detection/benign.pe.bin"))),"size_bytes":1536},"target_hashes":[],"sandbox":{},"execution":{"pid":1},"coverage":{},"limitations":[],"raw_event_counts":{"process":0,"network":0,"filesystem":0,"registry":0},"normalized_event_counts":{"process":0,"network":0,"filesystem":0,"registry":0},"processes":[],"file_events":[],"registry_events":[],"network_events":[],"artifacts":[],"validation_warnings":[],"source_paths":[],"raw":{}})).unwrap()
    }
    #[test]
    fn packet_process_links_require_exact_tuple_clock_and_unambiguous_identity() {
        let mut run = normalized();
        let stage: ScannerResult =
            serde_json::from_str(include_str!("../../tests/fixtures/detection/network.json"))
                .unwrap();
        let packet = stage.packets[1].clone();
        let mut report = DetectionReport {
            stages: vec![stage],
            ..Default::default()
        };
        let event = NetworkEvent {
            evidence_id: "network:direct".into(),
            pid: 42,
            protocol: packet.protocol.clone(),
            direction: "outbound".into(),
            local_address: packet.source.clone(),
            local_port: Some(packet.source_port),
            remote_address: packet.destination.clone(),
            remote_port: Some(packet.destination_port),
            domain: None,
            state: "connected".into(),
            observed_at_ms: 1,
            source: "fixture".into(),
            association: ProcessAssociation {
                pid: 42,
                parent_pid: None,
                image: "fixture.exe".into(),
                inferred: false,
                method: "sysmon".into(),
            },
            raw: json!({"capture_epoch_ms":packet.timestamp_us.unwrap()/1000-1,"process_guid":"one"}),
        };
        run.network_events.push(event.clone());
        summarize_network(&run, &mut report);
        assert_eq!(report.packet_correlations.len(), 1);
        assert_eq!(report.packet_correlations[0].pid, 42);
        assert!(!report.network_flows.is_empty());
        let expected = report.packet_correlations.clone();
        report.packet_correlations.clear();
        run.network_events.push(event.clone());
        summarize_network(&run, &mut report);
        assert_eq!(report.packet_correlations, expected);
        report.packet_correlations.clear();
        run.network_events[1].raw["process_guid"] = "reused".into();
        summarize_network(&run, &mut report);
        assert!(report.packet_correlations.is_empty());
        for mode in 0..4 {
            run.network_events = vec![event.clone()];
            match mode {
                0 => run.network_events[0].remote_port = Some(9),
                1 => run.network_events[0].raw = json!({}),
                2 => run.network_events[0].observed_at_ms = 999999,
                _ => run.network_events[0].association.inferred = true,
            };
            summarize_network(&run, &mut report);
            assert!(report.packet_correlations.is_empty());
        }
    }
    #[test]
    fn unavailable_coverage_and_same_hash_finding_duplicates_are_explicit() {
        let mut run = normalized();
        run.coverage = json!({"processes":{"complete":true},"network":{"complete":true},"filesystem":{"complete":true},"registry":{"complete":true}});
        run.detection
            .coverage
            .insert("yara".into(), Status::Unavailable);
        let verdict = super::super::verdict::build_verdict(
            &run,
            "hash",
            &super::super::VerdictConfig::default(),
        );
        assert_eq!(verdict.verdict, "inconclusive");
        let stage: ScannerResult =
            serde_json::from_str(include_str!("../../tests/fixtures/detection/yara.json")).unwrap();
        run.detection.stages = vec![stage.clone(), stage];
        run.detection.stages[1].target = "extracted-files/copy.exe".into();
        run.detection.stages[1].findings[0].evidence_ids = vec!["artifact:copy".into()];
        let findings = scanner_findings(&run);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.len(), 2);
        run.detection.stages.reverse();
        assert_eq!(scanner_findings(&run), findings);
    }
    fn golden(name: &str, value: &impl serde::Serialize) {
        let mut data = serde_json::to_vec_pretty(value).unwrap();
        data.push(b'\n');
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/detection")
            .join(name);
        if std::env::var("FOXHOLE_UPDATE_DETECTION_GOLDENS").as_deref() == Ok("1") {
            fs::write(&path, &data).unwrap();
        }
        assert!(
            fs::read(&path).unwrap() == data,
            "golden differs: {name}; update deliberately and review the text diff"
        );
    }
    #[test]
    fn all_real_scanner_fixtures_import_with_valid_provenance_and_stable_reports() {
        let root =
            std::env::temp_dir().join(format!("foxhole-detection-fixture-{}", std::process::id()));
        fs::create_dir_all(root.join("detection")).unwrap();
        fs::create_dir_all(root.join("extracted-files")).unwrap();
        let mut run = normalized();
        let mut config = DetectionConfig::default();
        let capture = include_bytes!("../../tests/fixtures/detection/network.pcapng");
        fs::write(root.join("extracted-files/capture.pcapng"), capture).unwrap();
        run.artifacts.push(Artifact {
            evidence_id: "artifact:capture".into(),
            relative_path: "extracted-files/capture.pcapng".into(),
            kind: "packet_capture_pcapng".into(),
            size_bytes: capture.len() as u64,
            sha256: format!("{:x}", Sha256::digest(capture)),
            exists: true,
            hash_verified: true,
            source: "fixture".into(),
            raw: json!({}),
        });
        for name in ["yara", "pe", "capa", "network"] {
            let bytes = fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("tests/fixtures/detection/{name}.json")),
            )
            .unwrap();
            let mut result: ScannerResult = serde_json::from_slice(&bytes).unwrap();
            if name == "network" {
                result.target = "extracted-files/capture.pcapng".into();
                result.evidence_ids = vec![result.target.clone()];
                for p in &mut result.packets {
                    p.evidence_ids = result.evidence_ids.clone();
                }
                for f in &mut result.findings {
                    f.evidence_ids = result.evidence_ids.clone();
                }
            }
            let stage = match name {
                "yara" => &mut config.yara,
                "pe" => &mut config.pe,
                "capa" => &mut config.capa,
                _ => &mut config.network,
            };
            if let Some(pack) = result.rule_packs.first() {
                stage.rules = Some(RulePack {
                    id: pack.id.clone(),
                    version: pack.version.clone(),
                    path: String::new(),
                    sha256: pack.sha256.clone(),
                });
            }
            let bytes = serde_json::to_vec(&result).unwrap();
            let relative = format!("detection/{name}.json");
            fs::write(root.join(&relative), &bytes).unwrap();
            run.artifacts.push(Artifact {
                evidence_id: format!("artifact:{name}"),
                relative_path: relative,
                kind: format!("detection_{name}"),
                size_bytes: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
                exists: true,
                hash_verified: true,
                source: "fixture".into(),
                raw: json!({}),
            });
        }
        run.raw.insert(
            "guest_result".into(),
            json!({"detection_config":config.public()}),
        );
        run.detection = import(&run, &root);
        assert_eq!(run.detection.stages.len(), 4);
        assert!(
            run.detection
                .stages
                .iter()
                .all(|s| matches!(s.status, Status::Completed | Status::Partial)),
            "{:?}",
            run.detection
                .stages
                .iter()
                .map(|s| (&s.scanner, &s.warnings))
                .collect::<Vec<_>>()
        );
        let hash = super::super::normalized_input_sha256(&run).unwrap();
        let verdict = super::super::verdict::build_verdict(
            &run,
            &hash,
            &super::super::VerdictConfig::default(),
        );
        let iocs = super::super::ioc::extract_iocs(&run, &hash);
        super::super::publication::validate(&run, &verdict, &iocs).unwrap();
        assert_eq!(verdict.score, 0);
        assert_eq!(verdict.verdict, "inconclusive");
        assert!(iocs.indicators.iter().any(|i| i.ioc_type == "domain"
            && i.normalized_value == "example.com"
            && i.contextual));
        golden("normalized.json", &run);
        golden("findings.json", &verdict.findings);
        golden("iocs.json", &iocs);
        golden("verdict.json", &verdict);
        golden(
            "web-data.json",
            &super::super::publication::public_value(
                &json!({"normalized":run,"verdict":verdict,"iocs":iocs}),
            )
            .unwrap(),
        );
        let mut bad = verdict.clone();
        bad.findings[0].evidence[0].evidence_id = "unknown".into();
        assert!(super::super::publication::validate(&run, &bad, &iocs).is_err());
        let mut reordered = run.clone();
        reordered.artifacts.reverse();
        let other = import(&reordered, &root);
        assert_eq!(run.detection, other);
        fs::write(root.join("detection/yara.json"), b"malformed").unwrap();
        let bad = import(&run, &root);
        assert!(
            bad.stages
                .iter()
                .any(|s| s.scanner == "yara" && s.status == Status::InvalidOutput)
        );
        assert!(
            bad.stages
                .iter()
                .any(|s| s.scanner == "capa" && s.status == Status::Completed)
        );
        for a in &run.artifacts {
            fs::remove_file(root.join(&a.relative_path)).unwrap();
        }
        fs::remove_dir(root.join("detection")).unwrap();
        fs::remove_dir(root.join("extracted-files")).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
