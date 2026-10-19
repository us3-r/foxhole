//! Typed import of bounded, manifest-verified Sysmon records. Legacy arrays remain available.
use super::model::*;
use super::process_index::AssociationBudget;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    #[serde(default = "schema_one")]
    schema_version: u32,
    #[serde(default)]
    started_unix_ms: Option<u64>,
    source: String,
    event_id: u32,
    record_id: u64,
    time_utc: String,
    #[serde(default)]
    observed_at_ms: Option<u64>,
    data: BTreeMap<String, serde_json::Value>,
}
fn schema_one() -> u32 {
    1
}

pub fn import(
    run: &mut NormalizedRun,
    root: &Path,
    budget: &AssociationBudget,
) -> std::io::Result<()> {
    let mut process_indices = BTreeMap::new();
    for (index, process) in run.processes.iter().enumerate() {
        process_indices.entry(process.pid).or_insert(index);
    }
    let artifacts = run
        .artifacts
        .iter()
        .filter(|a| a.kind == "guest_telemetry_events")
        .cloned()
        .collect::<Vec<_>>();
    for artifact in artifacts {
        let result = (|| {
            if !artifact.hash_verified
                || !crate::detection::validation::relative_path(&artifact.relative_path)
            {
                return Err("unverified structured telemetry");
            }
            let path = root.join(&artifact.relative_path);
            let _pins = crate::artifact::pin_safe_directory_tree(
                path.parent().ok_or("invalid telemetry path")?,
                false,
            )
            .map_err(|_| "unsafe telemetry path")?;
            let mut bytes = vec![];
            crate::artifact::open_safe_regular_file(&path)
                .map_err(|_| "unsafe telemetry file")?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "telemetry read failed")?;
            use sha2::{Digest, Sha256};
            if format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256 {
                return Err("telemetry artifact changed");
            }
            let limits = crate::detection::Limits {
                output_bytes: 16 * 1024 * 1024,
                string_bytes: 4096,
                ..Default::default()
            };
            let value = crate::detection::validation::bounded_json(&bytes, &limits)?;
            // WFP rows carry their own normalized network fields. Validate the shared
            // bounded JSON first, then strictly decode only the Sysmon rows imported here.
            let values = value.as_array().ok_or("unsupported telemetry schema")?;
            if values.len() > 10000 {
                return Err("telemetry row limit");
            }
            // Preserve guest-wide WFP attempts for the HTML evidence view. Keep
            // unattributed rows out of target-only behavioral scoring.
            for row in values.iter().filter(|row| {
                row.get("source").and_then(|v| v.as_str()) == Some("windows_filtering_platform")
            }) {
                if row
                    .get("schema_version")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1)
                    != 1
                {
                    return Err("unsupported WFP telemetry schema version");
                }
                let mut event = row.clone();
                event["source_artifact"] = artifact.relative_path.clone().into();
                event["artifact_evidence_id"] = artifact.evidence_id.clone().into();
                if run.network_attempts.len() < 10000 {
                    run.network_attempts.push(event);
                } else {
                    return Err("WFP attempt view limit");
                }
            }
            let rows: Vec<Row> = values
                .iter()
                .filter(|row| row.get("source").and_then(|v| v.as_str()) == Some("sysmon"))
                .map(|row| {
                    serde_json::from_value(row.clone()).map_err(|_| "unsupported telemetry schema")
                })
                .collect::<Result<_, _>>()?;
            if rows.len() > 10000 {
                return Err("telemetry row limit");
            }
            let mut ids = std::collections::BTreeSet::new();
            for row in rows {
                if row.schema_version != 1 {
                    return Err("unsupported telemetry schema version");
                }
                if row.source != "sysmon" {
                    continue;
                }
                if !ids.insert(row.record_id) {
                    return Err("duplicate telemetry record ID");
                }
                let Some(time) = row.observed_at_ms.filter(|t| *t > 0) else {
                    continue;
                };
                if row.time_utc.len() > 64 {
                    return Err("invalid telemetry timestamp");
                }
                let get = |key: &str| {
                    row.data
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(key))
                        .and_then(|(_, v)| v.as_str())
                        .unwrap_or_default()
                };
                let pid = get(if [8, 10].contains(&row.event_id) {
                    "SourceProcessId"
                } else {
                    "ProcessId"
                })
                .parse::<u32>()
                .unwrap_or(0);
                let Some(&index) = process_indices.get(&pid) else {
                    continue;
                };
                let p = &run.processes[index];
                budget
                    .charge(p.image.len())
                    .map_err(|_| "process association image byte budget exceeded")?;
                let association = ProcessAssociation {
                    pid,
                    image: p.image.clone(),
                    parent_pid: p.parent_pid,
                    inferred: false,
                    method: "sysmon_process_guid".into(),
                };
                let id = format!("sysmon:{}:{}", &artifact.sha256[..16], row.record_id);
                let image = get(if [8, 10].contains(&row.event_id) {
                    "SourceImage"
                } else {
                    "Image"
                });
                let guid = get(if [8, 10].contains(&row.event_id) {
                    "SourceProcessGUID"
                } else {
                    "ProcessGuid"
                });
                let raw = serde_json::json!({"artifact_evidence_id":artifact.evidence_id,"process_guid":guid,"record_id":row.record_id,"capture_epoch_ms":row.started_unix_ms});
                match row.event_id {
                    1 | 5 => {
                        let parent = get("ParentProcessId").parse().ok().or(p.parent_pid);
                        run.processes[index].observations.push(ProcessObservation {
                            evidence_id: id,
                            pid,
                            parent_pid: parent,
                            image: image.into(),
                            command_line: if row.event_id == 1 {
                                Some(get("CommandLine").into())
                            } else {
                                None
                            },
                            status: if row.event_id == 1 {
                                "started"
                            } else {
                                "terminated"
                            }
                            .into(),
                            observed_at_ms: time,
                            source: artifact.relative_path.clone(),
                            raw,
                        });
                    }
                    8 | 10 | 25 => {
                        let mut raw = raw;
                        raw["event_type"] = serde_json::json!(match row.event_id {
                            8 => "remote_thread",
                            10 => "process_access",
                            _ => "telemetry_tamper",
                        });
                        raw["object"] = serde_json::json!(get("TargetProcessGUID"));
                        let parent = p.parent_pid;
                        run.processes[index].observations.push(ProcessObservation {
                            evidence_id: id,
                            pid,
                            parent_pid: parent,
                            image: image.into(),
                            command_line: None,
                            status: "security_observation".into(),
                            observed_at_ms: time,
                            source: artifact.relative_path.clone(),
                            raw,
                        });
                    }
                    11 | 15 | 17 | 18 | 29 => {
                        run.file_events.push(FileEvent {
                            evidence_id: id,
                            pid,
                            path: get(if [17, 18].contains(&row.event_id) {
                                "PipeName"
                            } else {
                                "TargetFilename"
                            })
                            .into(),
                            action: match row.event_id {
                                17 => "named_pipe_create",
                                18 => "named_pipe_connect",
                                15 => "alternate_stream_create",
                                _ => "create_or_overwrite",
                            }
                            .into(),
                            size_bytes: None,
                            sha256: None,
                            hash_source: None,
                            observed_at_ms: time,
                            source: artifact.relative_path.clone(),
                            association,
                            raw,
                        });
                    }
                    13 => {
                        let key = get("TargetObject");
                        let (key, name) = key.rsplit_once('\\').unwrap_or((key, ""));
                        run.registry_events.push(RegistryEvent {
                            evidence_id: id,
                            pid,
                            key: key.into(),
                            operation: "set_value".into(),
                            value_name: Some(name.into()),
                            value_data: Some(get("Details").into()),
                            observed_at_ms: time,
                            source: artifact.relative_path.clone(),
                            association,
                            raw,
                        });
                    }
                    22 => {
                        let answers = get("QueryResults")
                            .split(';')
                            .filter_map(|v| v.trim().parse::<std::net::IpAddr>().ok())
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>();
                        let mut raw = raw;
                        raw["answers"] = serde_json::json!(answers);
                        run.network_events.push(NetworkEvent {
                            evidence_id: id,
                            pid,
                            protocol: "dns".into(),
                            direction: "outbound".into(),
                            local_address: String::new(),
                            local_port: None,
                            remote_address: get("QueryName").into(),
                            remote_port: Some(53),
                            domain: Some(get("QueryName").into()),
                            state: "answer".into(),
                            observed_at_ms: time,
                            source: artifact.relative_path.clone(),
                            association,
                            raw,
                        });
                    }
                    3 => {
                        run.network_events.push(NetworkEvent {
                            evidence_id: id,
                            pid,
                            protocol: get("Protocol").to_ascii_lowercase(),
                            direction: if get("Initiated").eq_ignore_ascii_case("true") {
                                "outbound"
                            } else {
                                "inbound"
                            }
                            .into(),
                            local_address: get("SourceIp").into(),
                            local_port: get("SourcePort").parse().ok(),
                            remote_address: get("DestinationIp").into(),
                            remote_port: get("DestinationPort").parse().ok(),
                            domain: None,
                            state: "connected".into(),
                            observed_at_ms: time,
                            source: artifact.relative_path.clone(),
                            association,
                            raw,
                        });
                    }
                    _ => (),
                }
            }
            Ok(())
        })();
        if let Err(message) = result {
            budget.check()?;
            run.validation_warnings.push(ValidationWarning {
                code: "structured_telemetry_incomplete".into(),
                source: artifact.relative_path,
                event_index: None,
                message: message.into(),
                raw: None,
            });
        }
    }
    for p in &mut run.processes {
        p.observations.sort_by(|a, b| {
            (a.observed_at_ms, &a.evidence_id).cmp(&(b.observed_at_ms, &b.evidence_id))
        });
    }
    run.file_events.sort_by(|a, b| {
        (a.observed_at_ms, &a.evidence_id).cmp(&(b.observed_at_ms, &b.evidence_id))
    });
    run.registry_events.sort_by(|a, b| {
        (a.observed_at_ms, &a.evidence_id).cmp(&(b.observed_at_ms, &b.evidence_id))
    });
    run.network_events.sort_by(|a, b| {
        (a.observed_at_ms, &a.evidence_id).cmp(&(b.observed_at_ms, &b.evidence_id))
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    #[test]
    fn structured_rows_use_indexed_pid_lookup_and_share_the_image_budget() {
        let root = std::env::temp_dir().join(format!(
            "foxhole-telemetry-index-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let mut run: NormalizedRun = serde_json::from_str(include_str!(
            "../../tests/fixtures/detection/normalized.json"
        ))
        .unwrap();
        run.processes = (1..=50_000)
            .map(|pid| Process {
                pid,
                parent_pid: None,
                image: "fixture.exe".into(),
                command_line: None,
                status: "started".into(),
                observed_at_ms: 1,
                observations: vec![],
                raw: json!({}),
            })
            .collect();
        let rows = (1..=10_000)
            .map(|id| {
                json!({"schema_version":1,"source":"sysmon","event_id":11,
            "record_id":id,"time_utc":"2020-01-01T00:00:00Z","observed_at_ms":id,
            "data":{"ProcessId":"50000","TargetFilename":"C:\\work\\file.bin"}})
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&rows).unwrap();
        let file = root.join("events.json");
        std::fs::write(&file, &bytes).unwrap();
        run.artifacts = vec![Artifact {
            evidence_id: "artifact:events".into(),
            relative_path: "events.json".into(),
            kind: "guest_telemetry_events".into(),
            size_bytes: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            exists: true,
            hash_verified: true,
            source: "fixture".into(),
            raw: json!({}),
        }];
        import(&mut run, &root, &AssociationBudget::default()).unwrap();
        assert_eq!(run.file_events.len(), 10_000);
        assert!(
            run.file_events
                .iter()
                .all(|event| event.pid == 50_000 && event.association.image == "fixture.exe")
        );
        assert!(
            run.validation_warnings.is_empty(),
            "{:?}",
            run.validation_warnings
        );
        run.file_events.clear();
        // Spend the shared budget without allocating large strings; the next
        // association must fail the import instead of becoming a warning only.
        let budget = AssociationBudget::default();
        budget.charge(64 * 1024 * 1024).unwrap();
        let error = import(&mut run, &root, &budget).unwrap_err();
        assert!(error.to_string().contains("analysis is incomplete"));
        assert!(run.file_events.is_empty());
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn structured_events_preserve_direct_associations_and_failures_are_visible() {
        let root =
            std::env::temp_dir().join(format!("foxhole-telemetry-parser-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut run: NormalizedRun = serde_json::from_str(include_str!(
            "../../tests/fixtures/detection/normalized.json"
        ))
        .unwrap();
        run.processes.push(Process {
            pid: 42,
            parent_pid: None,
            image: "fixture.exe".into(),
            command_line: None,
            status: "started".into(),
            observed_at_ms: 1,
            observations: vec![],
            raw: json!({}),
        });
        run.artifacts.clear();
        let mut rows=[8,10,25,11,15,17,18,29,13,22,3].iter().enumerate().map(|(i,id)|json!({"schema_version":1,"source":"sysmon","event_id":id,"record_id":i+1,"time_utc":"2020-01-01T00:00:00Z","observed_at_ms":100+i,"started_unix_ms":1000,"data":{"ProcessId":"42","SourceProcessId":"42","ProcessGuid":"guid-1","SourceProcessGUID":"guid-1","TargetProcessGUID":"guid-2","SourceImage":"fixture.exe","Image":"fixture.exe","TargetFilename":"C:\\work\\fixture.exe","TargetObject":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\fixture","Details":"C:\\work\\fixture.exe","PipeName":"\\\\.\\pipe\\fixture","QueryName":"example.com","QueryResults":"1.1.1.1; ::1;invalid","Protocol":"tcp","Initiated":"true","SourceIp":"10.0.0.2","DestinationIp":"1.1.1.1","SourcePort":"50000","DestinationPort":"443"}})).collect::<Vec<_>>();
        rows.push(json!({"schema_version":1,"source":"windows_filtering_platform","event_id":5157,
            "record_id":900,"time_utc":"2020-01-01T00:00:00Z","action":"connection_blocked","pid":null,
            "image":"","protocol":"udp","local_address":"10.0.0.2","local_port":50000,
            "remote_address":"1.1.1.1","remote_port":443,"data":{},
            "correlation":{"target":false,"confidence":"none","reason":"PID unavailable","process_guid":null}}));
        let file = root.join("telemetry.json");
        let write = |rows: &serde_json::Value| {
            let bytes = serde_json::to_vec(rows).unwrap();
            std::fs::write(&file, &bytes).unwrap();
            Artifact {
                evidence_id: "artifact:telemetry".into(),
                relative_path: "telemetry.json".into(),
                kind: "guest_telemetry_events".into(),
                size_bytes: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
                exists: true,
                hash_verified: true,
                source: "fixture".into(),
                raw: json!({}),
            }
        };
        run.artifacts.push(write(&json!(rows)));
        import(&mut run, &root, &AssociationBudget::default()).unwrap();
        assert_eq!(run.network_attempts.len(), 1);
        assert_eq!(run.network_attempts[0]["event_id"], 5157);
        assert_eq!(run.network_attempts[0]["correlation"]["target"], false);
        assert_eq!(run.network_attempts[0]["source_artifact"], "telemetry.json");
        let published = serde_json::to_value(&run).unwrap();
        assert!(published["network_attempts"][0]["pid"].is_null());
        assert_eq!(run.processes[0].observations.len(), 3);
        assert_eq!(run.file_events.len(), 5);
        assert_eq!(run.registry_events.len(), 1);
        assert_eq!(run.network_events.len(), 2);
        assert!(
            run.file_events
                .iter()
                .all(|f| f.pid == 42 && !f.association.inferred)
        );
        assert_eq!(
            run.network_events[0].raw["answers"],
            json!(["1.1.1.1", "::1"])
        );
        let mut wrong = json!(rows);
        wrong[0]["schema_version"] = 2.into();
        run.artifacts[0] = write(&wrong);
        import(&mut run, &root, &AssociationBudget::default()).unwrap();
        assert!(!run.validation_warnings.is_empty());
        std::fs::write(&file, b"{").unwrap();
        let n = run.validation_warnings.len();
        import(&mut run, &root, &AssociationBudget::default()).unwrap();
        assert!(run.validation_warnings.len() > n);
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
