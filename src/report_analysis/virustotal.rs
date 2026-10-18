use super::model::{
    NormalizedRun, VIRUSTOTAL_SCHEMA_VERSION, VirusTotalEngineResult, VirusTotalFileReport,
    VirusTotalReport, VirusTotalStats,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_VIRUSTOTAL_FILES: usize = 25;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileCandidate {
    role: String,
    name: String,
    path: String,
    sha256: String,
}

pub fn not_queried(normalized: &NormalizedRun, message: impl Into<String>) -> VirusTotalReport {
    let message = message.into();
    let files = candidates(normalized)
        .into_iter()
        .map(|candidate| unavailable_file(candidate, "not_queried", Some(message.clone())))
        .collect();
    VirusTotalReport {
        schema_version: VIRUSTOTAL_SCHEMA_VERSION.to_string(),
        run_id: normalized.run_id.clone(),
        status: "not_queried".to_string(),
        files,
        warnings: vec![message],
    }
}

pub async fn collect(
    normalized: &NormalizedRun,
    api_key: &str,
    trusted_engines: &[String],
) -> VirusTotalReport {
    if api_key.trim().is_empty() {
        return not_queried(normalized, "VirusTotal API key is empty in settings.json");
    }

    let candidates = candidates(normalized);
    let mut warnings = Vec::new();
    let mut by_hash = BTreeMap::new();
    let mut seen_hashes = BTreeSet::new();
    let unique_hashes = candidates
        .iter()
        .filter(|candidate| seen_hashes.insert(candidate.sha256.clone()))
        .map(|candidate| candidate.sha256.clone())
        .collect::<Vec<_>>();
    let mut skipped_message = "Lookup skipped after the per-report query limit".to_string();

    for (index, sha256) in unique_hashes.iter().enumerate() {
        if index >= MAX_VIRUSTOTAL_FILES {
            warnings.push(format!(
                "VirusTotal lookup limit reached; {} additional unique hash(es) were not queried",
                unique_hashes.len() - MAX_VIRUSTOTAL_FILES
            ));
            break;
        }

        let result = match crate::virustotal_api::lookup_file_report(sha256, api_key).await {
            Ok((status, body)) if status.is_success() => {
                parse_file_report(sha256, &body, trusted_engines).unwrap_or_else(|error| {
                    LookupResult::Error(format!("VirusTotal response could not be parsed: {error}"))
                })
            }
            Ok((status, _)) if status == reqwest::StatusCode::NOT_FOUND => LookupResult::NotFound,
            Ok((status, _)) if status == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                warnings.push(
                    "VirusTotal rate limit was reached; remaining lookups were skipped".to_string(),
                );
                by_hash.insert(
                    sha256.clone(),
                    LookupResult::Error("VirusTotal rate limit reached (HTTP 429)".to_string()),
                );
                skipped_message = "Lookup skipped after VirusTotal returned HTTP 429".to_string();
                break;
            }
            Ok((status, _))
                if status == reqwest::StatusCode::UNAUTHORIZED
                    || status == reqwest::StatusCode::FORBIDDEN =>
            {
                warnings.push(
                    "VirusTotal rejected the configured API key; remaining lookups were skipped"
                        .to_string(),
                );
                by_hash.insert(
                    sha256.clone(),
                    LookupResult::Error(format!("VirusTotal returned HTTP {status}")),
                );
                skipped_message =
                    "Lookup skipped because VirusTotal rejected the configured API key".to_string();
                break;
            }
            Ok((status, _)) => LookupResult::Error(format!("VirusTotal returned HTTP {status}")),
            Err(error) => LookupResult::Error(format!("VirusTotal lookup failed: {error}")),
        };
        by_hash.insert(sha256.clone(), result);
    }

    let files = candidates
        .into_iter()
        .map(|candidate| match by_hash.get(&candidate.sha256) {
            Some(LookupResult::Available(details)) => available_file(candidate, details.clone()),
            Some(LookupResult::NotFound) => unavailable_file(
                candidate,
                "not_found",
                Some("This hash is not currently known to VirusTotal".to_string()),
            ),
            Some(LookupResult::Error(message)) => {
                unavailable_file(candidate, "error", Some(message.clone()))
            }
            None => unavailable_file(candidate, "not_queried", Some(skipped_message.clone())),
        })
        .collect::<Vec<_>>();

    let available = files
        .iter()
        .filter(|file| file.status == "available")
        .count();
    let status = if files.is_empty() {
        warnings.push("No SHA-256 file hashes were available for VirusTotal lookup".to_string());
        "no_hashes"
    } else if available == files.len() {
        "complete"
    } else if available > 0 {
        "partial"
    } else {
        "unavailable"
    };

    VirusTotalReport {
        schema_version: VIRUSTOTAL_SCHEMA_VERSION.to_string(),
        run_id: normalized.run_id.clone(),
        status: status.to_string(),
        files,
        warnings,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LookupResult {
    Available(ParsedFileReport),
    NotFound,
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedFileReport {
    type_description: Option<String>,
    meaningful_name: Option<String>,
    last_analysis_date: Option<u64>,
    stats: VirusTotalStats,
    engines: Vec<VirusTotalEngineResult>,
}

fn parse_file_report(
    expected_sha256: &str,
    body: &str,
    trusted_engines: &[String],
) -> Result<LookupResult, String> {
    let value: Value = serde_json::from_str(body).map_err(|error| error.to_string())?;
    let data = value
        .get("data")
        .and_then(Value::as_object)
        .ok_or("missing data object")?;
    let returned_hash = data
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing data.id")?;
    if !returned_hash.eq_ignore_ascii_case(expected_sha256) {
        return Err("returned file hash does not match the requested hash".to_string());
    }
    let attributes = data
        .get("attributes")
        .and_then(Value::as_object)
        .ok_or("missing data.attributes")?;

    let stats_value = attributes
        .get("last_analysis_stats")
        .and_then(Value::as_object);
    let stats = VirusTotalStats {
        malicious: stat(stats_value, "malicious"),
        suspicious: stat(stats_value, "suspicious"),
        harmless: stat(stats_value, "harmless"),
        undetected: stat(stats_value, "undetected"),
        timeout: stat(stats_value, "timeout"),
        failure: stat(stats_value, "failure"),
        type_unsupported: stat(stats_value, "type-unsupported"),
        confirmed_timeout: stat(stats_value, "confirmed-timeout"),
    };

    let trusted = trusted_engines
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut engines = attributes
        .get("last_analysis_results")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(key, value)| {
            let object = value.as_object();
            let engine_name = string_field(object, "engine_name").unwrap_or_else(|| key.clone());
            VirusTotalEngineResult {
                trusted: trusted.contains(&engine_name.to_ascii_lowercase()),
                engine_name,
                category: string_field(object, "category").unwrap_or_else(|| "unknown".to_string()),
                result: string_field(object, "result"),
                engine_version: string_field(object, "engine_version"),
                engine_update: string_field(object, "engine_update"),
            }
        })
        .collect::<Vec<_>>();
    engines.sort_by(|left, right| {
        engine_rank(&left.category)
            .cmp(&engine_rank(&right.category))
            .then_with(|| left.engine_name.cmp(&right.engine_name))
    });

    Ok(LookupResult::Available(ParsedFileReport {
        type_description: string_field(Some(attributes), "type_description"),
        meaningful_name: string_field(Some(attributes), "meaningful_name"),
        last_analysis_date: attributes.get("last_analysis_date").and_then(Value::as_u64),
        stats,
        engines,
    }))
}

fn stat(object: Option<&serde_json::Map<String, Value>>, key: &str) -> u64 {
    object
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn string_field(object: Option<&serde_json::Map<String, Value>>, key: &str) -> Option<String> {
    object
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn engine_rank(category: &str) -> u8 {
    match category {
        "malicious" => 0,
        "suspicious" => 1,
        "harmless" => 2,
        "undetected" => 3,
        _ => 4,
    }
}

fn candidates(normalized: &NormalizedRun) -> Vec<FileCandidate> {
    let target_path = normalized
        .target
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("<unknown target>");
    let mut files = Vec::new();
    if let Some(sha256) = target_sha256(normalized) {
        files.push(FileCandidate {
            role: "target".to_string(),
            name: basename(target_path),
            path: target_path.to_string(),
            sha256,
        });
    }

    let mut seen = BTreeSet::new();
    for event in &normalized.file_events {
        let Some(sha256) = event
            .sha256
            .as_deref()
            .filter(|value| is_sha256(value))
            .map(str::to_ascii_lowercase)
        else {
            continue;
        };
        let key = (event.path.to_ascii_lowercase(), sha256.clone());
        if !seen.insert(key) {
            continue;
        }
        files.push(FileCandidate {
            role: "observed".to_string(),
            name: basename(&event.path),
            path: event.path.clone(),
            sha256,
        });
    }
    files.sort_by(|left, right| {
        role_rank(&left.role)
            .cmp(&role_rank(&right.role))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.sha256.cmp(&right.sha256))
    });
    files
}

fn target_sha256(normalized: &NormalizedRun) -> Option<String> {
    normalized
        .target
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| is_sha256(value))
        .or_else(|| {
            normalized
                .target_hashes
                .iter()
                .find(|hash| hash.algorithm.eq_ignore_ascii_case("sha256"))
                .map(|hash| hash.value.as_str())
                .filter(|value| is_sha256(value))
        })
        .map(str::to_ascii_lowercase)
}

fn available_file(candidate: FileCandidate, details: ParsedFileReport) -> VirusTotalFileReport {
    VirusTotalFileReport {
        permalink: report_url(&candidate.sha256),
        discussion_url: discussion_url(&candidate.sha256),
        role: candidate.role,
        name: candidate.name,
        path: candidate.path,
        sha256: candidate.sha256,
        status: "available".to_string(),
        type_description: details.type_description,
        meaningful_name: details.meaningful_name,
        last_analysis_date: details.last_analysis_date,
        stats: details.stats,
        engines: details.engines,
        message: None,
    }
}

fn unavailable_file(
    candidate: FileCandidate,
    status: &str,
    message: Option<String>,
) -> VirusTotalFileReport {
    VirusTotalFileReport {
        permalink: report_url(&candidate.sha256),
        discussion_url: discussion_url(&candidate.sha256),
        role: candidate.role,
        name: candidate.name,
        path: candidate.path,
        sha256: candidate.sha256,
        status: status.to_string(),
        type_description: None,
        meaningful_name: None,
        last_analysis_date: None,
        stats: VirusTotalStats::default(),
        engines: Vec::new(),
        message,
    }
}

fn report_url(sha256: &str) -> String {
    format!("https://www.virustotal.com/gui/file/{sha256}/detection")
}

fn discussion_url(sha256: &str) -> String {
    format!("https://www.virustotal.com/gui/file/{sha256}/community")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn basename(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .find(|value| !value.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn role_rank(role: &str) -> u8 {
    if role == "target" { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_analysis::{FileEvent, ProcessAssociation, RawEventCounts};
    use serde_json::json;

    fn normalized() -> NormalizedRun {
        NormalizedRun {
            capture_health: Vec::new(),
            network_attempts: Vec::new(),
            detection: Default::default(),
            schema_version: "1.0".to_string(),
            run_id: "run-1".to_string(),
            target: json!({"path": "C:\\samples\\target.exe", "sha256": "aa".repeat(32)}),
            target_hashes: Vec::new(),
            sandbox: json!({}),
            execution: json!({}),
            coverage: json!({}),
            limitations: Vec::new(),
            raw_event_counts: RawEventCounts::default(),
            normalized_event_counts: RawEventCounts::default(),
            processes: Vec::new(),
            file_events: vec![FileEvent {
                evidence_id: "file:1".to_string(),
                pid: 1,
                path: "C:\\Temp\\payload.dll".to_string(),
                action: "created".to_string(),
                size_bytes: Some(12),
                sha256: Some("bb".repeat(32)),
                hash_source: Some("guest".to_string()),
                observed_at_ms: 1,
                source: "events.json".to_string(),
                association: ProcessAssociation {
                    pid: 1,
                    image: "target.exe".to_string(),
                    parent_pid: None,
                    inferred: false,
                    method: "pid".to_string(),
                },
                raw: json!({}),
            }],
            registry_events: Vec::new(),
            network_events: Vec::new(),
            artifacts: Vec::new(),
            validation_warnings: Vec::new(),
            source_paths: Vec::new(),
            raw: BTreeMap::new(),
        }
    }

    #[test]
    fn target_is_first_and_observed_files_are_retained() {
        let files = candidates(&normalized());
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].role, "target");
        assert_eq!(files[0].name, "target.exe");
        assert_eq!(files[1].name, "payload.dll");
    }

    #[test]
    fn file_report_parser_keeps_detection_and_clean_engine_results() {
        let hash = "aa".repeat(32);
        let body = json!({
            "data": {
                "id": hash,
                "attributes": {
                    "meaningful_name": "sample.exe",
                    "type_description": "Win32 EXE",
                    "last_analysis_date": 1_700_000_000,
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "undetected": 1,
                        "harmless": 0
                    },
                    "last_analysis_results": {
                        "Microsoft": {
                            "engine_name": "Microsoft",
                            "category": "malicious",
                            "result": "Trojan:Win32/Test",
                            "engine_version": "1.2",
                            "engine_update": "20260907"
                        },
                        "Other": {
                            "engine_name": "Other",
                            "category": "undetected",
                            "result": null
                        }
                    }
                }
            }
        })
        .to_string();

        let LookupResult::Available(parsed) =
            parse_file_report(&hash, &body, &["Microsoft".to_string()]).unwrap()
        else {
            panic!("expected parsed report")
        };
        assert_eq!(parsed.stats.malicious, 1);
        assert_eq!(parsed.stats.total(), 2);
        assert_eq!(parsed.engines.len(), 2);
        assert_eq!(parsed.engines[0].engine_name, "Microsoft");
        assert!(parsed.engines[0].trusted);
        assert_eq!(parsed.engines[1].category, "undetected");
    }

    #[test]
    fn mismatched_hash_is_rejected() {
        let body = json!({"data": {"id": "bb".repeat(32), "attributes": {}}}).to_string();
        assert!(parse_file_report(&"aa".repeat(32), &body, &[]).is_err());
    }
}
