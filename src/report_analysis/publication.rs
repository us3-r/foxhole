use super::model::*;
use std::collections::BTreeSet;
use std::io;

/// Final gate: scanners and imported records cannot publish unresolved evidence links.
pub fn validate(run: &NormalizedRun, verdict: &VerdictReport, iocs: &IocReport) -> io::Result<()> {
    if run.schema_version != NORMALIZED_SCHEMA_VERSION
        || verdict.schema_version != VERDICT_SCHEMA_VERSION
        || iocs.schema_version != IOC_SCHEMA_VERSION
    {
        return Err(io::Error::other("unsupported published report schema"));
    }
    let mut available = BTreeSet::new();
    for id in run
        .processes
        .iter()
        .flat_map(|p| p.observations.iter().map(|o| &o.evidence_id))
        .chain(run.file_events.iter().map(|e| &e.evidence_id))
        .chain(run.registry_events.iter().map(|e| &e.evidence_id))
        .chain(run.network_events.iter().map(|e| &e.evidence_id))
        .chain(run.artifacts.iter().map(|a| &a.evidence_id))
    {
        if !available.insert(id.clone()) {
            return Err(io::Error::other(
                "duplicate evidence identifier in published report",
            ));
        }
    }
    if let Some(hash) = run
        .target
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|h| crate::detection::validation::sha256(h))
    {
        available.insert(format!("sha256:{}", hash.to_ascii_lowercase()));
    }
    let mut finding_ids = BTreeSet::new();
    for f in &verdict.findings {
        if !finding_ids.insert(f.rule_id.clone()) {
            return Err(io::Error::other("duplicate published finding identifier"));
        }
        let ids = f
            .evidence
            .iter()
            .map(|e| e.evidence_id.clone())
            .collect::<Vec<_>>();
        crate::detection::validation::resolve(&ids, &available).map_err(io::Error::other)?;
    }
    for stage in &run.detection.stages {
        crate::detection::validation::resolve(&stage.evidence_ids, &available)
            .map_err(io::Error::other)?;
        if let Some(original) = &stage.original
            && (!crate::detection::validation::relative_path(&original.path)
                || !run.artifacts.iter().any(|a| {
                    a.hash_verified
                        && a.relative_path == original.path
                        && a.sha256 == original.sha256
                }))
        {
            return Err(io::Error::other("unverified retained scanner output"));
        }
        for f in &stage.findings {
            crate::detection::validation::resolve(&f.evidence_ids, &available)
                .map_err(io::Error::other)?;
        }
        for p in &stage.packets {
            crate::detection::validation::resolve(&p.evidence_ids, &available)
                .map_err(io::Error::other)?;
        }
    }
    for ids in run
        .detection
        .network_flows
        .iter()
        .map(|f| &f.evidence_ids)
        .chain(
            run.detection
                .packet_correlations
                .iter()
                .map(|c| &c.evidence_ids),
        )
    {
        crate::detection::validation::resolve(ids, &available).map_err(io::Error::other)?;
    }
    for indicator in &iocs.indicators {
        if let Some(details) = &indicator.details
            && (!details.evidence_ids.is_empty()
                || indicator
                    .sources
                    .iter()
                    .any(|s| s.kind != "target_metadata"))
        {
            crate::detection::validation::resolve(&details.evidence_ids, &available)
                .map_err(io::Error::other)?;
        }
        for source in &indicator.sources {
            if let Some(id) = &source.evidence_id
                && !available.contains(id)
            {
                return Err(io::Error::other("unresolved IOC evidence"));
            }
        }
    }
    Ok(())
}

/// Exported views retain evidence identifiers while removing raw streams and obvious secrets.
/// Original bounded evidence remains in the protected run archive, outside web exports.
pub fn public_value(value: &impl serde::Serialize) -> io::Result<serde_json::Value> {
    let mut value = serde_json::to_value(value).map_err(io::Error::other)?;
    redact(&mut value, 0);
    Ok(value)
}
fn redact(value: &mut serde_json::Value, depth: usize) {
    if depth > 64 {
        *value = serde_json::Value::String("[redacted nesting limit]".into());
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let folded = key.to_ascii_lowercase();
                if [
                    "password",
                    "api_key",
                    "apikey",
                    "token",
                    "access_token",
                    "authorization",
                    "secret",
                    "credential",
                    "stdout",
                    "stderr",
                    "host_path",
                    "base_image_path",
                    "base_manifest_path",
                    "run_root",
                    "host_invocation",
                    "analysis_config",
                    "host_report",
                ]
                .contains(&folded.as_str())
                {
                    *value = serde_json::Value::String("[redacted]".into());
                } else {
                    if folded == "target"
                        && let Some(path) = value.get_mut("path")
                        && let Some(original) = path.as_str()
                    {
                        *path = serde_json::Value::String(
                            original
                                .rsplit(['/', '\\'])
                                .next()
                                .unwrap_or("[redacted]")
                                .to_string(),
                        );
                    }
                    redact(value, depth + 1);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact(value, depth + 1);
            }
        }
        serde_json::Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            if [
                "password=",
                "password:",
                "api_key=",
                "apikey=",
                "token=",
                "authorization:",
                "secret=",
                "--password ",
                "--token ",
            ]
            .iter()
            .any(|pattern| lower.contains(pattern))
            {
                *s = "[redacted sensitive value]".into();
            }
        }
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sensitive_streams_config_and_string_values_are_not_exported() {
        let v=public_value(&serde_json::json!({"stdout":"anything","password":"secret","host_path":"C:/Users/test","safe":"marker","value":"https://example.com/?token=hidden"})).unwrap();
        let s = v.to_string();
        assert!(!s.contains("anything"));
        assert!(!s.contains("hidden"));
        assert!(!s.contains("C:/Users"));
        assert_eq!(v["safe"], "marker");
    }
    #[test]
    fn report_deserialization_and_publication_reject_unsupported_schema_and_evidence() {
        let mut run: NormalizedRun = serde_json::from_str(include_str!(
            "../../tests/fixtures/detection/normalized.json"
        ))
        .unwrap();
        let verdict: VerdictReport =
            serde_json::from_str(include_str!("../../tests/fixtures/detection/verdict.json"))
                .unwrap();
        let iocs: IocReport =
            serde_json::from_str(include_str!("../../tests/fixtures/detection/iocs.json")).unwrap();
        validate(&run, &verdict, &iocs).unwrap();
        run.schema_version = "future".into();
        assert!(validate(&run, &verdict, &iocs).is_err());
        run.schema_version = NORMALIZED_SCHEMA_VERSION.into();
        run.detection.stages[0].evidence_ids = vec!["unknown".into()];
        assert!(validate(&run, &verdict, &iocs).is_err());
        let bytes = include_bytes!("../../tests/fixtures/detection/normalized.json");
        for index in (0..bytes.len()).step_by(89) {
            let mut mutated = bytes.to_vec();
            mutated[index] = 0xff;
            if let Ok(value) = crate::detection::validation::bounded_json(
                &mutated,
                &crate::detection::Limits::default(),
            ) {
                let _ = serde_json::from_value::<NormalizedRun>(value);
            }
        }
        let public=public_value(&serde_json::json!({"target":{"path":"C:\\Private\\fixture.exe"},"host_report":{"nested":{"anything":"C:\\Private\\secret"}},"host_invocation":{"command_line":"host command"}})).unwrap();
        assert!(!public.to_string().contains("Private"));
        assert_eq!(public["target"]["path"], "fixture.exe");
    }
}
