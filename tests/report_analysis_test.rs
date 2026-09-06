use foxhole::report_analysis::{IocReport, NormalizedRun, VerdictReport, analyze_run};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn phase_1_to_3_golden_fixture_is_complete_and_deterministic() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_ai_vm/16");
    if !fixture.join("reports").is_dir() {
        eprintln!("golden fixture is not installed; skipping local fixture assertion");
        return;
    }

    let first = analyze_run(&fixture).expect("analyze golden fixture");
    let first_normalized_bytes = fs::read(&first.normalized).expect("read normalized output");
    let first_verdict_bytes = fs::read(&first.verdict).expect("read verdict output");
    let first_ioc_bytes = fs::read(&first.iocs).expect("read IOC output");
    let first_web_bytes = read_web_outputs(&fixture.join("web"));

    let second = analyze_run(&fixture).expect("reanalyze golden fixture");
    assert_eq!(
        first_normalized_bytes,
        fs::read(&second.normalized).unwrap()
    );
    assert_eq!(first_verdict_bytes, fs::read(&second.verdict).unwrap());
    assert_eq!(first_ioc_bytes, fs::read(&second.iocs).unwrap());
    assert_eq!(first_web_bytes, read_web_outputs(&fixture.join("web")));

    let normalized: NormalizedRun = serde_json::from_slice(&first_normalized_bytes).unwrap();
    assert_eq!(normalized.run_id, "e71ecb7c4fcea6a0c8d3bd97b5653d04");
    assert_eq!(normalized.raw_event_counts.process, 21);
    assert_eq!(normalized.raw_event_counts.network, 13);
    assert_eq!(normalized.raw_event_counts.filesystem, 5);
    assert_eq!(normalized.raw_event_counts.registry, 12);
    assert_eq!(
        normalized.raw_event_counts,
        normalized.normalized_event_counts
    );
    assert!(normalized.validation_warnings.is_empty());
    assert!(normalized.artifacts.iter().all(|artifact| artifact.exists));
    assert!(
        normalized
            .artifacts
            .iter()
            .all(|artifact| artifact.hash_verified)
    );

    let verdict: VerdictReport = serde_json::from_slice(&first_verdict_bytes).unwrap();
    assert_eq!(verdict.verdict, "suspicious");
    assert_eq!(verdict.score, 30);
    assert!(
        verdict
            .findings
            .iter()
            .any(|finding| finding.rule_id == "ntfs_alternate_data_stream")
    );
    assert!(
        verdict
            .findings
            .iter()
            .all(|finding| finding.rule_id != "process_injection")
    );
    assert_eq!(verdict.timeline.len(), 21 + 13 + 5 + 12);

    let iocs: IocReport = serde_json::from_slice(&first_ioc_bytes).unwrap();
    assert_indicator(&iocs, "domain", "example.com", true);
    assert_indicator(&iocs, "domain", "foxhole-telemetry.invalid", true);
    assert_indicator(&iocs, "ipv4", "1.1.1.1", false);
    for artifact in &normalized.artifacts {
        assert_indicator(&iocs, "sha256", &artifact.sha256, false);
    }
    for file in &normalized.file_events {
        assert_indicator(&iocs, "file_path", &file.path, false);
    }
    for registry in &normalized.registry_events {
        assert!(iocs.indicators.iter().any(|indicator| {
            indicator.ioc_type == "registry_key"
                && indicator.normalized_value == registry.key.to_ascii_lowercase()
        }));
    }
    assert!(
        iocs.indicators
            .iter()
            .all(|indicator| !indicator.sources.is_empty())
    );
    assert!(
        iocs.extraction_warnings
            .iter()
            .any(|warning| warning.code == "target_hash_unavailable")
    );

    for page in [
        "index.html",
        "parameters.html",
        "findings.html",
        "timeline.html",
        "processes.html",
        "network.html",
        "iocs.html",
    ] {
        let html = String::from_utf8(first_web_bytes[page].clone()).unwrap();
        assert!(html.contains("assets/style.css"));
        assert!(html.contains("data/report-data.js"));
        assert!(html.contains("assets/app.js"));
        for link in [
            "index.html",
            "findings.html",
            "timeline.html",
            "processes.html",
            "iocs.html",
        ] {
            assert!(html.contains(&format!("href=\"{link}\"")));
        }
    }
    let application = String::from_utf8(first_web_bytes["assets/app.js"].clone()).unwrap();
    assert!(!application.contains("innerHTML"));
    assert!(!application.contains("fetch("));
    assert!(application.contains("function renderCreatedFileHashes()"));
    let overview = String::from_utf8(first_web_bytes["index.html"].clone()).unwrap();
    assert!(overview.contains("id=\"target-sha256\""));
    assert!(overview.contains("id=\"target-virustotal\""));
    assert!(overview.contains("id=\"created-file-table\""));
    assert!(overview.find("id=\"created-file-table\"") < overview.find("class=\"dashboard-grid\""));
    let data_script = String::from_utf8(first_web_bytes["data/report-data.js"].clone()).unwrap();
    assert!(data_script.contains(&normalized.run_id));
    assert!(data_script.starts_with("window.FOXHOLE_REPORT = "));
}

fn assert_indicator(iocs: &IocReport, ioc_type: &str, value: &str, contextual: bool) {
    let indicator = iocs
        .indicators
        .iter()
        .find(|indicator| {
            indicator.ioc_type == ioc_type && indicator.normalized_value.eq_ignore_ascii_case(value)
        })
        .unwrap_or_else(|| panic!("missing {ioc_type} IOC {value}"));
    assert_eq!(indicator.contextual, contextual);
}

fn read_web_outputs(root: &Path) -> BTreeMap<String, Vec<u8>> {
    [
        "index.html",
        "findings.html",
        "timeline.html",
        "processes.html",
        "iocs.html",
        "assets/style.css",
        "assets/app.js",
        "data/report-data.js",
    ]
    .into_iter()
    .map(|relative| {
        (
            relative.to_string(),
            fs::read(root.join(relative))
                .unwrap_or_else(|error| panic!("read generated web output {relative}: {error}")),
        )
    })
    .collect()
}
