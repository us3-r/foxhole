use super::validation::*;
use super::*;
use std::collections::{BTreeMap, BTreeSet};

fn fixture(scanner: &str) -> (ScannerResult, ScannerConfig, BTreeSet<String>) {
    let config = ScannerConfig {
        rules: Some(RulePack {
            id: "foxhole-test".into(),
            version: "1".into(),
            path: r"C:\Rules\test.yar".into(),
            sha256: "ab".repeat(32),
        }),
        ..Default::default()
    };
    let mut result = ScannerResult::empty(
        scanner,
        "primary",
        &"cd".repeat(32),
        Status::Completed,
        config.limits.clone(),
        "unused",
    );
    result.warnings.clear();
    result.evidence_ids = vec!["primary".into()];
    result.rule_packs = vec![PackIdentity {
        id: "foxhole-test".into(),
        version: "1".into(),
        sha256: "ab".repeat(32),
        trusted: true,
    }];
    (result, config, BTreeSet::from(["primary".into()]))
}
fn finding(id: &str, offset: u64) -> ScannerFinding {
    ScannerFinding {
        id: id.into(),
        rule: "harmless marker".into(),
        namespace: "foxhole/test".into(),
        title: "Harmless marker".into(),
        tags: vec![],
        metadata: BTreeMap::new(),
        attack: vec![],
        mbc: vec![],
        maec: BTreeMap::new(),
        scope: "file".into(),
        locations: vec![MatchLocation {
            kind: "file".into(),
            offset,
            length: 4,
            excerpt_hex: "41424344".into(),
        }],
        features: vec![],
        rule_pack: "foxhole-test".into(),
        evidence_ids: vec!["primary".into()],
    }
}
fn parse(
    r: &ScannerResult,
    c: &ScannerConfig,
    e: &BTreeSet<String>,
) -> Result<ScannerResult, &'static str> {
    parse_result(
        &serde_json::to_vec(r).unwrap(),
        &r.scanner,
        TrustedTarget {
            id: "primary",
            sha256: &"cd".repeat(32),
            size: 1024,
        },
        c,
        e,
    )
}
#[test]
fn every_scanner_contract_rejects_malformed_oversized_unsupported_and_unmarked_truncation() {
    for scanner in ["yara", "pe", "capa", "network"] {
        let (mut r, c, e) = fixture(scanner);
        assert!(parse(&r, &c, &e).is_ok(), "{scanner}");
        assert!(
            parse_result(
                b"{",
                scanner,
                TrustedTarget {
                    id: "primary",
                    sha256: &"cd".repeat(32),
                    size: 1024
                },
                &c,
                &e
            )
            .is_err()
        );
        r.schema_version = 2;
        assert!(parse(&r, &c, &e).is_err());
        r.schema_version = 1;
        r.version = "future".into();
        assert!(parse(&r, &c, &e).is_err());
        r.version = fixture(scanner).0.version;
        r.truncated = true;
        assert!(parse(&r, &c, &e).is_err());
        r.status = Status::Partial;
        r.warnings = vec![Warning {
            code: "truncated".into(),
            message: "bounded output".into(),
        }];
        assert!(parse(&r, &c, &e).is_ok());
        r.warnings[0].message = "a".repeat(c.limits.string_bytes + 1);
        assert!(parse(&r, &c, &e).is_err());
        r.warnings.clear();
        r.status = Status::Failed;
        assert!(parse(&r, &c, &e).is_err());
    }
}
#[test]
fn evidence_hash_path_pack_and_duplicate_identifiers_are_not_scanner_authority() {
    let (base, c, e) = fixture("yara");
    let mut mutations = vec![];
    let mut r = base.clone();
    r.target_sha256 = "ef".repeat(32);
    mutations.push(r);
    let mut r = base.clone();
    r.target_sha256 = "bad".into();
    mutations.push(r);
    let mut r = base.clone();
    r.target = "../outside".into();
    mutations.push(r);
    let mut r = base.clone();
    r.evidence_ids = vec!["missing".into()];
    mutations.push(r);
    let mut r = base.clone();
    r.evidence_ids.push("primary".into());
    mutations.push(r);
    let mut r = base.clone();
    r.rule_packs[0].sha256 = "ff".repeat(32);
    mutations.push(r);
    let mut r = base.clone();
    r.original = Some(OriginalResult {
        path: "C:/secret".into(),
        sha256: "ab".repeat(32),
    });
    mutations.push(r);
    let mut r = base.clone();
    r.findings = vec![finding("one", 4), finding("one", 8)];
    mutations.push(r);
    let mut r = base.clone();
    r.findings = vec![finding("one", 1022)];
    mutations.push(r);
    let mut r = base.clone();
    r.findings = vec![finding("one", u64::MAX)];
    mutations.push(r);
    let mut r = base.clone();
    r.findings = vec![finding("one", 4)];
    r.findings[0].locations[0].excerpt_hex = "00".repeat(c.limits.match_bytes + 1);
    mutations.push(r);
    let mut r = base.clone();
    r.findings = vec![finding("one", 4)];
    r.findings[0]
        .metadata
        .insert("severity".into(), "malicious".into());
    assert!(parse(&r, &c, &e).is_ok());
    for (index, r) in mutations.iter().enumerate() {
        assert!(parse(r, &c, &e).is_err(), "mutation {index}");
    }
}
#[test]
fn yara_and_capa_dedup_preserve_locations_with_stable_serialization() {
    for scanner in ["yara", "capa"] {
        let (mut r, c, e) = fixture(scanner);
        r.findings = vec![finding("b", 8), finding("a", 4)];
        let a = parse(&r, &c, &e).unwrap();
        r.findings.reverse();
        let b = parse(&r, &c, &e).unwrap();
        assert_eq!(a.findings.len(), 1);
        assert_eq!(a.findings[0].locations.len(), 2);
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
    }
}
#[test]
fn json_is_bounded_before_typed_deserialization_and_rejects_duplicate_keys() {
    let l = Limits::default();
    for value in [
        "{\"a\":1,\"a\":2}".to_string(),
        "[".repeat(50) + &"]".repeat(50),
        "\"".to_string() + &"a".repeat(l.string_bytes + 1) + "\"",
        "null trailing".into(),
    ] {
        assert!(bounded_json(value.as_bytes(), &l).is_err());
    }
    let small = Limits {
        output_bytes: 32,
        ..Default::default()
    };
    assert!(bounded_json(&[b' '; 33], &small).is_err());
}
#[test]
fn every_config_limit_has_zero_and_hard_ceiling_tests() {
    let default = DetectionConfig::default();
    assert!(default.validate().is_ok());
    let limits = serde_json::to_value(Limits::default()).unwrap();
    for key in limits.as_object().unwrap().keys() {
        for invalid in [0, u64::MAX] {
            let mut value = limits.clone();
            value[key] = invalid.into();
            let parsed = serde_json::from_value::<Limits>(value);
            assert!(
                parsed.is_err() || parsed.unwrap().validate().is_err(),
                "{key}"
            );
        }
    }
    let mut c = default.clone();
    let (_, scanner, _) = fixture("yara");
    c.yara = scanner;
    c.yara.user_rules = c.yara.rules.clone();
    assert!(c.validate().is_err());
    assert!(serde_json::from_str::<DetectionConfig>("{\"unknown\":true}").is_err());
    for path in [
        "python.exe",
        r"\\server\scanner.exe",
        r"C:\safe\..\scanner.exe",
    ] {
        let mut c = default.clone();
        c.yara.executable = Some(path.into());
        c.yara.executable_sha256 = Some("ab".repeat(32));
        assert!(c.validate().is_err());
    }
}
#[test]
fn observable_extractors_cover_syntax_context_case_duplicates_and_lengths() {
    use observables::{extract, normalize};
    let cases = [
        ("ipv4", "8.8.8.8", "127.0.0.1", "999.1.1.1"),
        ("ipv6", "2606:4700:4700::1111", "2001:db8::1", "gg::1"),
        (
            "domain",
            "Sub.Real-Domain.NET",
            "example.com",
            "bad..domain",
        ),
        (
            "url",
            "https://Real-Domain.net/a",
            "http://example.com/a",
            "https://user:secret@real-domain.net/",
        ),
        (
            "email",
            "Analyst@Real-Domain.net",
            "a@example.com",
            "a@@example.com",
        ),
        (
            "named_pipe",
            r"\\.\pipe\foxhole",
            r"\\.\pipe\local",
            r"C:\notpipe",
        ),
        (
            "registry",
            r"HKLM\Software\Foxhole",
            r"HKCU\Software\Test",
            "HKQQ\\bad",
        ),
        (
            "file_path",
            r"C:\work\marker.exe",
            r"C:\Windows\System32\cmd.exe",
            r"C:\..\file",
        ),
        ("filename", "payload.exe", "cmd.exe", "../payload.exe"),
        ("user_agent", "Foxhole/1.0", "Mozilla/5.0", "no version"),
        (
            "bitcoin_address",
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyU",
        ),
    ];
    for (kind, valid, context, invalid) in cases {
        let a = normalize(kind, valid).unwrap_or_else(|| panic!("{kind}"));
        assert_eq!(
            normalize(kind, &a.normalized).unwrap().normalized,
            a.normalized
        );
        assert!(normalize(kind, context).is_some());
        assert!(normalize(kind, invalid).is_none(), "{kind}");
        assert!(normalize(kind, &"a".repeat(2049)).is_none());
        let values = extract(&format!("{valid} {valid}"));
        assert_eq!(values.iter().collect::<BTreeSet<_>>().len(), values.len());
    }
    for kind in ["mutex", "service", "scheduled_task"] {
        assert!(normalize(kind, "Global\\Foxhole").is_some());
        assert!(normalize(kind, "<script>").is_none());
        assert!(normalize(kind, &"x".repeat(257)).is_none());
    }
    assert!(normalize("certificate_sha256", &"AB".repeat(32)).is_some());
    assert!(normalize("certificate_sha256", "zz").is_none());
    for value in ["YARA_RULE", "T1055", "CreateProcessW", "capa", "malicious"] {
        assert!(extract(value).is_empty());
    }
    for value in ["localhost", "example.com", "a.example.org", "x.test"] {
        assert!(observables::contextual_domain(value));
    }
    for value in [
        "10.0.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "100.64.0.1",
        "::ffff:127.0.0.1",
        "fc00::1",
    ] {
        assert!(
            observables::contextual_ip(value.parse().unwrap()),
            "{value}"
        );
    }
}
#[test]
fn arbitrary_parser_inputs_never_panic_and_normalization_is_idempotent() {
    let mut state = 0x5473981u64;
    for length in 0..1024 {
        let bytes = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect::<Vec<_>>();
        let _ = bounded_json(&bytes, &Limits::default());
        for scanner in ["yara", "pe", "capa", "network"] {
            let (_, c, e) = fixture(scanner);
            let _ = parse_result(
                &bytes,
                scanner,
                TrustedTarget {
                    id: "primary",
                    sha256: &"cd".repeat(32),
                    size: 1024,
                },
                &c,
                &e,
            );
        }
        for o in observables::extract(&String::from_utf8_lossy(&bytes)) {
            assert_eq!(
                observables::normalize(&o.kind, &o.normalized)
                    .unwrap()
                    .normalized,
                o.normalized
            );
        }
        let id = String::from_utf8_lossy(&bytes).into_owned();
        let _ = resolve(&[id], &BTreeSet::new());
    }
}

#[test]
fn windows_device_names_cannot_enter_artifact_paths() {
    for path in [
        "NUL.json",
        "con.txt",
        "dir/aux.json",
        "dir/COM1.log",
        "dir/Lpt9",
        "dir/../file",
        "C:/host",
        "\\\\host\\file",
    ] {
        assert!(!relative_path(path), "{path}");
    }
    assert!(relative_path("detection/0001-yara.json"));
}

#[test]
fn metadata_stage_and_certificate_boundaries_are_enforced() {
    let (mut result, config, evidence) = fixture("yara");
    result.strings.push(ExtractedString {
        value: "example.com".into(),
        method: "ascii".into(),
        offset: Some(0),
    });
    assert!(parse(&result, &config, &evidence).is_err());
    let check = |result: &ScannerResult| {
        let config = ScannerConfig {
            rules: result.rule_packs.first().map(|p| RulePack {
                id: p.id.clone(),
                version: p.version.clone(),
                sha256: p.sha256.clone(),
                path: String::new(),
            }),
            ..Default::default()
        };
        parse_result(
            &serde_json::to_vec(result).unwrap(),
            &result.scanner,
            TrustedTarget {
                id: "primary",
                sha256: &result.target_sha256,
                size: 4096,
            },
            &config,
            &evidence,
        )
    };
    let mut pe: ScannerResult =
        serde_json::from_str(include_str!("../../tests/fixtures/detection/pe.json")).unwrap();
    assert!(check(&pe).is_ok());
    pe.pe
        .as_mut()
        .unwrap()
        .certificates
        .push(BTreeMap::from([("sha256".into(), "invalid".into())]));
    assert!(check(&pe).is_err());
    let mut packet: ScannerResult =
        serde_json::from_str(include_str!("../../tests/fixtures/detection/network.json")).unwrap();
    assert!(check(&packet).is_ok());
    result.strings.clear();
    result.packets = packet.packets.clone();
    assert!(parse(&result, &config, &evidence).is_err());
    packet.packets[0]
        .tls
        .insert("certificate_sha256".into(), "invalid".into());
    assert!(check(&packet).is_err());
}
