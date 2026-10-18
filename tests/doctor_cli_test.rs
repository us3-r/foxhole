use std::process::Command;

#[test]
fn doctor_is_a_subcommand_without_a_sample_requirement() {
    let result = Command::new(env!("CARGO_BIN_EXE_foxhole"))
        .args(["doctor", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let help = String::from_utf8(result.stdout).unwrap();
    assert!(help.contains("--base-image"));
    assert!(help.contains("--json"));
}

#[test]
fn failed_doctor_still_emits_exactly_one_json_document() {
    let result = Command::new(env!("CARGO_BIN_EXE_foxhole"))
        .args([
            "doctor",
            "--json",
            "--base-image",
            "C:\\foxhole-doctor-nonexistent-image.vhdx",
            "--base-manifest",
            "C:\\foxhole-doctor-nonexistent-image.manifest.json",
        ])
        .env_remove("FOXHOLE_HYPERV_BASE_IMAGE")
        .env_remove("FOXHOLE_HYPERV_BASE_MANIFEST")
        .env_remove("FOXHOLE_HYPERV_GATEWAY_CONFIG")
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&result.stdout).expect("stdout must be JSON even on failure");
    assert_eq!(report["ready"], false);
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "base_image" && c["status"] != "pass")
    );
}

#[test]
fn doctor_distinguishes_unconfigured_disabled_and_invalid_scanners() {
    let path =
        std::env::temp_dir().join(format!("foxhole-doctor-config-{}.json", std::process::id()));
    for (config, expected_id, expected_status) in [
        (
            serde_json::json!({"schema_version":1}),
            "scanner_yara",
            "warning",
        ),
        (
            serde_json::json!({"schema_version":1,"yara":{"enabled":false}}),
            "scanner_yara",
            "not_checked",
        ),
        (
            serde_json::json!({"schema_version":999}),
            "scanner_config",
            "fail",
        ),
    ] {
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_foxhole"))
            .args([
                "doctor",
                "--json",
                "--base-image",
                "C:\\foxhole-doctor-nonexistent-image.vhdx",
                "--analysis-config",
            ])
            .arg(&path)
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["id"] == expected_id && c["status"] == expected_status)
        );
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["id"] == "guest_readiness" && c["status"] == "not_checked")
        );
    }
    std::fs::remove_file(path).unwrap();
}
