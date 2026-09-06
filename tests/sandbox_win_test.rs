#[cfg(target_os = "windows")]
#[test]
fn cli_help_runs_on_windows() {
    let bin = env!("CARGO_BIN_EXE_foxhole");
    let output = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .expect("failed to execute foxhole --help");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: foxhole.exe"));
}

#[cfg(target_os = "windows")]
#[test]
fn inspecting_a_file_does_not_require_virus_total_settings() {
    let bin = env!("CARGO_BIN_EXE_foxhole");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = std::process::Command::new(bin)
        .args(["--path", &manifest.display().to_string()])
        .current_dir(std::env::temp_dir())
        .output()
        .expect("failed to execute foxhole");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("[cli] target:"));
}

#[cfg(target_os = "windows")]
#[test]
fn dry_run_accepts_an_ipv4_and_ipv6_allow_list() {
    let _lock = sandbox_test_lock();
    let bin = env!("CARGO_BIN_EXE_foxhole");
    let output = std::process::Command::new(bin)
        .args([
            "--path",
            bin,
            "--sandbox",
            "--dry-run",
            "--no-report",
            "--network-policy",
            "allow-list",
            "--allow-ip",
            "192.0.2.0/24",
            "--allow-ip",
            "2001:db8::/32",
            "--mitigation-profile",
            "strict",
        ])
        .output()
        .expect("failed to execute foxhole dry run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("dry run validated executable"));
}

#[cfg(target_os = "windows")]
#[test]
fn live_capture_only_and_allow_internet_modes_launch_successfully() {
    let _lock = sandbox_test_lock();
    let bin = env!("CARGO_BIN_EXE_foxhole");
    for policy in ["capture-only", "allow-internet"] {
        let output = std::process::Command::new(bin)
            .args([
                "--path",
                bin,
                "--sandbox",
                "--no-report",
                "--timeout",
                "15",
                "--network-policy",
                policy,
                "--",
                "--version",
            ])
            .output()
            .expect("failed to execute live sandbox mode");
        assert!(
            output.status.success(),
            "policy {policy} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("exit=Some(0)"),
            "policy {policy} returned unexpected output: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(target_os = "windows")]
#[test]
fn enforcing_network_modes_fail_closed_without_wfp_permission() {
    let _lock = sandbox_test_lock();
    let bin = env!("CARGO_BIN_EXE_foxhole");
    for arguments in [
        vec!["--network-policy", "deny-all"],
        vec![
            "--network-policy",
            "allow-list",
            "--allow-ip",
            "127.0.0.1/32",
        ],
    ] {
        let mut command = std::process::Command::new(bin);
        command.args(["--path", bin, "--sandbox", "--no-report", "--timeout", "15"]);
        command.args(arguments);
        command.args(["--", "--version"]);
        let output = command.output().expect("failed to execute enforcing mode");
        if output.status.success() {
            assert!(String::from_utf8_lossy(&output.stdout).contains("exit=Some(0)"));
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("network_filters"),
                "unexpected error: {stderr}"
            );
        }
    }
}

#[cfg(target_os = "windows")]
#[test]
fn every_mitigation_profile_has_integration_coverage() {
    let _lock = sandbox_test_lock();
    let bin = env!("CARGO_BIN_EXE_foxhole");
    for profile in ["compatible", "strict", "maximum"] {
        let output = std::process::Command::new(bin)
            .args([
                "--path",
                bin,
                "--sandbox",
                "--dry-run",
                "--no-report",
                "--mitigation-profile",
                profile,
            ])
            .output()
            .expect("failed to execute mitigation dry run");
        assert!(output.status.success(), "profile {profile} failed");
    }
}
#[cfg(target_os = "windows")]
fn sandbox_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
