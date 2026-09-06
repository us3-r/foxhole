#[cfg(target_os = "linux")]
#[test]
fn cli_help_runs_on_linux() {
    let bin = env!("CARGO_BIN_EXE_foxhole");
    let output = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .expect("failed to execute foxhole --help");

    assert!(output.status.success());
}
