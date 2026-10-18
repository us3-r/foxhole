param([string]$Output = 'tmp/detection-coverage.json')
$ErrorActionPreference = 'Stop'
# The coverage job leaves these live desktop tests to the separate privileged job.
# Ordinary cargo test still invokes them; each test self-skips only when the process is not elevated.
$desktopTests = @(
    'sandbox::windows::restricted_process::tests::live_batch_launch_and_timeout_paths_are_covered',
    'sandbox::windows::restricted_process::tests::enforcing_network_modes_either_run_or_fail_closed_at_wfp',
    'sandbox::windows::restricted_process::tests::live_non_enforcing_network_modes_launch_a_restricted_process',
    'sandbox::windows::restricted_process::tests::live_launch_stages_read_only_and_read_write_mappings',
    'sandbox::windows::restricted_process::tests::prepared_live_request_mismatch_and_armed_guard_fail_safely',
    'enforcing_network_modes_fail_closed_without_wfp_permission',
    'live_capture_only_and_allow_internet_modes_launch_successfully'
)
$testArguments = @()
foreach ($test in $desktopTests) { $testArguments += @('--skip', $test) }
$env:RUSTC_BOOTSTRAP = '1' # Rust 1.93.1: llvm-cov branch instrumentation is unstable.
cargo llvm-cov --branch --locked --all-targets --json --output-path $Output -- @testArguments
if ($LASTEXITCODE -ne 0) { throw 'Instrumented tests failed; coverage is not accepted.' }
