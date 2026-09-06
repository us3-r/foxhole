@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_cli_invalid] Testing rejection of invalid CLI combinations

cargo build --locked %* || exit /b 1
set "foxhole=%cd%\target\debug\foxhole.exe"

call :expect_failure --network-policy allow-list || exit /b 1
call :expect_failure --network-policy deny-all --allow-ip 192.0.2.1 || exit /b 1
call :expect_failure --allow-network --network-policy allow-internet || exit /b 1
call :expect_failure --network-policy allow-list --allow-ip not-an-ip || exit /b 1
exit /b 0

:expect_failure
"%foxhole%" --path "%foxhole%" --sandbox --dry-run --no-report %* >nul 2>&1
if not errorlevel 1 (
    echo [v1_cli_invalid] Expected failure for: %* 1>&2
    exit /b 1
)
exit /b 0
