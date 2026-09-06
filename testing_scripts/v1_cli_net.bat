@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_cli_net] Testing Windows network policies and mitigation profiles

cargo build --locked %* || exit /b 1
set "foxhole=%cd%\target\debug\foxhole.exe"

call :expect_success --network-policy deny-all --mitigation-profile compatible || exit /b 1
call :expect_success --network-policy allow-list --allow-ip 192.0.2.0/24 --allow-ip 2001:db8::/32 --mitigation-profile strict || exit /b 1
call :expect_success --network-policy allow-internet --mitigation-profile maximum || exit /b 1
call :expect_success --network-policy capture-only || exit /b 1
call :expect_success --allow-network || exit /b 1
exit /b 0

:expect_success
"%foxhole%" --path "%foxhole%" --sandbox --dry-run --no-report %* >nul 2>&1
if errorlevel 1 (
    echo [v1_cli_net] Expected success for: %* 1>&2
    exit /b 1
)
exit /b 0
