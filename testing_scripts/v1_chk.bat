@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_chk] Checking all Rust targets
cargo check --all-targets --locked %*
exit /b %errorlevel%
