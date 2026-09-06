@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_test] Running all Rust tests
cargo test --all-targets --locked %*
exit /b %errorlevel%
