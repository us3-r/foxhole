@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_fmt] Checking Rust formatting
cargo fmt --all --check %*
exit /b %errorlevel%
