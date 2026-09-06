@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_lint] Running Clippy with warnings denied
cargo clippy --all-targets --locked %* -- -D warnings
exit /b %errorlevel%
