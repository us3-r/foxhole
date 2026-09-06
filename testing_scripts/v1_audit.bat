@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_audit] Auditing Cargo.lock for known vulnerabilities

cargo audit --version >nul 2>&1
if errorlevel 1 (
    echo [v1_audit] cargo-audit is required; install it with: cargo install cargo-audit --locked 1>&2
    exit /b 127
)

cargo audit %*
exit /b %errorlevel%
