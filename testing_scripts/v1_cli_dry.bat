@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_cli_dry] Testing dry-run and target argument parsing

cargo build --locked %* || exit /b 1
set "foxhole=%cd%\target\debug\foxhole.exe"
set "output=%TEMP%\foxhole-v1-dry-%RANDOM%-%RANDOM%.txt"

"%foxhole%" --path "%foxhole%" --sandbox --dry-run --no-report --timeout 7 -- --example value >"%output%" 2>&1
if errorlevel 1 goto :fail
findstr /C:"dry run validated executable" "%output%" >nul || goto :fail

del /q "%output%" >nul 2>&1
exit /b 0

:fail
echo [v1_cli_dry] Dry-run test failed 1>&2
type "%output%" 1>&2
del /q "%output%" >nul 2>&1
exit /b 1
