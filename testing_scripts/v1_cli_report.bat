@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_cli_report] Testing report creation and --no-report

cargo build --locked %* || exit /b 1
set "foxhole=%cd%\target\debug\foxhole.exe"
set "test_id=%RANDOM%-%RANDOM%"
set "created_name=v1-created-%test_id%.json"
set "blocked_name=v1-no-report-%test_id%.json"
set "created_path=%LOCALAPPDATA%\Foxhole\artifacts\reports\functional\%created_name%"
set "blocked_path=%LOCALAPPDATA%\Foxhole\artifacts\reports\functional\%blocked_name%"

if exist "%created_path%" (
    echo [v1_cli_report] Refusing to overwrite existing test artifact: %created_path% 1>&2
    exit /b 1
)
if exist "%blocked_path%" (
    echo [v1_cli_report] Refusing to use existing test artifact: %blocked_path% 1>&2
    exit /b 1
)

"%foxhole%" --path "%foxhole%" --sandbox --dry-run --report "functional\%created_name%" >nul 2>&1
if errorlevel 1 goto :fail
if not exist "%created_path%" (
    echo [v1_cli_report] Expected report was not created 1>&2
    goto :fail
)
findstr /C:"\"schema_version\": \"2.0\"" "%created_path%" >nul || (
    echo [v1_cli_report] Created report has the wrong schema 1>&2
    goto :fail
)

"%foxhole%" --path "%foxhole%" --sandbox --dry-run --no-report --report "functional\%blocked_name%" >nul 2>&1
if errorlevel 1 goto :fail
if exist "%blocked_path%" (
    echo [v1_cli_report] --no-report unexpectedly created a report 1>&2
    goto :fail
)

del /q "%created_path%" >nul 2>&1
if exist "%created_path%" (
    echo [v1_cli_report] Could not remove the test report 1>&2
    exit /b 1
)
exit /b 0

:fail
if exist "%created_path%" del /q "%created_path%" >nul 2>&1
if exist "%blocked_path%" del /q "%blocked_path%" >nul 2>&1
exit /b 1
