@echo off
setlocal

cd /d "%~dp0.." || exit /b 1
echo [v1_cli_help] Testing CLI help and documented options

cargo build --locked %* || exit /b 1
set "foxhole=%cd%\target\debug\foxhole.exe"
set "output=%TEMP%\foxhole-v1-help-%RANDOM%-%RANDOM%.txt"

"%foxhole%" --help >"%output%" 2>&1
if errorlevel 1 goto :fail

findstr /C:"--sandbox" "%output%" >nul || goto :fail
findstr /C:"--dry-run" "%output%" >nul || goto :fail
findstr /C:"--allow-network" "%output%" >nul || goto :fail
findstr /C:"--network-policy" "%output%" >nul || goto :fail
findstr /C:"--no-report" "%output%" >nul || goto :fail

del /q "%output%" >nul 2>&1
exit /b 0

:fail
echo [v1_cli_help] CLI help test failed 1>&2
type "%output%" 1>&2
del /q "%output%" >nul 2>&1
exit /b 1
