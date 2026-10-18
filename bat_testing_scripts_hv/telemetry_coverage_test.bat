@echo off
setlocal EnableExtensions DisableDelayedExpansion

echo [telemetry test] start

echo [telemetry test] file create/write/rename/delete
> telemetry-created.txt echo foxhole telemetry marker
ren telemetry-created.txt telemetry-renamed.txt
> telemetry-renamed.txt:foxhole-stream echo alternate data stream marker
type telemetry-renamed.txt > nul
del /q telemetry-renamed.txt

echo [telemetry test] registry create/update/read/delete
reg.exe add HKCU\Software\FoxholeTelemetryTest /v Marker /t REG_SZ /d created /f
reg.exe add HKCU\Software\FoxholeTelemetryTest /v Marker /t REG_SZ /d updated /f
reg.exe query HKCU\Software\FoxholeTelemetryTest /v Marker
reg.exe delete HKCU\Software\FoxholeTelemetryTest /f

echo [telemetry test] child process
cmd.exe /d /c "echo [telemetry child] running"

echo [telemetry test] DNS and TCP attempts; failures are expected with deny-all
nslookup.exe foxhole-telemetry.invalid
curl.exe --max-time 5 --verbose --header "X-Foxhole-Test: telemetry-marker" --data "foxhole-body-marker" http://example.com/telemetry
curl.exe --max-time 5 --verbose http://1.1.1.1:81/

echo [telemetry test] complete
exit /b 0
