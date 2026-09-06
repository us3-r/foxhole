@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Foxhole bounded telemetry demo. Foxhole streams this file to cmd.exe, so
rem guaranteed artifacts are written directly in the existing work folder.
rem No PowerShell dependency is used: restricted guests may terminate it during
rem PSEtwLog initialization even when the executable path is absolute.

set "ROOT=%CD%"
set "LOG=%ROOT%\what_can_be.log"
set "CMD=%SystemRoot%\System32\cmd.exe"
set "CURL=%SystemRoot%\System32\curl.exe"
set "REG=%SystemRoot%\System32\reg.exe"
set "CIPHER=%SystemRoot%\System32\cipher.exe"
set "PING=%SystemRoot%\System32\ping.exe"
set "IPCONFIG=%SystemRoot%\System32\ipconfig.exe"
set "ROUTE=%SystemRoot%\System32\route.exe"
set "NSLOOKUP=%SystemRoot%\System32\nslookup.exe"
set "NETSTAT=%SystemRoot%\System32\netstat.exe"
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "STAGE1=%ROOT%\process-stage-1.cmd"
set "STAGE2=%ROOT%\process-stage-2.cmd"
set "STAGE3=%ROOT%\process-stage-3.cmd"
set "STAGE4=%ROOT%\process-stage-4.cmd"
set "STAGE5=%ROOT%\process-stage-5.cmd"
set "STAGE6=%ROOT%\process-stage-6.cmd"
set "MASS_STAGE=%ROOT%\mass-file-stage.cmd"

> "%LOG%" echo Foxhole native telemetry demo started

echo [1/7] Files and folder probe
mkdir "%ROOT%\FoxholeDemoFolders" 2>>"%LOG%"
> "%ROOT%\created.txt" echo Foxhole disposable file telemetry canary
>> "%ROOT%\created.txt" echo second write
copy /y "%ROOT%\created.txt" "%ROOT%\renamed.txt" >nul 2>>"%LOG%"
copy /y "%ROOT%\renamed.txt" "%ROOT%\copied.txt" >nul 2>>"%LOG%"
del /q "%ROOT%\created.txt" "%ROOT%\copied.txt" 2>>"%LOG%"

echo [2/7] NTFS alternate data stream probe
> "%ROOT%\ads-carrier.txt" echo Visible Foxhole ADS carrier
> "%ROOT%\ads-carrier.txt:foxhole-demo" echo Disposable alternate stream marker

rem The runner's policy decides whether outbound traffic is permitted. Every
rem command below still executes, and its output plus exit code reaches stdout.
echo [3/7] Executing and logging native network commands
echo [network-command] ipconfig /all
>> "%LOG%" echo [network-command] ipconfig /all
"%IPCONFIG%" /all >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] ipconfig exit_code=%RC%
>> "%LOG%" echo [network-result] ipconfig exit_code=%RC%

echo [network-command] route print
>> "%LOG%" echo [network-command] route print
"%ROUTE%" print >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] route exit_code=%RC%
>> "%LOG%" echo [network-result] route exit_code=%RC%

echo [network-command] ping 127.0.0.1
>> "%LOG%" echo [network-command] ping 127.0.0.1
"%PING%" -n 2 -w 1000 127.0.0.1 >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] ping_loopback exit_code=%RC%
>> "%LOG%" echo [network-result] ping_loopback exit_code=%RC%

echo [network-command] nslookup example.com
>> "%LOG%" echo [network-command] nslookup example.com
"%NSLOOKUP%" example.com >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] nslookup_example exit_code=%RC%
>> "%LOG%" echo [network-result] nslookup_example exit_code=%RC%

set "NET_TOKEN=%RANDOM%%RANDOM%"
echo [network-command] curl example.com sequence=1 token=%NET_TOKEN%
>> "%LOG%" echo [network-command] curl example.com sequence=1 token=%NET_TOKEN%
"%CURL%" --noproxy "*" --connect-timeout 3 --max-time 5 --silent --show-error --head --header "X-Foxhole-Run: %NET_TOKEN%" --header "X-Foxhole-Sequence: 1" --user-agent "Foxhole-Telemetry-Demo/%RANDOM%" "http://example.com/?foxhole=%NET_TOKEN%" >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] curl_example exit_code=%RC%
>> "%LOG%" echo [network-result] curl_example exit_code=%RC%

echo [network-command] curl TEST-NET-1 sequence=2
>> "%LOG%" echo [network-command] curl TEST-NET-1 sequence=2
"%CURL%" --noproxy "*" --connect-timeout 2 --max-time 2 --silent --show-error --head --header "X-Foxhole-Sequence: 2" http://192.0.2.1/ >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] curl_test_net exit_code=%RC%
>> "%LOG%" echo [network-result] curl_test_net exit_code=%RC%

echo [network-command] curl loopback sequence=3
>> "%LOG%" echo [network-command] curl loopback sequence=3
"%CURL%" --noproxy "*" --connect-timeout 2 --max-time 2 --silent --show-error --head --header "X-Foxhole-Sequence: 3" http://127.0.0.1:9/ >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] curl_loopback exit_code=%RC%
>> "%LOG%" echo [network-result] curl_loopback exit_code=%RC%

echo [network-command] netstat -ano
>> "%LOG%" echo [network-command] netstat -ano
"%NETSTAT%" -ano >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [network-result] netstat exit_code=%RC%
>> "%LOG%" echo [network-result] netstat exit_code=%RC%

echo [4/7] Two deep process branches with seven generations each
> "%STAGE1%" echo @echo off
>> "%STAGE1%" echo echo [process-tree] generation=1
>> "%STAGE1%" echo "%CMD%" /d /c call "%STAGE2%"
> "%STAGE2%" echo @echo off
>> "%STAGE2%" echo echo [process-tree] generation=2
>> "%STAGE2%" echo "%CMD%" /d /c call "%STAGE3%"
> "%STAGE3%" echo @echo off
>> "%STAGE3%" echo echo [process-tree] generation=3 branch=A
>> "%STAGE3%" echo "%CMD%" /d /c call "%STAGE4%"
>> "%STAGE3%" echo echo [process-tree] generation=3 branch=B
>> "%STAGE3%" echo "%CMD%" /d /c call "%STAGE4%"
> "%STAGE4%" echo @echo off
>> "%STAGE4%" echo echo [process-tree] generation=4
>> "%STAGE4%" echo "%CMD%" /d /c call "%STAGE5%"
> "%STAGE5%" echo @echo off
>> "%STAGE5%" echo echo [process-tree] generation=5
>> "%STAGE5%" echo "%CMD%" /d /c call "%STAGE6%"
> "%STAGE6%" echo @echo off
>> "%STAGE6%" echo echo [process-tree] generation=6 leaf=ping
>> "%STAGE6%" echo "%PING%" -n 2 -w 250 127.0.0.1 ^> nul
echo [process-tree] generation=0 branch=1
"%CMD%" /d /c call "%STAGE1%"
echo [process-tree] generation=0 branch=2
"%CMD%" /d /c call "%STAGE1%"

echo [5/7] Transient Startup and RunOnce probes
if not exist "%STARTUP%" mkdir "%STARTUP%" >> "%LOG%" 2>&1
if not exist "%STARTUP%" (
  >> "%LOG%" echo startup_file_attempt skipped_unavailable path="%STARTUP%"
) else (
  if not exist "%STARTUP%\what_can_be.bat" (
    > "%STARTUP%\what_can_be.bat" echo @echo off
    >> "%STARTUP%\what_can_be.bat" echo echo Foxhole one-shot startup probe
    >> "%STARTUP%\what_can_be.bat" echo exit /b 0
    >> "%LOG%" echo startup_file_attempt path="%STARTUP%\what_can_be.bat"
    del /q "%STARTUP%\what_can_be.bat" >> "%LOG%" 2>&1
  ) else (
    >> "%LOG%" echo startup_file_attempt skipped_existing
  )
)
set "RUN_VALUE=FoxholeDemoOneShot_%RANDOM%%RANDOM%"
"%REG%" add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "%RUN_VALUE%" /t REG_SZ /d "cmd.exe /d /c exit /b 0" /f >nul 2>>"%LOG%"
"%REG%" query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "%RUN_VALUE%" >>"%LOG%" 2>&1
"%REG%" delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "%RUN_VALUE%" /f >nul 2>>"%LOG%"

echo [6/7] Rapid disposable file creation for mass-file telemetry
> "%MASS_STAGE%" echo @echo off
>> "%MASS_STAGE%" echo setlocal EnableExtensions EnableDelayedExpansion
>> "%MASS_STAGE%" echo set /a N=1
>> "%MASS_STAGE%" echo :mass_loop
>> "%MASS_STAGE%" echo ^> "%ROOT%\mass-document-!N!.txt" echo Foxhole disposable mass-file canary !N!
>> "%MASS_STAGE%" echo set /a N+=1
>> "%MASS_STAGE%" echo if !N! LEQ 520 goto mass_loop
"%CMD%" /d /c call "%MASS_STAGE%"

echo [7/7] Final recoverable encryption probes
> "%ROOT%\canary-01.txt" echo Recoverable plaintext Foxhole canary 01
> "%ROOT%\canary-02.txt" echo Recoverable plaintext Foxhole canary 02
copy /y "%ROOT%\canary-01.txt" "%ROOT%\canary-01.txt.encrypted" >nul 2>>"%LOG%"
copy /y "%ROOT%\canary-02.txt" "%ROOT%\canary-02.txt.encrypted" >nul 2>>"%LOG%"
"%CIPHER%" /e /a "%ROOT%\canary-01.txt.encrypted" "%ROOT%\canary-02.txt.encrypted" >>"%LOG%" 2>&1
> "%ROOT%\README_RECOVERY.txt" echo Plaintext canaries were retained; encrypted files are disposable test copies.
mkdir "%ROOT%\FoxholeDemoCanary" 2>>"%LOG%"
copy /y "%ROOT%\canary-01.txt" "%ROOT%\FoxholeDemoCanary\program-files-canary.txt" >nul 2>>"%LOG%"
"%CIPHER%" /e /a "%ROOT%\FoxholeDemoCanary\program-files-canary.txt" >>"%LOG%" 2>&1
>> "%LOG%" echo Program Files probe intentionally limited to a dedicated canary directory.

echo [report-log-begin] what_can_be.log
type "%LOG%"
echo [report-log-end] what_can_be.log

exit /b 0
