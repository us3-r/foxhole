# Runs only the repository's harmless fixture inside a disposable Hyper-V guest.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaseImage,
    [Parameter(Mandatory)][string]$BaseManifest,
    [Parameter(Mandatory)][string]$GatewayConfig,
    [string]$AnalysisConfig,
    [string]$Compiler = 'g++.exe',
    [string]$Python = 'python.exe',
    [string]$OutputRoot,
    [switch]$SkipBuild,
    [switch]$RequireHostPcapng
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
function Invoke-SmokeCommand([string]$Executable, [string[]]$Arguments) {
    # Windows PowerShell represents native stderr as ErrorRecord on redirection.
    # Keep progress output in the transcript and determine failure from exit status.
    $ErrorActionPreference = 'Continue'
    & $Executable @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "Command failed with exit ${code}: $Executable" }
}
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the smoke test in elevated PowerShell.' }
$token = [guid]::NewGuid().ToString('N')
if (!$OutputRoot) { $OutputRoot = Join-Path $repo "output\smoke-$token" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) { throw 'Smoke output must be a new directory; previous runs are preserved.' }
$gateway = Get-Content -LiteralPath $GatewayConfig -Raw | ConvertFrom-Json
$ip = [string]$gateway.host_ipv4
$port = [int]$gateway.host_service_port
if ($port -lt 1 -or $port -gt 65534 -or $gateway.nat_enabled) { throw 'Use a host-server gateway with a dedicated private IPv4 endpoint.' }
$fixtureDir = Join-Path $repo 'target\smoke-fixture'
New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null
$fixture = Join-Path $fixtureDir 'test_telemetry_smoke.exe'
$foxhole = Join-Path $repo 'target\release\foxhole.exe'
$analyze = Join-Path $repo 'target\release\foxhole-analyze.exe'
$server = $null
$previousPath = $env:PATH
Push-Location $repo
try {
    $compilerPath = (Get-Command $Compiler -ErrorAction Stop).Source
    $env:PATH = (Split-Path -Parent $compilerPath) + ';' + $env:PATH
    if (!$SkipBuild) {
        & cargo build --locked --release --bins
        if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    }
    & $Compiler -std=c++17 -Os -s -ffunction-sections -fdata-sections '-Wl,--gc-sections' -Wall -Wextra -Werror -static (Join-Path $repo 'cpp_files\code\test_telemetry_smoke.cpp') -o $fixture -lwinhttp -lws2_32 -ldnsapi -ladvapi32
    if ($LASTEXITCODE -ne 0) { throw 'Smoke fixture compilation failed.' }
    $doctor = @('doctor','--base-image',$BaseImage,'--base-manifest',$BaseManifest,'--gateway-config',$GatewayConfig,'--network-policy','host-server')
    if ($AnalysisConfig) { $doctor += @('--analysis-config',$AnalysisConfig) }
    Invoke-SmokeCommand $foxhole $doctor
    if ($LASTEXITCODE -ne 0) { throw 'Doctor found failed prerequisites.' }

    # Reuse an existing healthy endpoint; otherwise own only this temporary listener.
    $healthy = $false
    try { $healthy = (Invoke-WebRequest -UseBasicParsing -Uri "http://${ip}:$port/health" -TimeoutSec 3).StatusCode -eq 200 } catch {}
    if (!$healthy) {
        New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
        $pythonPath = (Get-Command $Python -ErrorAction Stop).Source
        $serverScript = Join-Path $PSScriptRoot 'smoke_http_server.py'
        if ($serverScript.Contains('"')) { throw 'Unsupported quote in script path.' }
        $server = Start-Process -FilePath $pythonPath -WindowStyle Hidden -PassThru `
            -ArgumentList @('-u',('"' + $serverScript + '"'),$ip,[string]$port,$token) `
            -RedirectStandardOutput (Join-Path $OutputRoot 'http-server.stdout.log') `
            -RedirectStandardError (Join-Path $OutputRoot 'http-server.stderr.log')
        for ($i=0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 250
            try { $healthy = (Invoke-WebRequest -UseBasicParsing -Uri "http://${ip}:$port/health" -TimeoutSec 1).StatusCode -eq 200 } catch {}
            if ($healthy) { break }
            if ($server.HasExited) { throw 'Smoke HTTP listener failed; inspect http-server.stderr.log.' }
        }
        if (!$healthy) { throw 'No healthy HTTP fixture endpoint; existing services were not stopped or modified.' }
    }
    $arguments = @('--path',$fixture,'--sandbox','hyperv','--hv-profile','n','--mitigation-profile','compatible',
        '--hyperv-base-image',$BaseImage,'--hyperv-base-manifest',$BaseManifest,
        '--allow-host-server','--hyperv-gateway-config',$GatewayConfig,'--output',$OutputRoot,'--timeout','60')
    if ($AnalysisConfig) { $arguments += @('--analysis-config',$AnalysisConfig) }
    $arguments += @('--','--foxhole-smoke',$token,$ip,[string]$port)
    Invoke-SmokeCommand $foxhole $arguments
    if ($LASTEXITCODE -ne 0) { throw "Foxhole run failed. Preserve $OutputRoot for recovery/diagnosis." }
    Invoke-SmokeCommand $analyze @('--no-virustotal',$OutputRoot)
    if ($LASTEXITCODE -ne 0) { throw 'Offline report generation failed.' }
    $resultPath = Join-Path $OutputRoot 'smoke-result.json'
    $verifyArgs = @((Join-Path $PSScriptRoot 'verify_smoke.py'),$OutputRoot,'--token',$token,'--sample',$fixture,'--host-ip',$ip,'--port',[string]$port,'--result',$resultPath)
    if ($AnalysisConfig) { $verifyArgs += '--require-scanners' }
    if ($RequireHostPcapng) { $verifyArgs += '--require-host-pcapng' }
    try { Invoke-SmokeCommand $Python $verifyArgs }
    catch { throw "Smoke evidence verification failed: $resultPath. $($_.Exception.Message)" }
    Write-Output "Smoke passed. Evidence: $resultPath"
    Write-Output "Report: $(Join-Path $OutputRoot 'web\index.html')"
} finally {
    $env:PATH = $previousPath
    if ($server) { if (!$server.HasExited) { $server.Kill(); $server.WaitForExit(5000) | Out-Null }; $server.Dispose() }
    Pop-Location
}
