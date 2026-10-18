# Exercise the actual collector with simulated Event Log records. No sample runs,
# real event logs, registry settings, or Sysmon installation are involved.
param([string]$CollectorPath)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $repo 'guest-agent\assets\Collect-FoxholeTelemetry.ps1'
if ($CollectorPath) { $collector = [IO.Path]::GetFullPath($CollectorPath) }
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('foxhole-sysmon-query-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$fixtureInput = Join-Path $fixtureRoot 'request.json'
$fixtureOutput = Join-Path $fixtureRoot 'result.json'
$fixtureTime = [DateTime]::SpecifyKind([DateTime]'2026-09-07T08:00:00', [DateTimeKind]::Utc)
$rootGuid = '{11111111-1111-1111-1111-111111111111}'
$childGuid = '{22222222-2222-2222-2222-222222222222}'
function New-FixtureEvent([int]$Id, [long]$RecordId, [hashtable]$Data) {
    $xmlData = ($Data.Keys | Sort-Object | ForEach-Object { '<Data Name="' + $_ + '">' + [Security.SecurityElement]::Escape([string]$Data[$_]) + '</Data>' }) -join ''
    $record = [pscustomobject]@{ Id=$Id; RecordId=$RecordId; TimeCreated=$fixtureTime; Xml="<Event><EventData>$xmlData</EventData></Event>" }
    $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.Xml }
    return $record
}
function Get-WinEvent {
    [CmdletBinding()]
    param([string]$LogName, [string]$ListLog, [string]$FilterXPath, [hashtable]$FilterHashtable, [int]$MaxEvents=1, [switch]$Oldest)
    if ($ListLog) { return [pscustomobject]@{ LogName=$ListLog } }
    if ($FilterHashtable -and $FilterHashtable.LogName -ne 'Microsoft-Windows-Sysmon/Operational') { return }
    if ($LogName -and $LogName -ne 'Microsoft-Windows-Sysmon/Operational') { return }
    $rows = @($global:FoxholeTestSysmonEvents)
    if ($FilterXPath) {
        if ($FilterXPath -notmatch 'EventRecordID > (\d+)') { throw 'The query must filter the baseline before the event limit.' }
        $baseline = [long]$Matches[1]
        $rows = @($rows | Where-Object { $_.RecordId -gt $baseline })
        if ($FilterXPath -notmatch 'TimeCreated\[@SystemTime >= ') { throw 'The query must retain its time bound.' }
    }
    # The legacy hashtable query included all these recent pre-baseline rows.
    if ($Oldest) { return $rows | Sort-Object RecordId | Select-Object -First $MaxEvents }
    return $rows | Sort-Object RecordId -Descending | Select-Object -First $MaxEvents
}
try {
    $noise = New-FixtureEvent 10 1 @{ ProcessId=999; ProcessGuid='{33333333-3333-3333-3333-333333333333}' }
    $global:FoxholeTestSysmonEvents = @(1..10001 | ForEach-Object { $noise }) + @(
        (New-FixtureEvent 1 10002 @{ ProcessId=4242; ProcessGuid=$rootGuid; ParentProcessGuid='{44444444-4444-4444-4444-444444444444}'; ParentProcessId=111; Image='C:\fixture\target.bin' }),
        (New-FixtureEvent 1 10003 @{ ProcessId=4243; ProcessGuid=$childGuid; ParentProcessGuid=$rootGuid; ParentProcessId=4242; Image='C:\fixture\child.exe' }),
        (New-FixtureEvent 13 10004 @{ ProcessId=4243; ProcessGuid=$childGuid; TargetObject='HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Fixture'; Details='C:\fixture\child.exe' })
    )
    [ordered]@{ root_pid=4242; started_unix_ms=([DateTimeOffset]$fixtureTime).ToUnixTimeMilliseconds(); sysmon_available=$true; sysmon_record_id=10001; security_record_id=0; defender_record_id=0 } | ConvertTo-Json | Set-Content -LiteralPath $fixtureInput -Encoding UTF8
    & $collector -Mode Collect -InputPath $fixtureInput -OutputPath $fixtureOutput
    $result = Get-Content -LiteralPath $fixtureOutput -Raw | ConvertFrom-Json
    if ($result.processes.Count -ne 2 -or $result.registry_observations.Count -ne 1) { Write-Output ($result | ConvertTo-Json -Depth 8); throw 'Pre-baseline noise hid the target process tree or its registry event.' }
    if (@($result.warnings | Where-Object { $_ -match 'target process creation|event limit' }).Count -ne 0) { throw 'The complete fixture incorrectly reported missing or truncated process events.' }
    # Post-baseline excess still consumes the hard cap and must be reported.
    $after = New-FixtureEvent 10 10005 @{ ProcessId=999; ProcessGuid='{33333333-3333-3333-3333-333333333333}' }
    $global:FoxholeTestSysmonEvents += @(1..10001 | ForEach-Object { $after })
    & $collector -Mode Collect -InputPath $fixtureInput -OutputPath $fixtureOutput
    $result = Get-Content -LiteralPath $fixtureOutput -Raw | ConvertFrom-Json
    if (-not $result.truncated -or @($result.warnings | Where-Object { $_ -match 'event limit reached' }).Count -ne 1) { throw 'Post-baseline overflow was not reported.' }
    if ($result.processes.Count -ne 2 -or $result.registry_observations.Count -ne 1) { throw 'The bounded result lost its observed target process tree.' }
    Write-Output 'PASS: old ProcessAccess records do not hide the target; new-record overflow remains bounded and visible.'
} finally {
    Remove-Variable -Name FoxholeTestSysmonEvents -Scope Global -ErrorAction SilentlyContinue
    foreach ($file in @($fixtureInput, $fixtureOutput)) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    Remove-Item -LiteralPath $fixtureRoot
}
