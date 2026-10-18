# Runs the production normalizer against synthetic logs; never changes audit policy.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$collector = Join-Path $repo 'guest-agent/assets/Collect-FoxholeTelemetry.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('foxhole-wfp-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$inputFile = Join-Path $root 'input.json'
$outputFile = Join-Path $root 'output.json'
$time = [DateTime]::SpecifyKind([DateTime]'2026-09-08T08:00:00', [DateTimeKind]::Utc)
function Event([int]$Id, [long]$RecordId, [hashtable]$Data, [int]$Seconds=1) {
    $xml = ($Data.Keys | ForEach-Object { '<Data Name="' + $_ + '">' + [Security.SecurityElement]::Escape([string]$Data[$_]) + '</Data>' }) -join ''
    $e = [pscustomobject]@{Id=$Id; RecordId=$RecordId; TimeCreated=$time.AddSeconds($Seconds); Xml="<Event><EventData>$xml</EventData></Event>"}
    $e | Add-Member ScriptMethod ToXml { $this.Xml }
    $e
}
function Get-WinEvent {
    [CmdletBinding()]
    param([string]$LogName, [string]$ListLog, [string]$FilterXPath, [hashtable]$FilterHashtable, [int]$MaxEvents=1, [switch]$Oldest)
    if (($LogName -eq 'Security' -or $ListLog -eq 'Security') -and $global:FoxholeWfpUnavailable) { throw 'simulated access denied' }
    if ($ListLog) { return [pscustomobject]@{ LogName=$ListLog } }
    if ($FilterHashtable) { return }
    $rows = if ($LogName -eq 'Security') { @($global:FoxholeWfpFixture) } else { @($global:FoxholeSysmonFixture) }
    if ($FilterXPath) {
        if ($FilterXPath -notmatch 'EventRecordID > (\d+)') { throw 'baseline must be applied before MaxEvents' }
        $baseline = [long]$Matches[1]
        $rows = @($rows | Where-Object { $_.RecordId -gt $baseline })
        if ($LogName -eq 'Security') {
            if ($FilterXPath -notmatch '@SystemTime <= ') { throw 'execution end bound missing' }
            $rows = @($rows | Where-Object { $_.TimeCreated -ge $time -and $_.TimeCreated -le $time.AddSeconds(5) })
        }
    }
    $sorted = if ($Oldest) { @($rows | Sort-Object RecordId) } else { @($rows | Sort-Object RecordId -Descending) }
    $sorted = @($sorted)
    for ($index=0; $index -lt [Math]::Min($MaxEvents, $sorted.Count); $index++) { $sorted[$index] }
}
function Collect {
    & $collector -Mode Collect -InputPath $inputFile -OutputPath $outputFile
    Get-Content -LiteralPath $outputFile -Raw | ConvertFrom-Json
}
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
    $global:FoxholeWfpUnavailable=$false
    $global:FoxholeSysmonFixture = @(
        (Event 1 11 @{ ProcessId=4242; ProcessGuid='root'; ParentProcessGuid='other'; Image='C:\target.exe' } 0),
        (Event 1 12 @{ ProcessId=4243; ProcessGuid='child'; ParentProcessGuid='root'; Image='C:\child.exe' } 0),
        (Event 5 13 @{ ProcessId=4243; ProcessGuid='child' } 2),
        (Event 1 14 @{ ProcessId=4243; ProcessGuid='reused'; ParentProcessGuid='other' } 3),
        (Event 1 15 @{ ProcessId=4242; ProcessGuid='root-reused'; ParentProcessGuid='other' } 4)
    )
    $global:FoxholeWfpFixture = @(Event 5156 1 @{ ProcessID=99 }) # old noise must not consume the query cap
    foreach ($id in 5152..5159) {
        $global:FoxholeWfpFixture += Event $id ($id + 100) @{ ProcessID='0x1093'; Application='\device\volume\child.exe'; Protocol=17; Direction='%%14593'; SourceAddress='10.0.0.2'; SourcePort=50000; DestAddress='8.8.8.8'; DestPort=443 }
    }
    $global:FoxholeWfpFixture += @(
        (Event 5156 5300 @{ ProcessID=4242; Protocol=6; Direction='%%14592'; SourceAddress='8.8.8.8'; SourcePort=443; DestAddress='10.0.0.2'; DestPort=50001 }),
        (Event 5157 5301 @{ ProcessID=0; Protocol=6; SourceAddress='10.0.0.2'; DestAddress='1.1.1.1' }),
        (Event 5157 5302 @{ ProcessID=4243; Protocol=6 } 4),
        (Event 5157 5303 @{ ProcessID=4242; Protocol=6 } 5),
        (Event 5157 5304 @{ ProcessID=4242; Protocol=6 } 9)
    )
    @{ root_pid=4242; started_unix_ms=([DateTimeOffset]$time).ToUnixTimeMilliseconds(); ended_unix_ms=([DateTimeOffset]$time.AddSeconds(5)).ToUnixTimeMilliseconds(); sysmon_available=$true; wfp_available=$true; sysmon_record_id=10; security_record_id=100; defender_record_id=0 } | ConvertTo-Json | Set-Content -LiteralPath $inputFile -Encoding UTF8
    # A delayed setup record has a new record ID but predates observation.
    $global:FoxholeWfpFixture += Event 4719 5305 @{} -1
    $r = Collect
    Assert (-not $r.capture_health[0].loss_detected) 'setup policy change leaked into observation window'
    $raw = @($r.raw_events | Where-Object source -eq windows_filtering_platform)
    Assert ($raw.Count -eq 12) ('WFP rows=' + $raw.Count + '; health=' + ($r.capture_health | ConvertTo-Json -Depth 5 -Compress))
    Assert ($r.network_connections.Count -eq 9) 'PID reuse or unattributed event was falsely assigned to target'
    Assert ($raw[0].pid -eq 4243 -and $raw[0].protocol -eq 'udp') 'hex PID or UDP normalization failed'
    Assert ($raw[0].correlation.confidence -eq 'medium' -and $raw[0].correlation.reason -match 'lifetime') 'inferred attribution reason missing'
    Assert ($raw[0].image -eq '\device\volume\child.exe' -and $raw[0].time_utc) 'image or timestamp missing'
    Assert ($raw[8].local_address -eq '10.0.0.2' -and $raw[8].local_port -eq 50001 -and $raw[8].remote_port -eq 443) 'inbound endpoints reversed'
    Assert ($raw[9].correlation.confidence -eq 'none' -and $null -eq $raw[9].pid) 'unknown PID was invented'
    Assert ($r.network_connections[0].event.event_id -eq 5152) 'report event context missing'
    Assert ($r.capture_health[0].started -and $r.capture_health[0].stopped -and $r.capture_health[0].captured_events -eq 12) 'WFP health state/count mismatch'
    Assert ($null -eq $r.capture_health[0].dropped_events) 'unknown loss counter must be null'
    $global:FoxholeWfpFixture += Event 4719 5306 @{} 4
    $r = Collect
    Assert ($r.capture_health[0].loss_detected) 'in-window policy change must remain visible'
    $global:FoxholeWfpFixture += Event 1101 5305 @{} 4
    $r = Collect
    Assert ($r.capture_health[0].loss_detected -and $r.capture_health[0].provider_errors.Count -gt 0) 'audit loss not reported'
    $noise = Event 5152 6000 @{ ProcessID=999; Protocol=17 }
    $global:FoxholeWfpFixture += @(1..10001 | ForEach-Object { $noise })
    $r = Collect
    Assert ($r.capture_health[0].truncated -and $r.capture_health[0].captured_events -eq 10000 -and $r.capture_health[0].retained_events -eq 5000) ('event bounds or truncation missing: ' + ($r.capture_health | ConvertTo-Json -Compress -Depth 5))
    Assert (@($r.warnings | Where-Object { $_ -match 'coverage is incomplete' }).Count -gt 0) 'truncation warning missing'
    # Exercise the independent byte bound below the event-count ceiling.
    $large = Event 5152 7000 @{ ProcessID=999; Application=('x' * 4096); Protocol=17 }
    $global:FoxholeWfpFixture = @(1..1200 | ForEach-Object { $large })
    $r = Collect
    Assert ($r.capture_health[0].truncated -and $r.capture_health[0].captured_events -eq 1200 -and $r.capture_health[0].retained_events -lt 1200 -and $r.capture_health[0].captured_bytes -le 8MB) 'raw byte budget not enforced'
    $request = Get-Content -LiteralPath $inputFile -Raw | ConvertFrom-Json
    $request.sysmon_available=$false
    $request | ConvertTo-Json | Set-Content -LiteralPath $inputFile -Encoding UTF8
    $global:FoxholeWfpFixture = @(Event 5157 8000 @{ ProcessID=4242; Protocol=6 })
    $r = Collect
    Assert ($r.network_connections[0].event.correlation.confidence -eq 'low') 'PID-only inference must be marked low confidence'
    $global:FoxholeWfpUnavailable=$true
    $r = Collect
    Assert (-not $r.capture_health[0].stopped -and $r.capture_health[0].provider_errors.Count -gt 0) 'unavailable Security channel masked'
    Write-Output 'PASS: WFP normalization, inbound direction, allowed/blocked/bind/listen events, PID reuse, raw retention, execution bounds, truncation, loss and unavailable-channel health.'
} finally {
    Remove-Variable -Name FoxholeWfpFixture,FoxholeSysmonFixture,FoxholeWfpUnavailable -Scope Global -ErrorAction SilentlyContinue
    foreach ($file in @($inputFile,$outputFile)) { if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file } }
    Remove-Item -LiteralPath $root
}
