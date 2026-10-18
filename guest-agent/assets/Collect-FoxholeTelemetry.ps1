param(
    [Parameter(Mandatory = $true)][ValidateSet('Baseline', 'Collect')][string] $Mode,
    [Parameter(Mandatory = $true)][string] $InputPath,
    [Parameter(Mandatory = $true)][string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$defenderLog = 'Microsoft-Windows-Windows Defender/Operational'
$maxEvents = 10000
$maxRawEvents = 5000
$maxHashedFiles = 2048
$maxHashFileBytes = 128MB
$maxHashTotalBytes = 256MB

function Write-Result([object] $Value) {
    if ($Value.Contains('raw_events')) {
        # Reserve the raw archive (8 MiB) even when verbose structured views overflow.
        # The Rust helper accepts at most 16 MiB for the entire response.
        [long]$structuredBytes = 0
        foreach ($field in @('processes','network_connections','file_observations','registry_observations')) {
            $kept = [Collections.Generic.List[object]]::new()
            $clipped = $false
            foreach ($row in $Value[$field]) {
                $bytes = [Text.Encoding]::UTF8.GetByteCount(($row | ConvertTo-Json -Compress -Depth 8)) + 1
                if (($structuredBytes + $bytes) -le 6MB) { $kept.Add($row); $structuredBytes += $bytes }
                else { $clipped = $true }
            }
            $Value[$field] = @($kept)
            if ($clipped) {
                $Value.truncated = $true
                $Value.warnings += "structured $field byte limit reached; raw events have an independent bounded archive"
                if ($field -eq 'network_connections') {
                    $Value.capture_health[0].truncated = $true
                    $Value.capture_health[0].warnings += 'Structured network observations exceeded the shared 6 MiB view limit.'
                }
            }
        }
    }
    $json = $Value | ConvertTo-Json -Compress -Depth 8
    [IO.File]::WriteAllText($OutputPath, $json, [Text.UTF8Encoding]::new($false))
}

function Last-Record([string] $LogName) {
    try {
        $event = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        if ($null -eq $event) { return [uint64]0 }
        return [uint64]$event.RecordId
    } catch {
        return [uint64]0
    }
}

function Event-Data([object] $Event) {
    $values = @{}
    $xml = [xml]$Event.ToXml()
    foreach ($item in @($xml.Event.EventData.Data)) {
        if ($null -eq $item -or [string]::IsNullOrWhiteSpace([string]$item.Name)) { continue }
        $values[[string]$item.Name] = [string]$item.'#text'
    }
    return $values
}

function Parse-Pid([string] $Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return [uint32]0 }
    try {
        if ($Value.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            return [Convert]::ToUInt32($Value.Substring(2), 16)
        }
        return [Convert]::ToUInt32($Value, 10)
    } catch { return [uint32]0 }
}

function Parse-Port([string] $Value) {
    $port = Parse-Pid $Value
    if ($port -gt 65535) { return [uint16]0 }
    return [uint16]$port
}

function Bounded([string] $Value, [int] $Limit = 4096) {
    if ($null -eq $Value) { return '' }
    if ($Value.Length -le $Limit) { return $Value }
    return $Value.Substring(0, $Limit)
}

function Bounded-EventData([hashtable] $Data) {
    $boundedData = [ordered]@{}
    foreach ($name in $Data.Keys) {
        $boundedData[(Bounded ([string]$name) 256)] = Bounded ([string]$Data[$name]) 4096
    }
    return $boundedData
}

function Parse-Sha256([string] $Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $match = [regex]::Match(
        $Value,
        '(?i)(?:^|,)\s*SHA256=([0-9a-f]{64})(?:,|$)',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success) { return $null }
    return $match.Groups[1].Value.ToLowerInvariant()
}

function Read-BoundedFileSha256([string] $Path, [uint64] $RemainingBytes) {
    $stream = $null
    $algorithm = $null
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return [pscustomobject]@{ status = 'non_regular' }
        }
        $length = [uint64]$item.Length
        if ($length -gt [uint64]$maxHashFileBytes -or $length -gt $RemainingBytes) {
            return [pscustomobject]@{ status = 'skipped'; size_bytes = $length }
        }
        $stream = [IO.File]::Open(
            $item.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ([uint64]$stream.Length -ne $length) {
            return [pscustomobject]@{ status = 'unavailable' }
        }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        $digest = $algorithm.ComputeHash($stream)
        if ([uint64]$stream.Length -ne $length) {
            return [pscustomobject]@{ status = 'unavailable' }
        }
        return [pscustomobject]@{
            status = 'hashed'
            size_bytes = $length
            sha256 = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
        }
    } catch {
        return [pscustomobject]@{ status = 'unavailable' }
    } finally {
        if ($null -ne $algorithm) { $algorithm.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Elapsed-Ms([object] $Event, [int64] $StartedUnixMs) {
    try {
        $timestamp = [DateTimeOffset]$Event.TimeCreated
        return [uint64][Math]::Max(0, $timestamp.ToUnixTimeMilliseconds() - $StartedUnixMs)
    } catch { return [uint64]0 }
}

function Test-SysmonReadiness {
    try {
        $probe = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
            -ArgumentList @('/d', '/c', 'ver') -WindowStyle Hidden -Wait -PassThru
        $probeId = [uint32]$probe.Id
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            Start-Sleep -Milliseconds 200
            $events = @(Get-WinEvent -FilterHashtable @{ LogName=$sysmonLog; Id=1 } -MaxEvents 256 -ErrorAction SilentlyContinue)
            foreach ($event in $events) {
                $data = Event-Data $event
                if ((Parse-Pid $data.ProcessId) -eq $probeId) { return $true }
            }
        } while ([DateTime]::UtcNow -lt $deadline)
    } catch { return $false }
    return $false
}

if ($Mode -eq 'Baseline') {
    $warnings = [Collections.Generic.List[string]]::new()
    $sysmonAvailable = $false
    $sysmonExe = 'C:\Foxhole\Telemetry\Sysmon64.exe'
    $sysmonConfig = 'C:\Foxhole\Telemetry\sysmon-config.xml'
    if ((Test-Path -LiteralPath $sysmonExe -PathType Leaf) -and
        (Test-Path -LiteralPath $sysmonConfig -PathType Leaf)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $sysmonExe
        if ($signature.Status -ne 'Valid' -or
            [string]$signature.SignerCertificate.Subject -notmatch 'Microsoft') {
            $warnings.Add('staged Sysmon binary does not have a valid Microsoft signature')
        } else {
            $registeredService = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue |
                Select-Object -First 1
            $sysmonOperation = if ($null -eq $registeredService) { 'installation' } else { 'configuration update' }
            $sysmonArguments = if ($null -eq $registeredService) {
                @('-accepteula', '-i', $sysmonConfig)
            } else {
                if ($registeredService.Status -ne 'Running') {
                    Start-Service -Name $registeredService.Name -ErrorAction SilentlyContinue
                }
                @('-c', $sysmonConfig)
            }
            $sysmonStdout = 'C:\Foxhole\Telemetry\sysmon-setup-stdout.txt'
            $sysmonStderr = 'C:\Foxhole\Telemetry\sysmon-setup-stderr.txt'
            $sysmonExitCode = -1
            $sysmonOutput = ''
            try {
                try {
                    $sysmonProcess = Start-Process -FilePath $sysmonExe `
                        -ArgumentList $sysmonArguments `
                        -RedirectStandardOutput $sysmonStdout `
                        -RedirectStandardError $sysmonStderr `
                        -WindowStyle Hidden -Wait -PassThru
                    $sysmonExitCode = $sysmonProcess.ExitCode
                } catch {
                    $sysmonOutput = $_.Exception.Message
                }
                foreach ($diagnosticFile in @($sysmonStdout, $sysmonStderr)) {
                    if (Test-Path -LiteralPath $diagnosticFile -PathType Leaf) {
                        $bytes = [IO.File]::ReadAllBytes($diagnosticFile)
                        if ($bytes.Length -gt 0) {
                            $sysmonOutput += [Text.Encoding]::Unicode.GetString($bytes)
                        }
                    }
                }
            } finally {
                Remove-Item -LiteralPath $sysmonStdout, $sysmonStderr -Force -ErrorAction SilentlyContinue
            }
            if ($sysmonExitCode -eq 0) {
                $serviceDeadline = [DateTime]::UtcNow.AddSeconds(10)
                do {
                    $sysmonService = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue |
                        Where-Object { $_.Status -eq 'Running' } |
                        Select-Object -First 1
                    if ($null -eq $sysmonService) { Start-Sleep -Milliseconds 200 }
                } while ($null -eq $sysmonService -and [DateTime]::UtcNow -lt $serviceDeadline)
                if ($null -eq $sysmonService) {
                    $warnings.Add("Sysmon $sysmonOperation completed but its service did not reach Running within 10 seconds")
                } else {
                    Start-Sleep -Milliseconds 500
                    Get-WinEvent -ListLog $sysmonLog -ErrorAction Stop | Out-Null
                    $sysmonAvailable = $true
                }
            } else {
                $warnings.Add("Sysmon $sysmonOperation failed with exit code $sysmonExitCode`: $(Bounded $sysmonOutput 4096)")
            }
        }
    } else {
        $warnings.Add('no staged Microsoft-signed Sysmon package and configuration are available')
    }
    if ($sysmonAvailable -and -not (Test-SysmonReadiness)) {
        $warnings.Add('Sysmon channel exists but an exact process-creation readiness probe was not observed')
        $sysmonAvailable = $false
    }
    $wfpAvailable = $true
    # Locale-independent subcategory GUIDs: Packet Drop and Connection.
    foreach ($subcategory in @('{0CCE9225-69AE-11D9-BED3-505054503030}', '{0CCE9226-69AE-11D9-BED3-505054503030}')) {
        try {
            & "$env:SystemRoot\System32\auditpol.exe" /set /subcategory:$subcategory /success:enable /failure:enable | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol exited $LASTEXITCODE" }
        } catch { $wfpAvailable = $false; $warnings.Add("could not enable WFP audit subcategory $subcategory`: $($_.Exception.Message)") }
    }
    try { Get-WinEvent -ListLog Security -ErrorAction Stop | Out-Null } catch { $wfpAvailable = $false; $warnings.Add('Security log unavailable') }
    Write-Result ([ordered]@{
        wfp_available = $wfpAvailable
        sysmon_available = $sysmonAvailable
        sysmon_record_id = if ($sysmonAvailable) { Last-Record $sysmonLog } else { [uint64]0 }
        security_record_id = Last-Record 'Security'
        defender_record_id = Last-Record $defenderLog
        warnings = @($warnings)
    })
    exit 0
}

$request = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
$warnings = [Collections.Generic.List[string]]::new()
$eventEndTime = if ($request.ended_unix_ms) { [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$request.ended_unix_ms).UtcDateTime } else { [DateTime]::UtcNow }
$eventStartTime = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$request.started_unix_ms).LocalDateTime.AddSeconds(-2)
$sysmonRows = @()
$truncated = $false
if ([bool]$request.sysmon_available) {
    try {
        Get-WinEvent -ListLog $sysmonLog -ErrorAction Stop | Out-Null
        $structuredIds = @(1,3,5,8,9,10,11,12,13,14,15,17,18,22,25,26,27,28,29,255)
        # Apply the baseline inside Event Log, before MaxEvents. Filtering it after
        # the cap lets older high-volume ProcessAccess records hide the target tree.
        $eventIdFilter = ($structuredIds | ForEach-Object { 'EventID=' + [int]$_ }) -join ' or '
        $sysmonStartUtc = $eventStartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
        $sysmonQuery = "*[System[($eventIdFilter) and EventRecordID > $([uint64]$request.sysmon_record_id) and TimeCreated[@SystemTime >= '$sysmonStartUtc']]]"
        $events = @()
        $targetProcessObserved = $false
        $sysmonDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $events = @(Get-WinEvent -LogName $sysmonLog -FilterXPath $sysmonQuery `
                -Oldest -MaxEvents ($maxEvents + 1) -ErrorAction SilentlyContinue)
            foreach ($candidate in $events) {
                if ([int]$candidate.Id -ne 1) { continue }
                $candidateData = Event-Data $candidate
                if ((Parse-Pid $candidateData.ProcessId) -eq [uint32]$request.root_pid) {
                    $targetProcessObserved = $true
                    break
                }
            }
            if (-not $targetProcessObserved -and [DateTime]::UtcNow -lt $sysmonDeadline) {
                Start-Sleep -Milliseconds 250
            }
        } while (-not $targetProcessObserved -and [DateTime]::UtcNow -lt $sysmonDeadline)
        if ($events.Count -eq 0) {
            $warnings.Add("Sysmon emitted no records after baseline $([uint64]$request.sysmon_record_id); latest record is $(Last-Record $sysmonLog)")
        } elseif (-not $targetProcessObserved) {
            $warnings.Add("Sysmon did not emit the target process creation event within the bounded five-second collection window")
        }
        if ($events.Count -gt $maxEvents) {
            $events = @($events | Select-Object -First $maxEvents)
            $truncated = $true
            $warnings.Add("Sysmon event limit reached at $maxEvents records")
        }
        $sysmonRows = @($events | ForEach-Object {
            [pscustomobject]@{ event = $_; data = Event-Data $_ }
        })
    } catch { $warnings.Add("Sysmon event query failed: $($_.Exception.Message)") }
}

$guids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$pids = [Collections.Generic.HashSet[uint32]]::new()
$null = $pids.Add([uint32]$request.root_pid)
$rootCreation = @($sysmonRows | Where-Object { [int]$_.event.Id -eq 1 -and (Parse-Pid $_.data.ProcessId) -eq [uint32]$request.root_pid } | Sort-Object { $_.event.TimeCreated }, { $_.event.RecordId } | Select-Object -First 1)
$rootGuid = if ($rootCreation.Count -gt 0) { [string]$rootCreation[0].data.ProcessGuid } else { '' }
$changed = $true
while ($changed) {
    $changed = $false
    foreach ($row in $sysmonRows) {
        if ([int]$row.event.Id -ne 1) { continue }
        $processId = Parse-Pid $row.data.ProcessId
        $guid = [string]$row.data.ProcessGuid
        $parentGuid = [string]$row.data.ParentProcessGuid
        if ((-not [string]::IsNullOrWhiteSpace($rootGuid) -and $guid -eq $rootGuid) -or $guids.Contains($parentGuid)) {
            if (-not [string]::IsNullOrWhiteSpace($guid) -and $guids.Add($guid)) { $changed = $true }
            if ($pids.Add($processId)) { $changed = $true }
        }
    }
}

$processes = [Collections.Generic.List[object]]::new()
$network = [Collections.Generic.List[object]]::new()
$files = [Collections.Generic.List[object]]::new()
$registry = [Collections.Generic.List[object]]::new()
$rawEvents = [Collections.Generic.List[object]]::new()
$rawEventsTruncated = $false
$script:rawBytes = 2
function Add-RawEvent([object]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetByteCount(($Value | ConvertTo-Json -Compress -Depth 8)) + 1
    if ($rawEvents.Count -ge $maxRawEvents -or ($script:rawBytes + $bytes) -gt 8MB) {
        $script:rawEventsTruncated = $true
        $script:truncated = $true
        return
    }
    $script:rawBytes += $bytes
    $rawEvents.Add($Value)
}
# Index ALL observed process incarnations, including PID reuse outside the target tree.
$incarnations = @{}
$terminations = @{}
foreach ($row in $sysmonRows) {
    if ([int]$row.event.Id -eq 5) { $terminations[[string]$row.data.ProcessGuid] = $row.event.TimeCreated }
    if ([int]$row.event.Id -eq 1) {
        $key = [string](Parse-Pid $row.data.ProcessId)
        if (-not $incarnations.ContainsKey($key)) { $incarnations[$key] = @() }
        $incarnations[$key] += $row
    }
}
$wfpCollected = $false
$wfpHealth = [ordered]@{
    channel='guest_wfp'; requested=$true; started=[bool]$request.wfp_available; stopped=$false
    byte_limit=8388608; event_limit=$maxEvents; raw_event_limit=$maxRawEvents
    captured_events=0; retained_events=0; captured_bytes=0; truncated=$false
    dropped_events=$null; dropped_packets=$null; loss_detected=$false
    provider_errors=@(); artifacts=@('extracted-files/telemetry-events.json')
    warnings=@('Security audit loss counts are unknown; events lost before instrumentation and guest-admin tampering can prevent complete observation.')
}
try {
    Get-WinEvent -ListLog Security -ErrorAction Stop | Out-Null
    $wfpIds = @(5152,5153,5154,5155,5156,5157,5158,5159,1100,1101,1102,1104,4719)
    $idFilter = ($wfpIds | ForEach-Object { 'EventID=' + $_ }) -join ' or '
    $startUtc = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$request.started_unix_ms).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $endUtc = $eventEndTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $query = "*[System[($idFilter) and EventRecordID > $([uint64]$request.security_record_id) and TimeCreated[@SystemTime >= '$startUtc' and @SystemTime <= '$endUtc']]]"
    $queryErrors = @()
    $events = @(Get-WinEvent -LogName Security -FilterXPath $query -Oldest -MaxEvents ($maxEvents + 1) -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
    foreach ($queryError in $queryErrors) {
        if ($queryError.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw $queryError }
    }
    if ($events.Count -gt $maxEvents) { $events = @($events | Select-Object -First $maxEvents); $wfpHealth.truncated=$true }
    # A reset/overwrite can invalidate the baseline even when the query returned no rows.
    $latest = Last-Record 'Security'
    $oldest = @(Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue)
    if ($latest -lt [uint64]$request.security_record_id -or ($oldest.Count -gt 0 -and [uint64]$request.security_record_id -gt 0 -and [uint64]$oldest[0].RecordId -gt ([uint64]$request.security_record_id + 1))) {
        $wfpHealth.loss_detected=$true
        $wfpHealth.warnings += 'Security log reset or rollover invalidated the baseline.'
    }
    foreach ($event in $events) {
        $data = Event-Data $event
        $id = [int]$event.Id
        if ($id -lt 5152) {
            $wfpHealth.loss_detected=$true
            $message = "Security audit interruption or policy change event $id"
            if ($wfpHealth.provider_errors -notcontains $message) { $wfpHealth.provider_errors += $message }
        }
        $processId = Parse-Pid $data.ProcessID
        $correlation = [ordered]@{ target=$false; confidence='none'; reason='no process identity matched the target tree'; process_guid=$null }
        $known = @($incarnations[[string]$processId] | Where-Object { $null -ne $_ -and $_.event.TimeCreated -le $event.TimeCreated } | Sort-Object { $_.event.TimeCreated } -Descending)
        if ($known.Count -gt 0) {
            $owner = $known[0]
            $correlation.process_guid = [string]$owner.data.ProcessGuid
            $terminated = $terminations.ContainsKey([string]$owner.data.ProcessGuid) -and $terminations[[string]$owner.data.ProcessGuid] -lt $event.TimeCreated
            if ($guids.Contains([string]$owner.data.ProcessGuid) -and -not $terminated) {
                $correlation.target=$true; $correlation.confidence='medium'; $correlation.reason='PID and event time match a Sysmon target-tree process lifetime; WFP supplies no ProcessGuid'
            } else { $correlation.reason='PID belongs to another process incarnation or an exited process' }
        } elseif ($processId -ne 0 -and $processId -eq [uint32]$request.root_pid -and -not $incarnations.ContainsKey([string]$processId)) {
            $correlation.target=$true; $correlation.confidence='low'; $correlation.reason='root PID within execution window only; process creation unavailable and PID reuse cannot be excluded'
        }
        $state = switch ($id) { 5152 {'packet_blocked'} 5153 {'packet_blocked_restrictive_filter'} 5154 {'listen_permitted'} 5155 {'listen_blocked'} 5156 {'connection_permitted'} 5157 {'connection_blocked'} 5158 {'bind_permitted'} 5159 {'bind_blocked'} default {'audit_health'} }
        $protocol = switch (Parse-Pid $data.Protocol) { 1 {'icmp'} 6 {'tcp'} 17 {'udp'} 58 {'icmpv6'} default {'ip/' + [string]$data.Protocol} }
        $inbound = [string]$data.Direction -eq '%%14592' -or [string]$data.Direction -eq 'Inbound'
        $localAddress = [string]$data.SourceAddress; $localPort = Parse-Port $data.SourcePort
        $remoteAddress = [string]$data.DestAddress; $remotePort = Parse-Port $data.DestPort
        if ($inbound -and $id -in 5152,5153,5156,5157) {
            $localAddress=[string]$data.DestAddress; $localPort=Parse-Port $data.DestPort
            $remoteAddress=[string]$data.SourceAddress; $remotePort=Parse-Port $data.SourcePort
        }
        $normalized = [ordered]@{
            schema_version=1; source='windows_filtering_platform'; event_id=$id; action=$state
            record_id=[uint64]$event.RecordId; time_utc=$event.TimeCreated.ToUniversalTime().ToString('o')
            observed_at_ms=Elapsed-Ms $event ([int64]$request.started_unix_ms)
            pid=$(if ($processId -gt 0) { $processId } else { $null }); image=Bounded ([string]$data.Application)
            protocol=$protocol; local_address=Bounded $localAddress 256; local_port=$localPort
            remote_address=Bounded $remoteAddress 256; remote_port=$remotePort
            correlation=$correlation; data=(Bounded-EventData $data)
        }
        $wfpHealth.captured_events++
        $eventBytes = [Text.Encoding]::UTF8.GetByteCount(($normalized | ConvertTo-Json -Compress -Depth 8)) + 1
        if ($rawEvents.Count -lt $maxRawEvents -and ($wfpHealth.captured_bytes + $eventBytes) -le $wfpHealth.byte_limit) {
            $before = $rawEvents.Count
            Add-RawEvent $normalized
            if ($rawEvents.Count -gt $before) { $wfpHealth.retained_events++; $wfpHealth.captured_bytes += $eventBytes }
            else { $wfpHealth.truncated=$true }
        } else { $wfpHealth.truncated=$true; $rawEventsTruncated=$true }
        if ($correlation.target -and $id -ge 5152) {
            $context = [ordered]@{ time_utc=$normalized.time_utc; event_id=$id; action=$state; image=$normalized.image; correlation=$correlation }
            $network.Add([ordered]@{ event=$context; pid=$processId; protocol=$protocol; local_address=$localAddress; local_port=$localPort; remote_address=$remoteAddress; remote_port=$remotePort; state=$state; observed_at_ms=$normalized.observed_at_ms })
        }
    }
    $wfpCollected = [bool]$request.wfp_available
    $wfpHealth.stopped=$true
} catch { $wfpHealth.provider_errors += "WFP audit query failed: $($_.Exception.Message) at $($_.ScriptStackTrace)" }
if (-not $wfpHealth.started) { $wfpHealth.warnings += 'WFP auditing unavailable or not confirmed before target launch.' }
if ($wfpHealth.truncated) { $truncated=$true; $warnings.Add('WFP event or byte limit reached; network attempt coverage is incomplete') }
$warnings.AddRange([string[]]$wfpHealth.provider_errors)
$warnings.AddRange([string[]]$wfpHealth.warnings)

foreach ($row in $sysmonRows) {
    $id = [int]$row.event.Id
    $data = $row.data
    $guid = [string]$data.ProcessGuid
    if ($id -eq 8 -or $id -eq 10) { $guid = [string]$data.SourceProcessGUID }
    if (-not $guids.Contains($guid)) { continue }
    if ($rawEvents.Count -lt $maxRawEvents) {
        Add-RawEvent ([ordered]@{
            schema_version = 1
            source = 'sysmon'
            event_id = $id
            record_id = [uint64]$row.event.RecordId
            time_utc = $row.event.TimeCreated.ToUniversalTime().ToString('o')
            observed_at_ms = Elapsed-Ms $row.event ([int64]$request.started_unix_ms)
            started_unix_ms = [uint64]$request.started_unix_ms
            data = (Bounded-EventData $data)
        })
    } else {
        $rawEventsTruncated = $true
        $truncated = $true
    }
    $processId = Parse-Pid $data.ProcessId
    $elapsed = Elapsed-Ms $row.event ([int64]$request.started_unix_ms)
    switch ($id) {
        1 {
            $processes.Add([ordered]@{
                pid = $processId
                parent_pid = Parse-Pid $data.ParentProcessId
                image = Bounded (([string]$data.Image) + ' | ' + ([string]$data.CommandLine))
                observed_at_ms = $elapsed
            })
        }
        5 {
            $processes.Add([ordered]@{
                pid = $processId
                parent_pid = 0
                image = Bounded ('terminated | ' + ([string]$data.Image))
                observed_at_ms = $elapsed
            })
        }
        3 {
            $network.Add([ordered]@{
                pid = $processId
                protocol = Bounded ([string]$data.Protocol) 64
                local_address = Bounded ([string]$data.SourceIp) 256
                local_port = Parse-Port $data.SourcePort
                remote_address = Bounded (([string]$data.DestinationIp) + $(if ($data.DestinationHostname) { ' (' + $data.DestinationHostname + ')' } else { '' })) 512
                remote_port = Parse-Port $data.DestinationPort
                state = 'connected'
                observed_at_ms = $elapsed
            })
        }
        22 {
            $network.Add([ordered]@{
                pid = $processId
                protocol = 'dns'
                local_address = ''
                local_port = 0
                remote_address = Bounded ([string]$data.QueryName) 512
                remote_port = 53
                state = Bounded ('attempt status=' + ([string]$data.QueryStatus) + ' results=' + ([string]$data.QueryResults)) 1024
                observed_at_ms = $elapsed
            })
        }
        { $_ -in 11,15,26,27,28,29 } {
            $operation = switch ($id) {
                11 {'create_or_overwrite'}
                15 {'alternate_stream_create'}
                26 {'delete'}
                27 {'executable_blocked'}
                28 {'shredding_blocked'}
                29 {'executable_create'}
            }
            $fileObservation = [ordered]@{
                relative_path = Bounded ([string]$data.TargetFilename) 4096
                size_bytes = 0
                kind = $operation
                observed_at_ms = $elapsed
            }
            $eventSha256 = Parse-Sha256 ([string]$data.Hashes)
            if ($null -ne $eventSha256) {
                $fileObservation['sha256'] = $eventSha256
                $fileObservation['hash_source'] = 'sysmon_event'
            }
            $files.Add($fileObservation)
            if ($id -eq 27 -or $id -eq 28) {
                $warnings.Add("Sysmon enforcement event $id affected the target process tree at $([string]$data.TargetFilename)")
            }
        }
        { $_ -in 12,13,14 } {
            $operation = switch ($id) {
                12 {
                    switch ([string]$data.EventType) {
                        'CreateKey' { 'create_key' }
                        'DeleteKey' { 'delete_key' }
                        default { 'create_or_delete' }
                    }
                }
                13 { 'set_value' }
                14 { 'rename' }
            }
            $details = Bounded ([string]$data.Details) 2048
            if ($details) { $operation = $operation + ' data=' + $details }
            $registry.Add([ordered]@{
                key = Bounded ([string]$data.TargetObject) 4096
                operation = Bounded $operation 4096
                observed_at_ms = $elapsed
            })
        }
        9 { $files.Add([ordered]@{ relative_path=Bounded ([string]$data.Device) 4096; size_bytes=0; kind='raw_disk_read'; observed_at_ms=$elapsed }) }
        17 { $files.Add([ordered]@{ relative_path=Bounded ([string]$data.PipeName) 4096; size_bytes=0; kind='named_pipe_create'; observed_at_ms=$elapsed }) }
        18 { $files.Add([ordered]@{ relative_path=Bounded ([string]$data.PipeName) 4096; size_bytes=0; kind='named_pipe_connect'; observed_at_ms=$elapsed }) }
        25 { $processes.Add([ordered]@{ pid=$processId; parent_pid=0; image=Bounded (([string]$data.Image) + ' | tampering=' + ([string]$data.Type)); observed_at_ms=$elapsed }) }
        255 { $warnings.Add('Sysmon reported an internal telemetry error for the target process tree') }
    }
}

$defenderCollected = $false
try {
    Get-WinEvent -ListLog $defenderLog -ErrorAction Stop | Out-Null
    $defenderIds = @(1006,1007,1008,1009,1015,1116,1117,1118,1119,1121,1122)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName=$defenderLog; Id=$defenderIds; StartTime=$eventStartTime } `
        -Oldest -MaxEvents ($maxEvents + 1) -ErrorAction SilentlyContinue |
        Where-Object { [uint64]$_.RecordId -gt [uint64]$request.defender_record_id })
    if ($events.Count -gt $maxEvents) {
        $events = @($events | Select-Object -First $maxEvents)
        $truncated = $true
        $warnings.Add("Windows Defender event limit reached at $maxEvents records")
    }
    foreach ($event in $events) {
        $data = Event-Data $event
        if ($rawEvents.Count -lt $maxRawEvents) {
            Add-RawEvent ([ordered]@{
                source = 'windows_defender'
                event_id = [int]$event.Id
                record_id = [uint64]$event.RecordId
                time_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
                data = (Bounded-EventData $data)
            })
        } else {
            $rawEventsTruncated = $true
            $truncated = $true
        }
        $affectedPath = [string]$data.Path
        if ([string]::IsNullOrWhiteSpace($affectedPath)) { $affectedPath = [string]$data.'Process Name' }
        if ([string]::IsNullOrWhiteSpace($affectedPath)) { $affectedPath = '<not supplied>' }
        $files.Add([ordered]@{
            relative_path = Bounded $affectedPath 4096
            size_bytes = 0
            kind = "windows_defender_event_$([int]$event.Id)"
            observed_at_ms = Elapsed-Ms $event ([int64]$request.started_unix_ms)
        })
        $warnings.Add("Windows Defender event $([int]$event.Id) occurred during target execution: $(Bounded $affectedPath 1024)")
    }
    $defenderCollected = $true
} catch { $warnings.Add("Windows Defender event query failed: $($_.Exception.Message)") }
if ($rawEventsTruncated) {
    $warnings.Add("raw telemetry event limit reached at $maxRawEvents target-related records")
}

# Hash only regular files whose create/write events were attributed to the target process tree.
# The target has already exited and its process tree has been terminated. Exclusive write/delete
# sharing is denied while each file is read, and strict count/byte/deadline limits keep collection
# bounded. Sysmon Event 29 hashes are seeded first so deleted or renamed executable downloads still
# retain their creation-time digest.
$hashCache = @{}
foreach ($observation in $files) {
    $path = [string]$observation.relative_path
    $digest = [string]$observation.sha256
    if (-not [string]::IsNullOrWhiteSpace($path) -and -not [string]::IsNullOrWhiteSpace($digest)) {
        $hashCache[$path] = [pscustomobject]@{
            sha256 = $digest
            size_bytes = [uint64]$observation.size_bytes
            hash_source = [string]$observation.hash_source
        }
    }
}
$hashableKinds = @('create_or_overwrite', 'alternate_stream_create', 'executable_create')
$hashCount = 0
[uint64]$hashBytes = 0
$unavailableHashCount = 0
$skippedHashCount = 0
$hashDeadline = [DateTime]::UtcNow.AddSeconds(20)
foreach ($observation in $files) {
    if ($hashableKinds -notcontains [string]$observation.kind) { continue }
    $path = [string]$observation.relative_path
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    if ($hashCache.ContainsKey($path)) {
        $cached = $hashCache[$path]
        if ([uint64]$cached.size_bytes -eq 0 -and
            $hashCount -lt $maxHashedFiles -and
            [DateTime]::UtcNow -lt $hashDeadline) {
            $remainingBytes = [uint64]$maxHashTotalBytes - $hashBytes
            $currentFile = Read-BoundedFileSha256 $path $remainingBytes
            $hashCount++
            if ([string]$currentFile.status -eq 'hashed') {
                $hashBytes += [uint64]$currentFile.size_bytes
                if ([string]$currentFile.sha256 -eq [string]$cached.sha256) {
                    $cached.size_bytes = [uint64]$currentFile.size_bytes
                } else {
                    $warnings.Add("a target-created file changed after Sysmon recorded its creation hash: $(Bounded $path 1024)")
                }
            }
        }
        $observation['sha256'] = [string]$cached.sha256
        $observation['hash_source'] = [string]$cached.hash_source
        if ([uint64]$cached.size_bytes -gt 0) {
            $observation['size_bytes'] = [uint64]$cached.size_bytes
        }
        continue
    }
    if ($hashCount -ge $maxHashedFiles -or [DateTime]::UtcNow -ge $hashDeadline) {
        $skippedHashCount++
        continue
    }
    $remainingBytes = [uint64]$maxHashTotalBytes - $hashBytes
    $fileHash = Read-BoundedFileSha256 $path $remainingBytes
    $hashCount++
    if ($null -eq $fileHash -or [string]$fileHash.status -eq 'unavailable') {
        $unavailableHashCount++
        continue
    }
    if ([string]$fileHash.status -eq 'non_regular') {
        continue
    }
    if ([string]$fileHash.status -eq 'skipped') {
        $skippedHashCount++
        continue
    }
    $hashBytes += [uint64]$fileHash.size_bytes
    $cached = [pscustomobject]@{
        sha256 = [string]$fileHash.sha256
        size_bytes = [uint64]$fileHash.size_bytes
        hash_source = 'guest_post_run_file'
    }
    $hashCache[$path] = $cached
    $observation['sha256'] = [string]$cached.sha256
    $observation['hash_source'] = [string]$cached.hash_source
    $observation['size_bytes'] = [uint64]$cached.size_bytes
}
if ($unavailableHashCount -gt 0) {
    $warnings.Add("$unavailableHashCount target-created file observation(s) could not be hashed because the path was absent, non-regular, or unreadable after execution")
}
if ($skippedHashCount -gt 0) {
    $warnings.Add("$skippedHashCount target-created file observation(s) exceeded the bounded file-hash count, byte, size, or time budget")
}

Write-Result ([ordered]@{
    processes = @($processes)
    network_connections = @($network)
    file_observations = @($files)
    registry_observations = @($registry)
    raw_events = @($rawEvents)
    sysmon_collected = [bool]$request.sysmon_available
    capture_health = @($wfpHealth)
    wfp_collected = $wfpCollected
    defender_collected = $defenderCollected
    truncated = $truncated
    warnings = @($warnings)
})
