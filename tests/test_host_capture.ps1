# Execute the actual host stop script against mocked NetEvent commands only.
$ErrorActionPreference = 'Stop'
$network = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/sandbox/hyperv/network.rs') -Raw
$limitFunction = [regex]::Match($network, '(?s)function Test-CaptureLimit\(\$Value\) \{.*?\r?\n\}')
if (!$limitFunction.Success) { throw 'Capture limit normalizer not found.' }
. ([scriptblock]::Create($limitFunction.Value))
foreach ($accepted in @(128, '128', '128 MB', ' 128 MB ')) {
    if (!(Test-CaptureLimit $accepted)) { throw "Valid provider limit rejected: $accepted" }
}
foreach ($rejected in @($null, 0, 256, '128 KB', '128 MB extra', '128.5 MB', '128000000')) {
    if (Test-CaptureLimit $rejected) { throw "Invalid provider limit accepted: $rejected" }
}
$source = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/sandbox/hyperv/capture.rs') -Raw
$match = [regex]::Match($source, '(?s)const STOP: &str = r#"(.*?)"#;')
if (-not $match.Success) { throw 'Host capture script not found' }
$script = $match.Groups[1].Value.Replace('$request = [Console]::In.ReadToEnd() | ConvertFrom-Json', '$request = [pscustomobject]@{session="FoxholeNet-fixture";etl="C:\fixture\network-capture.etl"}')
function Get-NetEventSession {
    [CmdletBinding()] param([string]$Name)
    [pscustomobject]@{LocalFilePath=$global:FoxholeCapturePath;SessionStatus=$global:FoxholeCaptureState;EventsLost=7}
}
function Stop-NetEventSession {
    [CmdletBinding()] param([string]$Name)
    if ($Name -ne 'FoxholeNet-fixture') { throw 'wrong session' }
    $global:FoxholeCaptureStops++
    $global:FoxholeCaptureState='Stopped'
}
try {
    $global:FoxholeCapturePath='C:\fixture\network-capture.etl'
    $global:FoxholeCaptureState='Running'
    $global:FoxholeCaptureStops=0
    $result = & ([scriptblock]::Create($script)) | ConvertFrom-Json
    if (-not $result.ok -or -not $result.data.started -or -not $result.data.stopped -or $result.data.dropped_events -ne 7 -or $global:FoxholeCaptureStops -ne 1) { throw 'stop states or loss counters missing' }
    $global:FoxholeCapturePath='C:\unrelated.etl'
    $result = & ([scriptblock]::Create($script)) | ConvertFrom-Json
    if ($result.ok -or $global:FoxholeCaptureStops -ne 1) { throw 'ownership mismatch must not stop unrelated capture' }
    Write-Output 'PASS: host capture stop script, provider counters and session ownership.'
} finally {
    Remove-Variable -Name FoxholeCapturePath,FoxholeCaptureState,FoxholeCaptureStops -Scope Global -ErrorAction SilentlyContinue
}
