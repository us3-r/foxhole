[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ImagePath,
    [Parameter(Mandatory = $true)]
    [string]$AgentPath,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$GuestImageVersion,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$transcriptStarted = $false
if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    Start-Transcript -LiteralPath ([System.IO.Path]::GetFullPath($LogPath)) -Force | Out-Null
    $transcriptStarted = $true
}
trap {
    Write-Output ($_ | Out-String)
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
    exit 1
}
$image = [System.IO.Path]::GetFullPath($ImagePath)
$agent = [System.IO.Path]::GetFullPath($AgentPath)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
if (-not (Test-Path -LiteralPath $image -PathType Leaf) -or
    -not [System.IO.Path]::GetExtension($image).Equals('.vhdx', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ImagePath must identify an existing VHDX file.'
}
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
    throw 'AgentPath must identify an existing guest-agent executable.'
}

$asciiImage = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($agent))
foreach ($forbiddenImport in @('VCRUNTIME140.dll', 'api-ms-win-crt-runtime-l1-1-0.dll')) {
    if ($asciiImage.IndexOf($forbiddenImport, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "refusing to install a guest agent with dynamic CRT dependency $forbiddenImport"
    }
}
if (-not $PSCmdlet.ShouldProcess($image, "replace the sealed guest agent and restore automatic service startup")) {
    return
}

$mounted = $false
$hiveName = 'FoxholeBaseAgentUpdate'
$originalAttributes = [System.IO.File]::GetAttributes($image)
try {
    [System.IO.File]::SetAttributes($image, $originalAttributes -band (-bnot [System.IO.FileAttributes]::ReadOnly))
    $vhd = Mount-VHD -Path $image -PassThru -ErrorAction Stop
    $mounted = $true
    $disk = $vhd | Get-Disk -ErrorAction Stop
    $partition = Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
        Where-Object { $_.Type -eq 'Basic' -and $_.Size -gt 1GB } |
        Sort-Object Size -Descending |
        Select-Object -First 1
    if ($null -eq $partition) { throw 'Could not locate the Windows partition.' }
    $volume = $partition | Get-Volume -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$volume.DriveLetter)) {
        throw 'The Windows partition did not receive a temporary drive letter.'
    }
    $root = ([string]$volume.DriveLetter) + ':\'
    foreach ($relative in @('Foxhole\foxhole-agent.exe', 'Program Files\Foxhole\foxhole-agent.exe')) {
        $destination = Join-Path $root $relative
        if (-not (Test-Path -LiteralPath (Split-Path -Parent $destination) -PathType Container)) {
            throw "guest-agent destination directory is missing: $destination"
        }
        Copy-Item -LiteralPath $agent -Destination $destination -Force
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash) {
            throw "guest-agent copy verification failed: $destination"
        }
    }

    $hivePath = Join-Path $root 'Windows\System32\config\SYSTEM'
    & reg.exe load "HKLM\$hiveName" $hivePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "reg.exe load failed with exit code $LASTEXITCODE" }
    try {
        $serviceKey = "Registry::HKEY_LOCAL_MACHINE\$hiveName\ControlSet001\Services\FoxholeAgent"
        if (-not (Test-Path -LiteralPath $serviceKey)) { throw 'FoxholeAgent service registration is missing.' }
        Set-ItemProperty -LiteralPath $serviceKey -Name ImagePath -Value 'C:\Foxhole\foxhole-agent.exe --service' -Type ExpandString
        Set-ItemProperty -LiteralPath $serviceKey -Name Start -Value 2 -Type DWord
        Set-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -Value 0 -Type DWord
        if (-not [string]::IsNullOrWhiteSpace($GuestImageVersion)) {
            $environmentKey = "Registry::HKEY_LOCAL_MACHINE\$hiveName\ControlSet001\Control\Session Manager\Environment"
            if (-not (Test-Path -LiteralPath $environmentKey)) {
                throw 'Guest system environment registration is missing.'
            }
            Set-ItemProperty `
                -LiteralPath $environmentKey `
                -Name FOXHOLE_GUEST_IMAGE_VERSION `
                -Value $GuestImageVersion `
                -Type String
        }
    } finally {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKLM\$hiveName" | Out-Null
    }
} finally {
    if ($mounted) { Dismount-VHD -Path $image -ErrorAction Continue }
    [System.IO.File]::SetAttributes($image, $originalAttributes)
}

$installedHash = (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash.ToLowerInvariant()
[pscustomobject]@{
    ImagePath = $image
    AgentPath = $agent
    AgentSha256 = $installedHash
    ServiceImagePath = 'C:\Foxhole\foxhole-agent.exe --service'
    ServiceStart = 'automatic'
    GuestImageVersion = $GuestImageVersion
}
if ($transcriptStarted) { Stop-Transcript | Out-Null }
