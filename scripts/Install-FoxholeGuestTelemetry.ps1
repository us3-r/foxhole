[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string] $ImagePath,

    [Parameter(Mandatory = $true)]
    [string] $SysmonPath,

    [string] $ConfigPath = (Join-Path $PSScriptRoot '..\guest-agent\assets\sysmon-config.xml')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

$image = [IO.Path]::GetFullPath($ImagePath)
$sysmon = [IO.Path]::GetFullPath($SysmonPath)
$config = [IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $image -PathType Leaf) -or
    -not [IO.Path]::GetExtension($image).Equals('.vhdx', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ImagePath must identify an existing VHDX file.'
}
if (-not (Test-Path -LiteralPath $sysmon -PathType Leaf)) {
    throw 'SysmonPath must identify an existing Sysmon64.exe.'
}
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw 'ConfigPath must identify an existing Sysmon configuration file.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $sysmon
if ($signature.Status -ne 'Valid' -or
    [string]$signature.SignerCertificate.Subject -notmatch 'Microsoft') {
    throw 'Sysmon64.exe must have a valid Microsoft Authenticode signature.'
}
if (-not $PSCmdlet.ShouldProcess($image, 'stage signed Sysmon telemetry components')) {
    return
}

$mounted = $false
$originalAttributes = [IO.File]::GetAttributes($image)
try {
    [IO.File]::SetAttributes($image, $originalAttributes -band (-bnot [IO.FileAttributes]::ReadOnly))
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
    $destination = Join-Path $root 'Foxhole\Telemetry'
    if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
        New-Item -ItemType Directory -Path $destination | Out-Null
    }
    Copy-Item -LiteralPath $sysmon -Destination (Join-Path $destination 'Sysmon64.exe') -Force
    Copy-Item -LiteralPath $config -Destination (Join-Path $destination 'sysmon-config.xml') -Force
    & icacls.exe $destination /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q
    if ($LASTEXITCODE -ne 0) { throw "icacls failed with exit code $LASTEXITCODE" }

    $installedSysmon = Join-Path $destination 'Sysmon64.exe'
    if ((Get-FileHash -LiteralPath $installedSysmon -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $sysmon -Algorithm SHA256).Hash) {
        throw 'Staged Sysmon copy verification failed.'
    }
} finally {
    if ($mounted) { Dismount-VHD -Path $image -ErrorAction Continue }
    [IO.File]::SetAttributes($image, $originalAttributes)
}

[pscustomobject]@{
    ImagePath = $image
    SysmonSha256 = (Get-FileHash -LiteralPath $sysmon -Algorithm SHA256).Hash.ToLowerInvariant()
    Destination = 'C:\Foxhole\Telemetry'
}
