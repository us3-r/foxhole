[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ImagePath,
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,
    [Parameter(Mandatory = $true)]
    [string]$ManifestBackupPath,
    [Parameter(Mandatory = $true)]
    [string]$ImageVersion,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
$image = [System.IO.Path]::GetFullPath($ImagePath)
$manifest = [System.IO.Path]::GetFullPath($ManifestPath)
$backup = [System.IO.Path]::GetFullPath($ManifestBackupPath)
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

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
if (-not (Test-Path -LiteralPath $image -PathType Leaf)) { throw 'Base image is missing.' }
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Current manifest is missing.' }
if (Test-Path -LiteralPath $backup) { throw 'Manifest backup destination already exists.' }
if (-not $PSCmdlet.ShouldProcess($manifest, "back up the old manifest and finalize the updated base image")) {
    return
}

[System.IO.File]::SetAttributes($manifest, [System.IO.FileAttributes]::Normal)
Move-Item -LiteralPath $manifest -Destination $backup
try {
    & (Join-Path $PSScriptRoot 'Finalize-FoxholeBaseImage.ps1') `
        -ImagePath $image `
        -ManifestPath $manifest `
        -ImageVersion $ImageVersion `
        -GuestProtocolVersion 2 `
        -Confirm:$false
} catch {
    if (-not (Test-Path -LiteralPath $manifest) -and (Test-Path -LiteralPath $backup)) {
        Move-Item -LiteralPath $backup -Destination $manifest
        [System.IO.File]::SetAttributes($manifest, [System.IO.FileAttributes]::ReadOnly)
    }
    throw
}

if ($transcriptStarted) { Stop-Transcript | Out-Null }
