[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ImagePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string] $ImageVersion,

    [string] $ManifestPath,

    [ValidateRange(1, 4294967295)]
    [uint32] $GuestProtocolVersion = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    throw 'Base-image finalization is supported only on Windows.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

if ($ImagePath -notmatch '^[A-Za-z]:[\\/]') {
    throw 'ImagePath must be an absolute path.'
}
$resolvedImagePath = [IO.Path]::GetFullPath($ImagePath)
if (-not [IO.Path]::GetExtension($resolvedImagePath).Equals('.vhdx', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ImagePath must name a VHDX file.'
}

$image = Get-Item -LiteralPath $resolvedImagePath -Force
if ($image.PSIsContainer -or ($image.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The base image must be a plain, non-reparse regular file.'
}
$resolvedImagePath = $image.FullName
$imageDirectory = [IO.Path]::GetDirectoryName($resolvedImagePath)

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = [IO.Path]::Combine(
        $imageDirectory,
        [IO.Path]::GetFileNameWithoutExtension($resolvedImagePath) + '.manifest.json'
    )
}
if ($ManifestPath -notmatch '^[A-Za-z]:[\\/]') {
    throw 'ManifestPath must be an absolute path.'
}
$resolvedManifestPath = [IO.Path]::GetFullPath($ManifestPath)
$manifestDirectory = [IO.Path]::GetDirectoryName($resolvedManifestPath)
if (-not $manifestDirectory.Equals($imageDirectory, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The manifest must be stored beside the base VHDX in the same protected directory.'
}
if (Test-Path -LiteralPath $resolvedManifestPath) {
    throw "Refusing to overwrite the existing manifest: $resolvedManifestPath"
}

$directory = Get-Item -LiteralPath $imageDirectory -Force
if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The base-image directory must be a plain, non-reparse directory.'
}
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($resolvedImagePath))
if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
    throw 'The base image must be stored on a fixed local volume.'
}

$modulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\Hyper-V\Hyper-V.psd1'
Import-Module Hyper-V -ErrorAction Stop
if (-not (Test-VHD -Path $resolvedImagePath -ErrorAction Stop)) {
    throw 'Hyper-V rejected the VHDX structure.'
}
$vhd = Get-VHD -Path $resolvedImagePath -ErrorAction Stop
if (-not ([string]$vhd.VhdFormat).Equals('VHDX', [StringComparison]::OrdinalIgnoreCase) -or
    -not @('Fixed', 'Dynamic').Contains([string]$vhd.VhdType) -or
    [bool]$vhd.Attached -or
    -not [string]::IsNullOrWhiteSpace([string]$vhd.ParentPath) -or
    [uint64]$vhd.Size -eq 0 -or
    [uint64]$vhd.Size -gt 128GB) {
    throw 'The base image must be an unattached standalone fixed/dynamic VHDX of at most 128 GiB.'
}

if (-not $PSCmdlet.ShouldProcess(
        $resolvedImagePath,
        "create $resolvedManifestPath and mark the base image read-only"
    )) {
    return
}

$imageStream = $null
$sha256 = $null
try {
    # Deny write/delete sharing while hashing and publishing the manifest so the recorded digest
    # is bound to the exact finalized bytes.
    $imageStream = [IO.FileStream]::new(
        $resolvedImagePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    if ($imageStream.Length -eq 0 -or $imageStream.Length -ne $image.Length) {
        throw 'The base-image file changed before it could be finalized.'
    }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($imageStream)
        $sha256 = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }

    $manifest = [ordered]@{
        schema_version = 1
        image_version = $ImageVersion
        guest_protocol_version = $GuestProtocolVersion
        vm_generation = 2
        secure_boot_template = 'MicrosoftWindows'
        sha256 = $sha256
        built_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
    $json = $manifest | ConvertTo-Json -Compress -Depth 4
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $manifestStream = [IO.FileStream]::new(
        $resolvedManifestPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $manifestStream.Write($bytes, 0, $bytes.Length)
        $manifestStream.Flush($true)
    }
    finally {
        $manifestStream.Dispose()
    }

    [IO.File]::SetAttributes(
        $resolvedImagePath,
        [IO.File]::GetAttributes($resolvedImagePath) -bor [IO.FileAttributes]::ReadOnly
    )
    [IO.File]::SetAttributes(
        $resolvedManifestPath,
        [IO.File]::GetAttributes($resolvedManifestPath) -bor [IO.FileAttributes]::ReadOnly
    )
}
catch {
    if (Test-Path -LiteralPath $resolvedManifestPath) {
        try {
            [IO.File]::SetAttributes($resolvedManifestPath, [IO.FileAttributes]::Normal)
            Remove-Item -LiteralPath $resolvedManifestPath -Force
        }
        catch {
            Write-Warning "Could not remove incomplete manifest $resolvedManifestPath`: $($_.Exception.Message)"
        }
    }
    throw
}
finally {
    if ($null -ne $imageStream) {
        $imageStream.Dispose()
    }
}

[PSCustomObject]@{
    ImagePath = $resolvedImagePath
    ManifestPath = $resolvedManifestPath
    ImageVersion = $ImageVersion
    GuestProtocolVersion = $GuestProtocolVersion
    Sha256 = $sha256
}
