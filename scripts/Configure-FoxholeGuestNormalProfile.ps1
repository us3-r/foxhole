[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ImagePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string] $Username,

    [Parameter(Mandatory = $true)]
    [Security.SecureString] $Password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

$resolvedImage = [IO.Path]::GetFullPath($ImagePath)
if (-not (Test-Path -LiteralPath $resolvedImage -PathType Leaf) -or
    -not [IO.Path]::GetExtension($resolvedImage).Equals('.vhdx', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ImagePath must identify an existing VHDX file.'
}
if (-not $PSCmdlet.ShouldProcess($resolvedImage, "configure the protected normal-user launch profile for $Username")) {
    return
}

$mounted = $false
$hiveLoaded = $false
$hiveName = 'FoxholeNormalProfile'
$originalAttributes = [IO.File]::GetAttributes($resolvedImage)
$plainPassword = $null
try {
    [IO.File]::SetAttributes($resolvedImage, $originalAttributes -band (-bnot [IO.FileAttributes]::ReadOnly))
    $vhd = Mount-VHD -Path $resolvedImage -PassThru -ErrorAction Stop
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
    $foxholeData = Join-Path $root 'ProgramData\Foxhole'
    if (-not (Test-Path -LiteralPath $foxholeData -PathType Container)) {
        New-Item -ItemType Directory -Path $foxholeData | Out-Null
    }
    $secretPath = Join-Path $foxholeData 'normal-user.secret'

    $credential = [Management.Automation.PSCredential]::new($Username, $Password)
    $plainPassword = $credential.GetNetworkCredential().Password
    if ([string]::IsNullOrEmpty($plainPassword) -or $plainPassword.Contains([char]0)) {
        throw 'Password must be non-empty and must not contain NUL.'
    }
    [IO.File]::WriteAllText($secretPath, $plainPassword, [Text.UTF8Encoding]::new($false))
    & icacls.exe $secretPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' /Q
    if ($LASTEXITCODE -ne 0) { throw "icacls failed with exit code $LASTEXITCODE" }

    $systemHive = Join-Path $root 'Windows\System32\config\SYSTEM'
    & reg.exe load "HKLM\$hiveName" $systemHive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "reg.exe load failed with exit code $LASTEXITCODE" }
    $hiveLoaded = $true
    $environmentKey = "Registry::HKEY_LOCAL_MACHINE\$hiveName\ControlSet001\Control\Session Manager\Environment"
    if (-not (Test-Path -LiteralPath $environmentKey)) {
        throw 'The offline SYSTEM hive has no machine environment key.'
    }
    Set-ItemProperty -LiteralPath $environmentKey -Name 'FOXHOLE_GUEST_NORMAL_USERNAME' -Value $Username -Type String
    Set-ItemProperty -LiteralPath $environmentKey -Name 'FOXHOLE_GUEST_NORMAL_PASSWORD_FILE' -Value 'C:\ProgramData\Foxhole\normal-user.secret' -Type String
} finally {
    $plainPassword = $null
    if ($hiveLoaded) {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKLM\$hiveName" | Out-Null
    }
    if ($mounted) {
        Dismount-VHD -Path $resolvedImage -ErrorAction Continue
    }
    [IO.File]::SetAttributes($resolvedImage, $originalAttributes)
}

[pscustomobject]@{
    ImagePath = $resolvedImage
    Username = $Username
    PasswordFile = 'C:\ProgramData\Foxhole\normal-user.secret'
}
