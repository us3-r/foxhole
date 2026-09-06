param(
    [string]$TargetDirectory = 'target\guest-agent-static'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$resolvedTarget = if ([System.IO.Path]::IsPathRooted($TargetDirectory)) {
    [System.IO.Path]::GetFullPath($TargetDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $TargetDirectory))
}

$previousTarget = $env:CARGO_TARGET_DIR
$previousFlags = $env:RUSTFLAGS
try {
    $env:CARGO_TARGET_DIR = $resolvedTarget
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    & cargo.exe build --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') --release --locked --bin foxhole-agent
    if ($LASTEXITCODE -ne 0) {
        throw "cargo failed to build the statically linked guest agent (exit $LASTEXITCODE)"
    }
} finally {
    $env:CARGO_TARGET_DIR = $previousTarget
    $env:RUSTFLAGS = $previousFlags
}

$agent = Join-Path $resolvedTarget 'release\foxhole-agent.exe'
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
    throw "the guest-agent build did not produce $agent"
}

$asciiImage = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($agent))
foreach ($forbiddenImport in @('VCRUNTIME140.dll', 'api-ms-win-crt-runtime-l1-1-0.dll')) {
    if ($asciiImage.IndexOf($forbiddenImport, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "guest agent still imports the dynamic CRT dependency $forbiddenImport"
    }
}

$file = Get-Item -LiteralPath $agent
$hash = Get-FileHash -LiteralPath $agent -Algorithm SHA256
[pscustomobject]@{
    Path = $file.FullName
    Length = $file.Length
    SHA256 = $hash.Hash.ToLowerInvariant()
}
