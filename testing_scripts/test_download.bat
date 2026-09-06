@echo off
setlocal

set "FOXHOLE_TEST_SCRIPT=%~f0"
set "FOXHOLE_TEST_SERVER=%~1"
set "FOXHOLE_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%FOXHOLE_POWERSHELL%" (
    set "FOXHOLE_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
)
if not exist "%FOXHOLE_POWERSHELL%" (
    for %%P in (powershell.exe pwsh.exe) do (
        if not exist "%FOXHOLE_POWERSHELL%" for /f "delims=" %%F in ('where.exe %%P 2^>nul') do set "FOXHOLE_POWERSHELL=%%F"
    )
)
if not exist "%FOXHOLE_POWERSHELL%" (
    echo Windows PowerShell or PowerShell 7 is required but could not be found. 1>&2
    exit /b 1
)

"%FOXHOLE_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$lines = Get-Content -LiteralPath $env:FOXHOLE_TEST_SCRIPT; $marker = [Array]::IndexOf($lines, '#__POWERSHELL__'); if ($marker -lt 0) { exit 1 }; $script = [scriptblock]::Create(($lines[($marker + 1)..($lines.Length - 1)] -join [Environment]::NewLine)); & $script"
set "FOXHOLE_TEST_EXIT=%ERRORLEVEL%"

endlocal & exit /b %FOXHOLE_TEST_EXIT%

#__POWERSHELL__
$ErrorActionPreference = 'Stop'

$downloadLimit = 256MB
$childTimeoutMilliseconds = 15000
$serverBase = $env:FOXHOLE_TEST_SERVER
if ([string]::IsNullOrWhiteSpace($serverBase)) {
    $serverBase = 'http://127.0.0.1:8080'
}
$serverBase = $serverBase.TrimEnd('/')

if ($serverBase.Length -gt 2048) {
    [Console]::Error.WriteLine('Server URL is too long.')
    exit 2
}

try {
    $baseUri = [Uri]$serverBase
    if (-not $baseUri.IsAbsoluteUri -or $baseUri.Scheme -notin @('http', 'https')) {
        throw 'Only HTTP and HTTPS server URLs are supported.'
    }
    $healthUri = [Uri]::new($serverBase + '/health')
    $downloadUri = [Uri]::new($serverBase + '/files/test_toDownloadExe.exe')
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}

function Open-GetResponse([Uri]$Uri) {
    $request = [Net.HttpWebRequest]::CreateHttp($Uri)
    $request.Method = 'GET'
    $request.UserAgent = 'FoxholeServerDownloadTest/1.0'
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 10000
    return $request.GetResponse()
}

try {
    $healthResponse = Open-GetResponse $healthUri
    try {
        $healthStatus = [int]$healthResponse.StatusCode
    } finally {
        $healthResponse.Dispose()
    }
    if ($healthStatus -ne 200) {
        [Console]::Error.WriteLine("Health endpoint returned HTTP $healthStatus")
        exit 3
    }
    Write-Host 'Server health check passed.'
} catch {
    [Console]::Error.WriteLine("Health check failed: $($_.Exception.Message)")
    exit 3
}

$temporaryRoots = [Collections.Generic.List[string]]::new()
try {
    $temporaryRoots.Add([IO.Path]::GetTempPath())
} catch {}

$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
    $temporaryRoots.Add([IO.Path]::Combine($localAppData, 'Temp'))
}
if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
    $temporaryRoots.Add([IO.Path]::Combine($env:SystemRoot, 'Temp'))
}
$temporaryRoots.Add($PWD.Path)

$testDirectory = $null
foreach ($temporaryRoot in $temporaryRoots) {
    if ([string]::IsNullOrWhiteSpace($temporaryRoot)) {
        continue
    }
    try {
        $candidate = [IO.Path]::Combine($temporaryRoot, 'FoxholeTests')
        [IO.Directory]::CreateDirectory($candidate) | Out-Null
        $testDirectory = $candidate
        break
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($testDirectory)) {
    [Console]::Error.WriteLine('Could not find or create a writable temporary download directory.')
    exit 4
}

$destination = [IO.Path]::Combine($testDirectory, 'test_toDownloadExe.exe')
$partialPath = $destination + '.part'

$downloadSucceeded = $false
$totalBytes = [long]0
try {
    $downloadResponse = Open-GetResponse $downloadUri
    try {
        $downloadStatus = [int]$downloadResponse.StatusCode
        if ($downloadStatus -ne 200) {
            throw "Download endpoint returned HTTP $downloadStatus"
        }

        $inputStream = $downloadResponse.GetResponseStream()
        $outputStream = [IO.FileStream]::new(
            $partialPath,
            [IO.FileMode]::Create,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            65536,
            [IO.FileOptions]::WriteThrough
        )
        try {
            $buffer = [byte[]]::new(65536)
            while (($bytesRead = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $totalBytes += $bytesRead
                if ($totalBytes -gt $downloadLimit) {
                    throw 'Download exceeded the 256 MiB test limit.'
                }
                $outputStream.Write($buffer, 0, $bytesRead)
            }
            $outputStream.Flush($true)
        } finally {
            if ($null -ne $outputStream) { $outputStream.Dispose() }
            if ($null -ne $inputStream) { $inputStream.Dispose() }
        }
    } finally {
        if ($null -ne $downloadResponse) { $downloadResponse.Dispose() }
    }

    Move-Item -LiteralPath $partialPath -Destination $destination -Force
    $downloadSucceeded = $true
    Write-Host "Downloaded $totalBytes bytes to $destination"
} catch {
    [Console]::Error.WriteLine("Download failed: $($_.Exception.Message)")
} finally {
    if (-not $downloadSucceeded) {
        Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
    }
}

if (-not $downloadSucceeded) {
    exit 5
}

try {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $destination
    $startInfo.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw 'The downloaded process could not be started.'
    }

    Write-Host "Started downloaded process with PID $($process.Id)."
    try {
        if (-not $process.WaitForExit($childTimeoutMilliseconds)) {
            [Console]::Error.WriteLine("Downloaded process exceeded the $childTimeoutMilliseconds ms test limit.")
            $process.Kill()
            $process.WaitForExit(5000) | Out-Null
            exit 6
        }
        if ($process.ExitCode -ne 0) {
            [Console]::Error.WriteLine("Downloaded process exited with code $($process.ExitCode).")
            exit 6
        }
    } finally {
        $process.Dispose()
    }
} catch {
    [Console]::Error.WriteLine("Could not run the downloaded process: $($_.Exception.Message)")
    exit 6
}

Write-Host 'Downloaded process completed successfully.'
exit 0
