[CmdletBinding()]
param(
    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PathsEqual {
    param(
        [string]$Left,
        [string]$Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    try {
        $leftFullPath = [IO.Path]::GetFullPath($Left)
        $rightFullPath = [IO.Path]::GetFullPath($Right)
        return [StringComparer]::OrdinalIgnoreCase.Equals($leftFullPath, $rightFullPath)
    }
    catch {
        return $false
    }
}

function Get-JsonPropertyValue {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

$architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$platformDirectory = switch ($architecture) {
    "X64" { "windows-amd64" }
    "Arm64" { "windows-arm64" }
    default { throw "VoCat requires 64-bit Windows (x64 or ARM64); detected $architecture." }
}

$bundleRoot = Join-Path $PSScriptRoot $platformDirectory
$vocatPath = Join-Path $bundleRoot "vocat.exe"
$xrayPath = Join-Path $bundleRoot "xray.exe"
$dataDirectory = Join-Path $PSScriptRoot "data"
$runtimeStatePath = Join-Path $dataDirectory "vocat.runtime.json"
$stopFilePath = Join-Path $dataDirectory ".vocat-stop"

if (-not (Test-IsAdministrator)) {
    Write-Host "Requesting Administrator privileges to stop VoCat..." -ForegroundColor Yellow
    $windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $relaunchArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $PSCommandPath + '"'),
        "-TimeoutSeconds", $TimeoutSeconds
    )
    $elevatedProcess = Start-Process `
        -FilePath $windowsPowerShell `
        -Verb RunAs `
        -WorkingDirectory $PSScriptRoot `
        -ArgumentList ($relaunchArguments -join " ") `
        -PassThru `
        -Wait
    exit $elevatedProcess.ExitCode
}

Set-Location -LiteralPath $PSScriptRoot

if (-not (Test-Path -LiteralPath $runtimeStatePath)) {
    if (Test-Path -LiteralPath $stopFilePath) {
        if (-not (Test-Path -LiteralPath $stopFilePath -PathType Leaf)) {
            throw "The stop-file path is not a regular file: $stopFilePath"
        }
        Remove-Item -LiteralPath $stopFilePath -Force
    }
    Write-Host "VoCat is not running under this launcher." -ForegroundColor Green
    exit 0
}
if (-not (Test-Path -LiteralPath $runtimeStatePath -PathType Leaf)) {
    throw "The runtime-state path is not a regular file: $runtimeStatePath"
}

try {
    $runtimeState = Get-Content -LiteralPath $runtimeStatePath -Raw | ConvertFrom-Json
}
catch {
    throw "The VoCat runtime state is unreadable; no process was stopped. $($_.Exception.Message)"
}

$schemaVersion = 0
if (-not [int]::TryParse(
        [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "schema_version"),
        [ref]$schemaVersion
    ) -or $schemaVersion -ne 1) {
    throw "The VoCat runtime state has an unsupported schema; no process was stopped."
}

$recordedProcessId = 0
if (-not [int]::TryParse(
        [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "process_id"),
        [ref]$recordedProcessId
    ) -or $recordedProcessId -le 0) {
    throw "The VoCat runtime state contains an invalid process ID; no process was stopped."
}

$recordedExecutablePath = [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "executable_path")
if (-not (Test-PathsEqual -Left $recordedExecutablePath -Right $vocatPath)) {
    throw "The recorded executable does not match this VoCat bundle; no process was stopped."
}
$recordedStopFilePath = [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "stop_file")
if (-not (Test-PathsEqual -Left $recordedStopFilePath -Right $stopFilePath)) {
    throw "The recorded stop-file path does not match this VoCat bundle; no process was stopped."
}
$recordedStartTime = [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "started_at_utc")
if ([string]::IsNullOrWhiteSpace($recordedStartTime)) {
    throw "The VoCat runtime state is missing its process start time; no process was stopped."
}

$serviceProcess = Get-Process -Id $recordedProcessId -ErrorAction SilentlyContinue
if ($null -eq $serviceProcess) {
    Remove-Item -LiteralPath $runtimeStatePath -Force
    if (Test-Path -LiteralPath $stopFilePath -PathType Leaf) {
        Remove-Item -LiteralPath $stopFilePath -Force
    }
    Write-Host "The recorded VoCat process has already stopped; stale state was removed." -ForegroundColor Green
    exit 0
}

$actualExecutablePath = $serviceProcess.Path
if (-not (Test-PathsEqual -Left $actualExecutablePath -Right $vocatPath)) {
    throw "PID $recordedProcessId belongs to another executable; no process was stopped."
}
$actualStartTime = $serviceProcess.StartTime.ToUniversalTime().ToString(
    "o",
    [Globalization.CultureInfo]::InvariantCulture
)
if (-not [StringComparer]::Ordinal.Equals($actualStartTime, $recordedStartTime)) {
    throw "PID $recordedProcessId does not match the recorded start time; no process was stopped."
}

if ((Test-Path -LiteralPath $stopFilePath) -and
    -not (Test-Path -LiteralPath $stopFilePath -PathType Leaf)) {
    throw "The stop-file path is not a regular file: $stopFilePath"
}

Write-Host "Requesting a graceful VoCat shutdown (PID $recordedProcessId)..." -ForegroundColor Cyan
[IO.File]::WriteAllText(
    $stopFilePath,
    "stop requested $([DateTime]::UtcNow.ToString('o'))`r`n",
    [Text.UTF8Encoding]::new($false)
)

try {
    $stoppedGracefully = $serviceProcess.WaitForExit($TimeoutSeconds * 1000)
    if (-not $stoppedGracefully) {
        Write-Warning "VoCat did not exit within $TimeoutSeconds seconds; forcing the verified process to stop."

        $currentProcess = Get-Process -Id $recordedProcessId -ErrorAction SilentlyContinue
        if ($null -ne $currentProcess) {
            $currentExecutablePath = $currentProcess.Path
            $currentStartTime = $currentProcess.StartTime.ToUniversalTime().ToString(
                "o",
                [Globalization.CultureInfo]::InvariantCulture
            )
            if (-not (Test-PathsEqual -Left $currentExecutablePath -Right $vocatPath) -or
                -not ([StringComparer]::Ordinal.Equals($currentStartTime, $recordedStartTime))) {
                throw "PID $recordedProcessId changed while waiting; refusing to force-stop it."
            }

            try {
                $xrayChildren = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $recordedProcessId" |
                    Where-Object { $_.Name -ieq "xray.exe" })
            }
            catch {
                Write-Warning "Managed Xray child discovery failed: $($_.Exception.Message)"
                $xrayChildren = @()
            }
            foreach ($child in $xrayChildren) {
                $xrayProcess = Get-Process -Id ([int]$child.ProcessId) -ErrorAction SilentlyContinue
                if ($null -eq $xrayProcess) {
                    continue
                }
                try {
                    if (Test-PathsEqual -Left $xrayProcess.Path -Right $xrayPath) {
                        $xrayProcess.Kill()
                        if (-not $xrayProcess.WaitForExit(5000)) {
                            Write-Warning "Managed Xray process $($xrayProcess.Id) did not exit promptly."
                        }
                    }
                }
                catch {
                    Write-Warning "Managed Xray process $($child.ProcessId) could not be stopped: $($_.Exception.Message)"
                }
            }

            $currentProcess.Kill()
            if (-not $currentProcess.WaitForExit(10000)) {
                throw "The verified VoCat process could not be stopped."
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $stopFilePath -PathType Leaf) {
        Remove-Item -LiteralPath $stopFilePath -Force -ErrorAction SilentlyContinue
    }
}

Remove-Item -LiteralPath $runtimeStatePath -Force
Write-Host "VoCat has stopped. Background logs were retained under dist\data\logs." -ForegroundColor Green
exit 0
