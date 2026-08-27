[CmdletBinding()]
param(
    [string]$Address = "127.0.0.1:17575",
    [switch]$SkipDoctor,
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -eq "Desktop") {
    $documentsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)
    $env:PSModulePath = @(
        (Join-Path $documentsDirectory "WindowsPowerShell\Modules"),
        (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"),
        (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules")
    ) -join ";"
}
Import-Module Microsoft.PowerShell.Security -ErrorAction Stop

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-PlainText {
    param([Security.SecureString]$SecureString)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Test-ListenAddressAvailable {
    param(
        [Net.IPAddress]$IPAddress,
        [int]$Port
    )

    $listener = [Net.Sockets.TcpListener]::new($IPAddress, $Port)
    try {
        $listener.Start()
        return $true
    }
    catch [Net.Sockets.SocketException] {
        return $false
    }
    finally {
        $listener.Stop()
    }
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

function ConvertTo-WebUrl {
    param([string]$ListenAddress)

    $browserAddress = $ListenAddress
    if ($browserAddress.StartsWith("0.0.0.0:")) {
        $browserAddress = "127.0.0.1:" + $browserAddress.Substring("0.0.0.0:".Length)
    }
    return "http://$browserAddress"
}

function Test-TcpEndpoint {
    param(
        [string]$HostName,
        [int]$Port
    )

    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.Connect($HostName, $Port)
        return $true
    }
    catch [Net.Sockets.SocketException] {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Stop-LaunchedVoCatAfterFailure {
    param(
        [Diagnostics.Process]$ServiceProcess,
        [string]$StopFilePath
    )

    try {
        $ServiceProcess.Refresh()
        if (-not $ServiceProcess.HasExited) {
            try {
                [IO.File]::WriteAllText(
                    $StopFilePath,
                    "stop requested after launcher failure`r`n",
                    [Text.UTF8Encoding]::new($false)
                )
            }
            catch {
                Write-Warning "The graceful-stop trigger could not be written: $($_.Exception.Message)"
            }
            if (-not $ServiceProcess.WaitForExit(5000)) {
                $ServiceProcess.Kill()
                $null = $ServiceProcess.WaitForExit(5000)
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $StopFilePath -PathType Leaf) {
            Remove-Item -LiteralPath $StopFilePath -Force -ErrorAction SilentlyContinue
        }
    }
}

$listenMatch = [regex]::Match($Address, '^(127\.0\.0\.1|localhost|0\.0\.0\.0):([0-9]{1,5})$')
if (-not $listenMatch.Success) {
    throw "Invalid listen address: $Address"
}
$listenHost = $listenMatch.Groups[1].Value
$listenPort = [int]$listenMatch.Groups[2].Value
if ($listenPort -lt 1 -or $listenPort -gt 65535) {
    throw "Invalid listen port: $listenPort"
}
$listenIPAddress = if ($listenHost -eq "0.0.0.0") {
    [Net.IPAddress]::Any
}
else {
    [Net.IPAddress]::Loopback
}

$architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$platformDirectory = switch ($architecture) {
    "X64" { "windows-amd64" }
    "Arm64" { "windows-arm64" }
    default { throw "VoCat requires 64-bit Windows (x64 or ARM64); detected $architecture." }
}

$bundleRoot = Join-Path $PSScriptRoot $platformDirectory
$vocatPath = Join-Path $bundleRoot "vocat.exe"
$wintunPath = Join-Path $bundleRoot "wintun.dll"
$xrayPath = Join-Path $bundleRoot "xray.exe"
$xrayLicensePath = Join-Path $bundleRoot "XRAY-LICENSE.txt"
$licensePath = Join-Path $bundleRoot "LICENSE"
$noticePath = Join-Path $bundleRoot "NOTICE"
$licensesPath = Join-Path $bundleRoot "LICENSES"
$xrayNoticesPath = Join-Path $licensesPath "xray-core-MPL-2.0.txt"

foreach ($requiredPath in @($vocatPath, $wintunPath, $xrayPath, $xrayLicensePath, $licensePath, $noticePath, $licensesPath, $xrayNoticesPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required runtime file is missing: $requiredPath"
    }
}

$signature = Get-AuthenticodeSignature -LiteralPath $wintunPath
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "The Wintun signature is not valid: $($signature.StatusMessage)"
}
if ($null -eq $signature.SignerCertificate -or
    $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=WireGuard LLC(,|$)') {
    throw "The Wintun DLL is not signed by WireGuard LLC."
}

& $vocatPath version
if ($LASTEXITCODE -ne 0) {
    throw "The VoCat executable failed its version smoke test."
}

$expectedXraySHA256 = switch ($architecture) {
    "X64" { "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1" }
    "Arm64" { "e3340409afd87c1cd928e19208c78cb7271e9f95777aa5122db30759b6d2dc81" }
}
$actualXraySHA256 = (Get-FileHash -LiteralPath $xrayPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualXraySHA256 -ne $expectedXraySHA256) {
    throw "The bundled Xray executable failed its pinned SHA-256 check."
}

$xrayVersion = (& $xrayPath version | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or $xrayVersion -notmatch '^Xray 26\.3\.27\b') {
    throw "The bundled Xray executable failed its pinned version smoke test."
}

if ($ValidateOnly) {
    Write-Host "VoCat runtime validation passed for $platformDirectory." -ForegroundColor Green
    exit 0
}

if (-not (Test-IsAdministrator)) {
    Write-Host "Requesting Administrator privileges for Wintun and WFP..." -ForegroundColor Yellow
    $windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $relaunchArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $PSCommandPath + '"'),
        "-Address", ('"' + $Address + '"')
    )
    if ($SkipDoctor) {
        $relaunchArguments += "-SkipDoctor"
    }
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

$dataDirectory = Join-Path $PSScriptRoot "data"
$databasePath = Join-Path $dataDirectory "vocat.db"
$runtimeStatePath = Join-Path $dataDirectory "vocat.runtime.json"
$stopFilePath = Join-Path $dataDirectory ".vocat-stop"
$logDirectory = Join-Path $dataDirectory "logs"
$stdoutPath = Join-Path $logDirectory "vocat.stdout.log"
$stderrPath = Join-Path $logDirectory "vocat.stderr.log"
New-Item -ItemType Directory -Force -Path $dataDirectory, $logDirectory | Out-Null

if (Test-Path -LiteralPath $runtimeStatePath) {
    if (-not (Test-Path -LiteralPath $runtimeStatePath -PathType Leaf)) {
        throw "The runtime-state path is not a regular file: $runtimeStatePath"
    }
    try {
        $runtimeState = Get-Content -LiteralPath $runtimeStatePath -Raw | ConvertFrom-Json
        $recordedSchemaVersion = 0
        if (-not [int]::TryParse(
                [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "schema_version"),
                [ref]$recordedSchemaVersion
            ) -or $recordedSchemaVersion -ne 1) {
            throw "The recorded runtime-state schema is unsupported."
        }
        $recordedProcessId = 0
        if (-not [int]::TryParse(
                [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "process_id"),
                [ref]$recordedProcessId
            ) -or $recordedProcessId -le 0) {
            throw "The recorded process ID is invalid."
        }
        $recordedExecutablePath = [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "executable_path")
        if (-not (Test-PathsEqual -Left $recordedExecutablePath -Right $vocatPath)) {
            throw "The recorded executable does not match this VoCat bundle."
        }
        $recordedStopFilePath = [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "stop_file")
        if (-not (Test-PathsEqual -Left $recordedStopFilePath -Right $stopFilePath)) {
            throw "The recorded stop-file path does not match this VoCat bundle."
        }
        $recordedStartTime = [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "started_at_utc")
        if ([string]::IsNullOrWhiteSpace($recordedStartTime)) {
            throw "The recorded process start time is missing."
        }
        $recordedAddress = [string](Get-JsonPropertyValue -InputObject $runtimeState -Name "address")
        $recordedAddressMatch = [regex]::Match(
            $recordedAddress,
            '^(127\.0\.0\.1|localhost|0\.0\.0\.0):([0-9]{1,5})$'
        )
        if (-not $recordedAddressMatch.Success) {
            throw "The recorded listen address is invalid."
        }
        $recordedPort = [int]$recordedAddressMatch.Groups[2].Value
        if ($recordedPort -lt 1 -or $recordedPort -gt 65535) {
            throw "The recorded listen port is invalid."
        }

        $runningProcess = Get-Process -Id $recordedProcessId -ErrorAction SilentlyContinue
        if ($null -eq $runningProcess) {
            throw "The recorded VoCat process is no longer running."
        }
        $actualExecutablePath = $runningProcess.Path
        if (-not (Test-PathsEqual -Left $actualExecutablePath -Right $vocatPath)) {
            throw "Process $recordedProcessId is not this VoCat executable."
        }
        $actualStartTime = $runningProcess.StartTime.ToUniversalTime().ToString(
            "o",
            [Globalization.CultureInfo]::InvariantCulture
        )
        if (-not [StringComparer]::Ordinal.Equals($actualStartTime, $recordedStartTime)) {
            throw "Process $recordedProcessId does not match the recorded start time."
        }

        $existingWebUrl = ConvertTo-WebUrl -ListenAddress $recordedAddress
        Write-Host "VoCat is already running at $existingWebUrl (PID $recordedProcessId)." -ForegroundColor Green
        try {
            Start-Process $existingWebUrl
        }
        catch {
            Write-Warning "VoCat is running, but the browser could not be opened: $($_.Exception.Message)"
        }
        exit 0
    }
    catch {
        Write-Warning "Removing stale VoCat runtime state: $($_.Exception.Message)"
        Remove-Item -LiteralPath $runtimeStatePath -Force
    }
}

if (Test-Path -LiteralPath $stopFilePath) {
    if (-not (Test-Path -LiteralPath $stopFilePath -PathType Leaf)) {
        throw "The stop-file path is not a regular file: $stopFilePath"
    }
    Remove-Item -LiteralPath $stopFilePath -Force
}

if (-not (Test-ListenAddressAvailable -IPAddress $listenIPAddress -Port $listenPort)) {
    $fallbackPort = @(17575, 27575, 37575, 47575) |
        Where-Object { $_ -ne $listenPort -and (Test-ListenAddressAvailable -IPAddress $listenIPAddress -Port $_) } |
        Select-Object -First 1
    if ($null -eq $fallbackPort) {
        throw "The requested port $listenPort is unavailable and no fallback port could be bound."
    }
    Write-Warning "Port $listenPort is occupied or reserved by Windows; using $fallbackPort instead."
    $listenPort = $fallbackPort
    $Address = "${listenHost}:$listenPort"
}

foreach ($serviceName in @("SCardSvr", "BFE")) {
    $service = Get-Service -Name $serviceName
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        Write-Host "Starting Windows service $serviceName..."
        Start-Service -Name $serviceName
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(15))
    }
}

if (-not (Test-Path -LiteralPath $databasePath)) {
    Write-Host "No local database was found. Creating the initial admin account 'admin'." -ForegroundColor Cyan
    $securePassword = Read-Host "Enter the VoCat administrator password" -AsSecureString
    $plainPassword = ConvertTo-PlainText -SecureString $securePassword
    try {
        if ([string]::IsNullOrWhiteSpace($plainPassword)) {
            throw "The administrator password cannot be empty."
        }
        $plainPassword | & $vocatPath bootstrap-admin --database $databasePath --username admin
        if ($LASTEXITCODE -ne 0) {
            throw "VoCat failed to initialize the administrator account."
        }
    }
    finally {
        $plainPassword = $null
        $securePassword.Dispose()
    }
}

if (-not $SkipDoctor) {
    Write-Host "Running Windows readiness diagnostics..." -ForegroundColor Cyan
    & $vocatPath doctor --json
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "VoCat doctor reported a failure. Review the JSON output before continuing."
        $continue = Read-Host "Start VoCat anyway? [y/N]"
        if ($continue -notmatch '^(?i:y|yes)$') {
            exit 1
        }
    }
}

$env:VOCAT_DATABASE_PATH = $databasePath
$env:VOCAT_ADDR = $Address
$env:VOCAT_XRAY_PATH = $xrayPath
$env:VOCAT_STOP_FILE = $stopFilePath

$webUrl = ConvertTo-WebUrl -ListenAddress $Address
Write-Host "Starting VoCat in the background at $webUrl..." -ForegroundColor Green

$serviceProcess = Start-Process `
    -FilePath $vocatPath `
    -ArgumentList "serve" `
    -WorkingDirectory $bundleRoot `
    -WindowStyle Hidden `
    -PassThru `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath

$serviceReady = $false
$startupDeadline = [DateTime]::UtcNow.AddSeconds(45)
while ([DateTime]::UtcNow -lt $startupDeadline) {
    $serviceProcess.Refresh()
    if ($serviceProcess.HasExited) {
        break
    }
    if (Test-TcpEndpoint -HostName "127.0.0.1" -Port $listenPort) {
        $serviceReady = $true
        break
    }
    Start-Sleep -Milliseconds 250
}

if (-not $serviceReady) {
    $serviceProcess.Refresh()
    if ($serviceProcess.HasExited) {
        $errorTail = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            (Get-Content -LiteralPath $stderrPath -Tail 20) -join [Environment]::NewLine
        }
        else {
            "No stderr log was written."
        }
        throw "VoCat exited with code $($serviceProcess.ExitCode) during startup.`r`n$errorTail"
    }
    Stop-LaunchedVoCatAfterFailure -ServiceProcess $serviceProcess -StopFilePath $stopFilePath
    throw "VoCat did not begin listening at $webUrl within 45 seconds."
}

$serviceProcess.Refresh()
if ($serviceProcess.HasExited) {
    throw "VoCat exited immediately after opening its HTTP listener."
}

$runtimeState = [ordered]@{
    schema_version  = 1
    process_id      = $serviceProcess.Id
    started_at_utc  = $serviceProcess.StartTime.ToUniversalTime().ToString(
        "o",
        [Globalization.CultureInfo]::InvariantCulture
    )
    executable_path = [IO.Path]::GetFullPath($vocatPath)
    address         = $Address
    stop_file       = [IO.Path]::GetFullPath($stopFilePath)
}
$temporaryStatePath = "$runtimeStatePath.$([Guid]::NewGuid().ToString('N')).tmp"
try {
    $runtimeStateJson = $runtimeState | ConvertTo-Json
    [IO.File]::WriteAllText(
        $temporaryStatePath,
        $runtimeStateJson + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporaryStatePath -Destination $runtimeStatePath -Force
}
catch {
    Remove-Item -LiteralPath $temporaryStatePath -Force -ErrorAction SilentlyContinue
    Stop-LaunchedVoCatAfterFailure -ServiceProcess $serviceProcess -StopFilePath $stopFilePath
    throw
}

try {
    Start-Process $webUrl
}
catch {
    Write-Warning "VoCat started, but the browser could not be opened: $($_.Exception.Message)"
}

Write-Host "VoCat is running in the background (PID $($serviceProcess.Id))." -ForegroundColor Green
Write-Host "Use stop-vocat.cmd to stop it safely."
Write-Host "Logs: $logDirectory"
exit 0
