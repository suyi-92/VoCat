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

$architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$platformDirectory = switch ($architecture) {
    "X64" { "windows-amd64" }
    "Arm64" { "windows-arm64" }
    default { throw "VoCat requires 64-bit Windows (x64 or ARM64); detected $architecture." }
}

$bundleRoot = Join-Path $PSScriptRoot $platformDirectory
$vocatPath = Join-Path $bundleRoot "vocat.exe"
$wintunPath = Join-Path $bundleRoot "wintun.dll"
$licensePath = Join-Path $bundleRoot "LICENSE"
$noticePath = Join-Path $bundleRoot "NOTICE"
$licensesPath = Join-Path $bundleRoot "LICENSES"

foreach ($requiredPath in @($vocatPath, $wintunPath, $licensePath, $noticePath, $licensesPath)) {
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
    Start-Process `
        -FilePath $windowsPowerShell `
        -Verb RunAs `
        -WorkingDirectory $PSScriptRoot `
        -ArgumentList ($relaunchArguments -join " ")
    exit 0
}

Set-Location -LiteralPath $PSScriptRoot

foreach ($serviceName in @("SCardSvr", "BFE")) {
    $service = Get-Service -Name $serviceName
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        Write-Host "Starting Windows service $serviceName..."
        Start-Service -Name $serviceName
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(15))
    }
}

$dataDirectory = Join-Path $PSScriptRoot "data"
$databasePath = Join-Path $dataDirectory "vocat.db"
New-Item -ItemType Directory -Force -Path $dataDirectory | Out-Null

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

$browserAddress = $Address
if ($browserAddress.StartsWith("0.0.0.0:")) {
    $browserAddress = "127.0.0.1:" + $browserAddress.Substring("0.0.0.0:".Length)
}
$webUrl = "http://$browserAddress"

Write-Host "Starting VoCat at $webUrl" -ForegroundColor Green
Write-Host "Press Ctrl+C in this window to stop VoCat."

$windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$escapedUrl = $webUrl.Replace("'", "''")
$browserScript = @"
`$webUrl = '$escapedUrl'
for (`$attempt = 1; `$attempt -le 30; `$attempt++) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri `$webUrl -TimeoutSec 1 | Out-Null
        Start-Process `$webUrl
        exit 0
    }
    catch {
        Start-Sleep -Seconds 1
    }
}
"@
$encodedBrowserScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($browserScript))
Start-Process `
    -FilePath $windowsPowerShell `
    -WindowStyle Hidden `
    -ArgumentList "-NoLogo -NoProfile -WindowStyle Hidden -EncodedCommand $encodedBrowserScript"

& $vocatPath serve
$serverExitCode = $LASTEXITCODE
if ($serverExitCode -ne 0) {
    throw "VoCat exited with code $serverExitCode."
}
