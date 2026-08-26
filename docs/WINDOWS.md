# Windows 11 native deployment

This document describes the native Windows implementation maintained by the
`suyi-92/VoCat` fork. It does not use EasyLPAC, WSL, a Linux virtual machine, or
a vendor modem driver for standard CCID eUICC access.

The Windows port is available for `amd64` and `arm64`. The eSIM path uses the
Windows Smart Card API (`winscard.dll`); VoWiFi uses Wintun for the negotiated
inner IP addresses and routes, then Windows Filtering Platform (WFP) Manual
IPsec for IMS traffic.

## Support boundary

| Capability | Native Windows 11 status |
| --- | --- |
| Enumerate CCID readers, ATR, EID and eUICC information | Supported through Windows PC/SC |
| List, download, enable, disable, switch, rename and delete profiles | Supported when the eUICC and SM-DP+ authorize the operation |
| Quectel AT/QMI/WWAN functions | Not available for a CCID-only reader; a separate supported modem interface is required |
| Direct cellular SMS and USSD | Not available for a CCID-only reader |
| ePDG/IKEv2/EAP-AKA and IMS registration | Implemented; requires carrier provisioning and an authorized SIM/eSIM |
| IMS SMS | Available after successful VoWiFi and IMS registration |
| Voice calls | Experimental; the current media path implements PCMA/PCMU (G.711). AMR/AMR-WB, RTP DTMF, AEC and a jitter buffer are not yet supported |
| Windows self-update | Release checks are supported; replace the stopped executable manually |

Support means VoCat can send the standards-based request. It does not bypass
eUICC trust, SM-DP+ policy, carrier authentication, IMS provisioning, regional
controls, MCC/MNC restrictions, device limits, or authorization expiry.

## Requirements

- 64-bit Windows 11 matching the downloaded `amd64` or `arm64` build.
- A Windows-visible CCID smart-card reader and eUICC.
- The Windows **Smart Card** service (`SCardSvr`).
- An elevated Administrator process for Wintun and WFP VoWiFi setup. PC/SC
  eSIM operations can often run without elevation.
- The **Base Filtering Engine** service (`BFE`) for IMS IPsec.
- The official, architecture-matched `wintun.dll` for VoWiFi.
- An operator-authorized SIM/eSIM with WiFi Calling provisioned, reachable
  ePDG, and valid IMS configuration.

Keep subscriber credentials, activation codes, Ki/OPc material, proxy secrets,
and operator test data outside the repository and diagnostic logs.

## Install the binary

Download these two files from the same GitHub Release:

- `vocat-windows-amd64.exe` or `vocat-windows-arm64.exe`
- `SHA256SUMS`

Verify the binary in PowerShell before running it:

```powershell
$binary = ".\vocat-windows-amd64.exe"
$expected = ((Select-String -LiteralPath .\SHA256SUMS -Pattern ([regex]::Escape((Split-Path $binary -Leaf)) + '$')).Line -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $expected -or $actual -ne $expected) { throw "VoCat SHA-256 verification failed" }
```

Create a dedicated directory such as `C:\VoCat`, move the verified executable
there, and optionally rename it to `vocat.exe`.

## Install the official Wintun DLL

VoCat does not redistribute `wintun.dll`. Download the signed Wintun package
from the [official Wintun site](https://www.wintun.net/), then copy exactly one
DLL beside `vocat.exe`:

- x86-64 VoCat: `bin\amd64\wintun.dll`
- ARM64 VoCat: `bin\arm64\wintun.dll`

VoCat loads the DLL only from the executable directory or Windows `System32`.
The executable directory is recommended because it keeps the dependency scoped
to VoCat. Do not use a DLL from an unofficial download or a different CPU
architecture.

Wintun is required only for VoWiFi. PC/SC eSIM reading and profile management
remain available when the DLL is absent.

## Identify the attached USB device

Windows Device Manager or these read-only PowerShell commands can show the
interfaces exposed by the hardware:

```powershell
Get-PnpDevice -PresentOnly -Class SmartCardReader
Get-PnpDevice -PresentOnly | Where-Object InstanceId -Like 'USB\VID_*&PID_*'
```

The hardware verified during this port reports `VID_04D9&PID_C001`:

| Interface | Windows role | Used by standard VoCat eUICC operations |
| --- | --- | --- |
| `MI_01` | CCID smart-card reader (`SCR Prime 0`) | Yes |
| `MI_00` | DFU | No |
| `MI_02` | Vendor-specific WinUSB | No |

This is not a Quectel/DJI modem composition: it exposes no COM, QMI, MBIM, or
WWAN function. VoCat therefore uses `MI_01` for ISO 7816/eUICC APDUs, while SMS
and calls must use the software VoWiFi/IMS path. Other standards-compliant CCID
readers may work even when their VID/PID and displayed reader name differ.

Do not replace the CCID driver with WinUSB. The vendor-specific `MI_02`
interface is intentionally not opened by the standard eUICC backend.

## Initialize and run VoCat

Open an elevated PowerShell window for the complete VoWiFi feature set, change
to the installation directory, and initialize a local database:

```powershell
Set-Location C:\VoCat
New-Item -ItemType Directory -Force -Path .\data | Out-Null
$database = Join-Path $PWD 'data\vocat.db'
$securePassword = Read-Host 'VoCat administrator password' -AsSecureString
$plainPassword = [System.Net.NetworkCredential]::new('', $securePassword).Password
$plainPassword | & .\vocat.exe bootstrap-admin --database $database
Remove-Variable plainPassword, securePassword
```

Run the read-only diagnostics before starting the server:

```powershell
& .\vocat.exe doctor --json
```

The Windows report checks elevation, `BFE`, `SCardSvr`, and the Wintun DLL path
and PE architecture. `doctor` without `--repair-dji-qmi` does not change USB
bindings, card profiles, routes, or service configuration.

Start the foreground service:

```powershell
$env:VOCAT_DATABASE_PATH = $database
$env:VOCAT_ADDR = '127.0.0.1:7575'
& .\vocat.exe serve
```

Open `http://127.0.0.1:7575`. Use an explicit LAN address and a narrowly scoped
Windows Firewall rule only if another computer must reach the Web interface.
Do not expose the unencrypted HTTP listener directly to the public Internet.

Only one VoCat process should use the installation at a time. Windows builds
use a native file lock to prevent concurrent processes from racing the card,
Wintun adapter, and WFP state.

## Add and verify the eUICC

1. Open **Devices**, rescan, and select the PC/SC reader (for the verified unit,
   `SCR Prime 0`).
2. Confirm that ATR, EID, and installed-profile inventory can be read.
3. Perform a profile download or state change only after checking the target
   ICCID, activation code, and carrier authorization.

The opt-in Go integration probe is intentionally read-only at the profile
level. It opens a logical channel, selects ISD-R, and closes the channel:

```powershell
$env:VOCAT_PCSC_INTEGRATION_READER = 'SCR Prime 0'
go test ./internal/pcsc
Remove-Item Env:VOCAT_PCSC_INTEGRATION_READER
```

It never downloads, enables, disables, switches, renames, or deletes a profile.

## VoWiFi networking behavior

When the operator starts VoWiFi, VoCat:

1. completes IKEv2/EAP-AKA with the carrier ePDG and requires negotiated
   NAT-T;
2. creates or opens a dedicated Wintun adapter;
3. assigns only the negotiated `/32` or `/128` inner address;
4. installs host routes only for negotiated P-CSCF addresses, with MTU 1380,
   no default route, disabled router discovery, and no automatic metric; and
5. installs dynamic, address-and-port-scoped WFP Manual IPsec SAs for IMS.

Closing the session removes the dynamic WFP contexts, filters, sublayer,
routes, and addresses. VoCat does not ask Windows native IKE to acquire an SA
for those filters.

The WFP ABI and rollback paths are unit-tested, but an end-to-end registration
still depends on the specific operator. Do not manufacture IMS credentials or
run a live-network SA test without the operator-provided test subscription and
authorization.

## Updating on Windows

Use `vocat.exe update --check` or the Web UI to check for a release. Windows
does not try to overwrite its running executable. To update:

1. download the matching `.exe` and `SHA256SUMS` from the same release;
2. verify the SHA-256 value;
3. stop VoCat and make a backup of the existing executable;
4. replace it with the verified file; and
5. run `doctor --json`, then start `serve` again.

Keep the database and `wintun.dll`; neither needs to be replaced with every
VoCat release.

## Troubleshooting

- `smart_card_service` is not running: in elevated PowerShell run
  `Start-Service SCardSvr`, then reconnect the reader.
- `wfp_service_not_running`: confirm `BFE` is enabled and running. Do not
  disable Windows Firewall/BFE to work around this error.
- `wintun_dll_missing`: place the official DLL beside the executable.
- `wintun_architecture_mismatch`: replace the DLL with the `amd64` or `arm64`
  build matching `vocat.exe`.
- Access denied while creating Wintun or WFP state: restart VoCat from an
  elevated Administrator console.
- The reader appears as WinUSB but not as a smart-card reader: restore the
  Microsoft CCID/smart-card driver for its CCID interface.
- eSIM works but SMS/USSD does not: a CCID reader is not a cellular modem;
  direct modem features require AT/QMI/MBIM/WWAN hardware, while IMS SMS needs
  successful VoWiFi registration.

See [MODIFICATIONS.md](../MODIFICATIONS.md) for the material-change notice and
[NOTICE](../NOTICE) for third-party components.
