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
- The official Xray-core v26.3.27 `xray.exe` when Clash VLESS/Reality upstream
  proxies are used.
- An operator-authorized SIM/eSIM with WiFi Calling provisioned, reachable
  ePDG, and valid IMS configuration.

Keep subscriber credentials, activation codes, Ki/OPc material, proxy secrets,
and operator test data outside the repository and diagnostic logs.

## Install the release archive

Download these two files from the same GitHub Release:

- `vocat-windows-amd64.zip` or `vocat-windows-arm64.zip`
- `SHA256SUMS`

Verify the downloaded archive in PowerShell before extracting or running it:

```powershell
$archive = ".\vocat-windows-amd64.zip"
$name = Split-Path $archive -Leaf
$pattern = '^(?<hash>[0-9A-Fa-f]{64})\s+\*?' + [regex]::Escape($name) + '$'
$records = @(Select-String -LiteralPath .\SHA256SUMS -Pattern $pattern)
if ($records.Count -ne 1) { throw "Expected exactly one SHA256SUMS record for $name" }
$expected = $records[0].Matches[0].Groups['hash'].Value.ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "VoCat SHA-256 verification failed for $name" }
Expand-Archive -LiteralPath $archive -DestinationPath .\vocat-windows-amd64
```

Confirm the extracted directory contains the matching `.exe`, `LICENSE`,
`NOTICE`, and `LICENSES/`. Move that directory to a dedicated location such as
`C:\VoCat`, retain the verified `.zip` there, and optionally rename the
executable to `vocat.exe`.

## Install the Windows runtime files

The checked-in ready-to-run bundles under `dist/windows-amd64` and
`dist/windows-arm64` already contain the unmodified, Authenticode-signed Wintun
0.14.1 DLL, the unmodified official Xray-core v26.3.27 executable, their license
texts, and checksums. Run `dist/start-vocat.cmd` to select the matching
architecture, validate Wintun and Xray before use, initialize the local
database, run diagnostics, and start VoCat as a hidden background process.
Once the HTTP listener is ready, the launcher opens the Web UI and its command
window exits. Run `dist/stop-vocat.cmd` to request a graceful shutdown. Runtime
state, the database, and background logs under `dist/data` are intentionally
excluded from Git; stdout and stderr are retained in `dist/data/logs`.

The launcher and VoCat both pin Xray by architecture and SHA-256 before it can
run:

| Architecture | Xray-core v26.3.27 SHA-256 |
| --- | --- |
| x86-64 | `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1` |
| ARM64 | `e3340409afd87c1cd928e19208c78cb7271e9f95777aa5122db30759b6d2dc81` |

For another build that does not contain the DLL, download the signed Wintun
package from the [official Wintun site](https://www.wintun.net/), then copy
exactly one DLL beside `vocat.exe`:

- x86-64 VoCat: `bin\amd64\wintun.dll`
- ARM64 VoCat: `bin\arm64\wintun.dll`

VoCat loads the DLL only from the executable directory or Windows `System32`.
The executable directory is recommended because it keeps the dependency scoped
to VoCat. Do not use a DLL from an unofficial download or a different CPU
architecture. At VoWiFi startup, VoCat locks the selected file against writes,
replacement, and deletion; validates its PE architecture, cached Authenticode
trust, and required exports; loads that exact canonical path with System32-only
dependency search; and verifies the resulting module file identity. The module
reference is retained for the process lifetime so later Wintun API lookups reuse
the validated image. VoWiFi fails closed if any step fails.

Wintun is required only for VoWiFi. PC/SC eSIM reading and profile management
remain available when the DLL is absent.

For another build that needs VLESS, download Xray-core v26.3.27 from the
[official Xray-core release](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27),
verify the matching hash above, and place `xray.exe` beside `vocat.exe` (or set
`VOCAT_XRAY_PATH` to that exact file). Windows builds deliberately reject a
different architecture or hash. VoCat starts one loopback-only SOCKS5 bridge
on demand for each active VLESS upstream and removes its temporary restricted
configuration file after Xray has read it.

In **Proxy Management**, choose **Import Clash** and paste exactly one VLESS +
TCP + TLS Reality proxy entry, a one-item YAML list, or a complete Clash YAML
document whose `proxies:` list contains one entry. VoCat recognizes `server`,
`port`, `uuid`, `flow`, `network`, `tls`, `client-fingerprint`, `udp`,
`reality-opts`, `alpn`, and `servername`. The UUID is stored as a secret and is
returned to the editor only as `********`. A node with `udp: false` can be
saved, but cannot be assigned to a SIM/Profile or an MCC country rule because
VoWiFi requires UDP.

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

For the checked-in ready-to-run bundle, double-click `dist\start-vocat.cmd` or
run it from PowerShell. The launcher requests Administrator privileges, creates
the initial `admin` account when necessary, starts VoCat in the background, and
opens the Web UI. No command-line window remains after startup. Stop that
background instance with:

```powershell
& .\dist\stop-vocat.cmd
```

The stop launcher validates the recorded PID, executable path, and process
start time before signalling VoCat. VoCat then removes its managed Xray,
VoWiFi, Wintun, WFP, device, and HTTP resources through the normal graceful
shutdown path. A forced stop is used only after the configured timeout.

The following commands are the manual foreground alternative. They do not
create launcher state, so stop a manually launched server with `Ctrl+C` in the
same console rather than `stop-vocat.cmd`.

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

The Windows report checks elevation, `BFE`, `SCardSvr`, and the Wintun DLL path,
PE architecture, cached Authenticode trust, and every Wintun API export used by
VoCat through the same locked-file validation used at VoWiFi startup. `doctor`
maps the DLL without resolving dependencies or running its initializers. Without
`--repair-dji-qmi`, it does not change USB bindings, card profiles, routes, or
service configuration.

Start the foreground service:

```powershell
$env:VOCAT_DATABASE_PATH = $database
$env:VOCAT_ADDR = '127.0.0.1:7575'
& .\vocat.exe serve
```

Open `http://127.0.0.1:7575`. Use an explicit LAN address and a narrowly scoped
Windows Firewall rule only if another computer must reach the Web interface.
Do not expose the unencrypted HTTP listener directly to the public Internet.

Only one VoCat server process may control a host at a time. Windows builds use
a restricted machine-wide `Global\` named-object sentinel, shared across
interactive users and service identities, to prevent concurrent processes from
racing the card, Wintun adapter, and WFP state.

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
4. installs host routes for negotiated P-CSCF addresses and, only after both
   IKE traffic selectors admit the UDP addresses and ports, active SDP media
   destinations; routes are reference-counted across early media, final
   answers, and re-INVITEs;
5. keeps MTU 1380, no default route, disabled router discovery, and no automatic
   metric, while a dynamic WFP source guard blocks an assigned inner address
   from escaping through any non-Wintun interface; and
6. installs dynamic, address-and-port-scoped WFP Manual IPsec SAs for IMS.

Closing the session removes the dynamic WFP contexts, filters, sublayer,
routes, and addresses. VoCat does not ask Windows native IKE to acquire an SA
for those filters.

The WFP ABI and rollback paths are unit-tested, but an end-to-end registration
still depends on the specific operator. Do not manufacture IMS credentials or
run a live-network SA test without the operator-provided test subscription and
authorization.

## Updating on Windows

Use `vocat.exe update --check` or the Web UI to check for a release. Windows
does not try to overwrite its running executable. Tagged builds check the
repository that produced the binary; `VOCAT_REPO` or `--repo` can explicitly
select a different trusted channel. A release is offered only when it contains
the matching Windows platform archive and `SHA256SUMS`. To update:

1. download the matching `.zip` and `SHA256SUMS` from the same release;
2. verify the archive's SHA-256 value before extracting it;
3. run `dist\stop-vocat.cmd` for a background-launcher instance (or press
   `Ctrl+C` for a manual foreground instance), then make a backup of the
   existing executable;
4. extract the archive, replace the executable, refresh `LICENSE`, `NOTICE`,
   and `LICENSES/`, and retain the verified archive; for a ready-to-run bundle,
   also refresh its pinned `xray.exe` and Xray license text; and
5. run `doctor --json`, then use `dist\start-vocat.cmd` again (or start
   `serve` manually for foreground operation).

Keep the database and `wintun.dll`; neither needs to be replaced with every
VoCat release. Keep `xray.exe` only when its version and SHA-256 still match the
new VoCat build's documented pin.

## Troubleshooting

- `smart_card_service` is not running: in elevated PowerShell run
  `Start-Service SCardSvr`, then reconnect the reader.
- `wfp_service_not_running`: confirm `BFE` is enabled and running. Do not
  disable Windows Firewall/BFE to work around this error.
- `wintun_dll_missing`: place the official DLL beside the executable.
- `wintun_architecture_mismatch`: replace the DLL with the `amd64` or `arm64`
  build matching `vocat.exe`.
- `wintun_dll_untrusted`: replace the DLL with an Authenticode-trusted package
  from the official Wintun site.
- `wintun_dll_exports_missing`: the DLL is not API-compatible with this VoCat
  build; replace it with the current official architecture-matched DLL.
- VLESS import reports that the proxy core is unavailable: place the pinned
  `xray.exe` beside `vocat.exe`, or configure `VOCAT_XRAY_PATH`.
- Xray architecture or SHA-256 validation fails: replace it only with the
  official v26.3.27 file for the current architecture; do not bypass the check.
- Access denied while creating Wintun or WFP state: restart VoCat from an
  elevated Administrator console.
- The reader appears as WinUSB but not as a smart-card reader: restore the
  Microsoft CCID/smart-card driver for its CCID interface.
- eSIM works but SMS/USSD does not: a CCID reader is not a cellular modem;
  direct modem features require AT/QMI/MBIM/WWAN hardware, while IMS SMS needs
  successful VoWiFi registration.

See [MODIFICATIONS.md](../MODIFICATIONS.md) for the material-change notice and
[NOTICE](../NOTICE) for third-party components.
