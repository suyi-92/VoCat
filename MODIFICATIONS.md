# Material modifications in the Windows fork

This repository is a modified fork of
[`MengMengCode/VoCat`](https://github.com/MengMengCode/VoCat). The Windows 11
implementation is maintained in [`suyi-92/VoCat`](https://github.com/suyi-92/VoCat)
and is not represented as an official upstream release or endorsement.

Material changes introduced by this fork as of 2026-08-27 include:

- a native `winscard.dll` PC/SC backend for CCID eUICC discovery, ATR/card
  status, device-instance identity, logical channels, APDU exchange, reset,
  and transaction management;
- a restricted machine-wide Windows named-object single-instance sentinel;
- a Wintun user-space ESP/NAT-T data plane with negotiated inner addresses and
  P-CSCF routes, traffic-selector-validated dynamic media routes, stable adapter
  identity, transient ring-pressure handling, and fail-closed source routing;
- dynamic Windows Filtering Platform Manual IPsec SAs and scoped filters for
  IMS traffic;
- Windows diagnostics for process elevation, Smart Card Service, Base
  Filtering Engine, and Wintun DLL integrity, architecture, Authenticode trust,
  and required exports;
- standard Clash YAML import for VLESS/TCP/TLS Reality upstreams, with strict
  field validation, secret redaction, UDP-aware binding rules, and an on-demand
  loopback SOCKS5 bridge through a version- and SHA-256-pinned Xray core;
- Windows background start and identity-validated graceful-stop launchers,
  with retained stdout/stderr logs and a bounded force-stop fallback;
- Windows `amd64` and `arm64` CI/release binaries and explicit manual-update
  behavior; and
- Windows-specific tests and cross-platform refactoring required to preserve
  the Linux implementation.

The checked-in `dist/windows-amd64` and `dist/windows-arm64` ready-to-run
bundles include the unmodified, Authenticode-signed Wintun 0.14.1 DLL alongside
VoCat and the Wintun prebuilt-binary license, as permitted for software using
the documented Wintun API. They also contain the unmodified official Xray-core
v26.3.27 executable and its MPL-2.0 license for managed VLESS operation. Other
release or source builds must obtain the required official, architecture-matched
runtime files separately. Vendor subscriber credentials, carrier test data,
private IMS configuration, proxy credentials, and runtime databases remain
excluded from the repository.

These modifications do not remove or weaken the license, geographic controls,
MCC/MNC restrictions, authorized-SIM/eSIM requirements, device limits,
evaluation/authorization expiry, integrity checks, or anti-abuse behavior.
Possession of this fork does not itself expand a user's rights. Any separate
written authorization applies only to the party and scope stated in that
authorization.

The original [LICENSE](LICENSE) remains in force. Third-party notices and
license texts are retained in [NOTICE](NOTICE) and [`LICENSES/`](LICENSES/).
The implementation review and remediation evidence are recorded in
[`docs/WINDOWS_NATIVE_REVIEW.md`](docs/WINDOWS_NATIVE_REVIEW.md).
