# Material modifications in the Windows fork

This repository is a modified fork of
[`MengMengCode/VoCat`](https://github.com/MengMengCode/VoCat). The Windows 11
implementation is maintained in [`suyi-92/VoCat`](https://github.com/suyi-92/VoCat)
and is not represented as an official upstream release or endorsement.

Material changes introduced by this fork as of 2026-08-26 include:

- a native `winscard.dll` PC/SC backend for CCID eUICC discovery, ATR/card
  status, device-instance identity, logical channels, APDU exchange, reset,
  and transaction management;
- a native Windows single-instance lock;
- a Wintun user-space ESP/NAT-T data plane with negotiated inner addresses and
  P-CSCF-only host routes;
- dynamic Windows Filtering Platform Manual IPsec SAs and scoped filters for
  IMS traffic;
- Windows diagnostics for process elevation, Smart Card Service, Base
  Filtering Engine, and Wintun DLL integrity/architecture;
- Windows `amd64` and `arm64` CI/release binaries and explicit manual-update
  behavior; and
- Windows-specific tests and cross-platform refactoring required to preserve
  the Linux implementation.

The fork does not bundle `wintun.dll`, vendor subscriber credentials, carrier
test data, or private IMS configuration. The official Wintun binary must be
obtained separately by the operator.

These modifications do not remove or weaken the license, geographic controls,
MCC/MNC restrictions, authorized-SIM/eSIM requirements, device limits,
evaluation/authorization expiry, integrity checks, or anti-abuse behavior.
Possession of this fork does not itself expand a user's rights. Any separate
written authorization applies only to the party and scope stated in that
authorization.

The original [LICENSE](LICENSE) remains in force. Third-party notices and
license texts are retained in [NOTICE](NOTICE) and [`LICENSES/`](LICENSES/).
