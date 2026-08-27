# Windows Native Branch Review and Remediation Record

## Scope

This document records the review of branch `codex/win11-native` at commit
`1554745b85d1423ee1eb04f14046bb6ef9d3ccbe`, compared with authoritative
upstream commit `upstream/master` at
`7dea7ad41af343be5ebc16f1b4725e3e9b78bad7`.

The review covers the native Windows 11 PC/SC, Wintun, WFP, update, diagnostic,
and release paths. The implementation work below must preserve Linux behavior
and must not weaken the negotiated IKE traffic-selector boundary.

## Findings

| ID | Priority | Area | Finding | Required remediation |
| --- | --- | --- | --- | --- |
| WIN-001 | P1 | IMS/WFP | Windows rejects odd inbound SPIs passed to `IPsecSaContextSetSpi0`; two independently random UE SPIs make setup failure likely. | Allocate valid, unique, non-reserved even UE SPIs and cover the constraint with tests. |
| WIN-002 | P1 | IMS/WFP | IPv6 addresses in `IPSEC_TRAFFIC1` are copied in network order although WFP expects four host-order 32-bit words in least-significant-word-first order. | Convert each IPv6 word from network to host order, reverse the four-word order, and update representation tests. |
| WIN-003 | P1 | IKE/media | The Wintun interface contains only P-CSCF host routes, while RTP uses the media address negotiated in SDP. | Add a traffic-selector-validated dynamic route lifecycle for media destinations and fail closed for unmatched traffic sourced from an inner address. |
| WIN-004 | P1 | PC/SC | Blocking WinSCard calls outlive `context.Context`; `SCardBeginTransaction` can freeze the service-wide card lock. | Cancel a blocked transaction with `SCardCancelTransaction`, cancel other outstanding context operations where supported, and map cancellation to `ctx.Err()`. |
| WIN-005 | P2 | Wintun | A transient full send ring is treated as a terminal dataplane failure. | Treat `ERROR_BUFFER_OVERFLOW` as bounded packet loss/backpressure and reserve teardown for terminal errors. |
| WIN-006 | P2 | Wintun | New adapters use a random requested GUID, creating a new NLA identity after recreation. | Derive a deterministic GUID from the stable tunnel/device name. |
| WIN-007 | P2 | Process control | The Windows instance lock lives in a per-user cache directory even though controlled resources are machine-wide. | Use a machine-wide named mutex with an explicit security policy and keep a process-owned handle for its lifetime. |
| WIN-008 | P2 | Update | Windows update checks can report a release without a matching executable, and fork builds default to the upstream repository. | Make the release repository build-configurable and require platform binary plus `SHA256SUMS` before reporting an available Windows update. |
| WIN-009 | P2 | Diagnostics | The Wintun doctor check accepts any architecture-matched PE file and can report readiness before required exports are resolved. | Validate all required Wintun exports and, when claiming an official DLL, validate a trusted signature or documented hash. |
| WIN-010 | P2 | Release | Binary release artifacts omit the repository's third-party notices and MIT license texts. | Publish archives containing the executable, `NOTICE`, and `LICENSES`, and document archive-based installation. |
| WIN-011 | P3 | PC/SC | Reader hot-plug can change the required multi-string length between the two `SCardListReadersW` calls. | Retry `SCARD_E_INSUFFICIENT_BUFFER` with the returned bounded size. |

## Post-implementation audit findings

The first remediation pass was reviewed again before release. The following
findings are part of the same release gate; completing only WIN-001 through
WIN-011 is not sufficient.

| ID | Priority | Area | Finding | Required remediation |
| --- | --- | --- | --- | --- |
| WIN-012 | P1 | IKE/WFP | The source guard compares `FWPM_CONDITION_IP_LOCAL_INTERFACE` with the Wintun LUID. That field identifies the interface associated with the local address, not the interface selected for outbound transmission, so an inner address bound to Wintun can bypass the guard when a physical interface is selected. | At `FWPM_LAYER_OUTBOUND_IPPACKET_V4/V6`, compare `FWPM_CONDITION_INTERFACE_INDEX` with the Wintun interface index using `FWP_UINT32` and `FWP_MATCH_NOT_EQUAL`; cover the condition key, type, and value with tests. |
| WIN-013 | P1 | IKE/Wintun | `FlushIPAddresses` ignores each row deletion error, and starting an existing adapter before clearing stale addresses exposes addresses left by a crashed or older process. Guard removal can therefore be based on a false cleanup success. | Enumerate and delete addresses while the adapter is inactive, retain per-row errors, re-enumerate to prove the target LUID has no addresses, then start the session and add the new addresses. On teardown, remove the guard only after the same verification succeeds; fail closed on either enumeration failure. |
| WIN-014 | P1 | IMS/RTP | When a media-route release fails, the endpoint previously discards the only ownership record and `sync.Once` prevents a later `Close` from retrying. Re-INVITE rollback can similarly lose a newly acquired reference. | Track every acquired route reference until its release succeeds, retain failed references across `Close` calls, and return cleanup errors to callers. |
| WIN-015 | P1 | IMS/RTP | Symmetric-RTP port learning changed the outbound destination port without re-validating it against the negotiated responder traffic selector. A narrow selector can then be bypassed and Linux can fall through to its physical default route. | Validate a complete RTP packet first, authorize the learned port through the media-route manager, preserve lock order, and change the endpoint only after the new authorization is acquired and the old reference is safely retired. |
| WIN-016 | P1 | PC/SC | Native cancellation is retried only eight times. If the cancellation watcher runs before the blocking WinSCard call actually enters the resource manager and the goroutine is delayed beyond that retry window, the call can begin after cancellation has stopped and freeze indefinitely. | Once context cancellation wins the outcome race, keep issuing cancellation at a bounded rate until the native call returns; never let cancellation callbacks outlive the helper. Add a deterministic pre-entry scheduling-gap test. |
| LNX-001 | P1 | IKE/XFRM | Narrow XFRM policy commands append `proto`, `sport`, and `dport` after `dir`; iproute2 requires those selector fields before `dir`, so a negotiated protocol or port selector makes CHILD_SA installation fail. Teardown also omits those selector fields and cannot precisely delete a narrow policy, while duplicate/equivalent selector pairs are installed twice and fail with `EEXIST`. | Build and deduplicate the complete selector before appending `dir` and the template, retain the exact selector used for every installed policy, and delete that exact policy during rollback/close. Cover IPv4/IPv6, duplicate selectors, wildcard protocol, and exact UDP ports with command tests and a user-namespace integration test. |
| LNX-002 | P1 | IKE/XFRM | Kernel XFRM permits packets that do not match an outbound protect policy to continue through ordinary routing. After the inner address is assigned to the dummy interface, traffic outside negotiated selectors can therefore escape through a physical default route in cleartext. | Install a lower-precedence catch-all outbound `action block` policy for every assigned inner address before exposing the interface, while keeping negotiated protect policies at higher precedence; record and remove each guard exactly and fail installation if it cannot be installed. |
| WIN-017 | P1 | IMS/RTP | RTP receive validates against an endpoint/codec snapshot, but symmetric-port authorization rechecks only the current IP. A same-IP re-INVITE can therefore complete between those operations and let a packet from the old payload generation overwrite the new remote port. Packets with invalid RTP padding can also reach port learning. | Carry the expected negotiated endpoint and codec/payload state into authorization, revalidate all of it under `routeMu`, validate CSRC/extension/padding and require non-empty media payload before learning, then mutate only the still-current endpoint. Add concurrent re-INVITE and malformed-padding tests. |
| WIN-018 | P1 | IKE/Wintun | VoWiFi starts through the Wintun Go wrapper without enforcing the DLL trust checks performed by `doctor`. An elevated process launched from a user-writable directory can therefore load an untrusted application-local `wintun.dll`. | Before the first Wintun API call, lock the selected DLL against replacement, validate its architecture, Authenticode trust and required exports, load that exact file by absolute canonical path with System32-only dependency search, verify the loaded module identity, and retain the module for the process lifetime. Share this validation implementation with `doctor`. |
| WIN-019 | P2 | IKE/Wintun | The legacy Go wrapper models the `void WintunCloseAdapter` export as a Boolean-returning function. Its synthetic error is derived from an undefined return register and stale last-error state; retaining the adapter owner after such an error permits a second close of an already-freed opaque handle. | Treat a completed wrapper call as ownership transfer regardless of its reported return value, clear the owner exactly once, and test a nonzero synthetic `syscall.Errno` result. |
| WIN-020 | P2 | IKE/WFP | Several unpublished-owner installation failures discard cleanup errors after one attempt. A transient address, route, cancellation-event, adapter, or source-guard cleanup failure can therefore strand machine-wide state with no handle available for retry. | Route every post-allocation failure through a bounded rollback helper, preserve both the installation and cleanup errors, make `void` adapter close terminal for local ownership, and cover transient recovery plus the strict retry bound. |
| WIN-021 | P2 | IMS/WFP | Partial Windows IMS IPsec installation rollback closes its dynamic WFP owner only once and then discards it. A transient engine-close failure can strand filters or security associations. | Reuse the bounded abandoned-owner cleanup helper, join rollback failure with the triggering install error, and test both transient recovery and persistent bounded failure. |
| WIN-022 | P2 | IMS/RTP | A failed RTP route release can survive the first `Close`, but INVITE write failure and terminal-call retention still delete the call that owns the retryable media object. The final route owner is then lost. | Retry cleanup before abandoning an unpublished call, retain a cleanup-only call owner after persistent failure, and never evict an expired call until its media cleanup succeeds. |
| LNX-003 | P1 | IKE/cleanup | Linux XFRM and userspace handles mark teardown complete or discard recorded cleanup commands after the first deletion failure. Installation rollback has the same problem because a nil handle is returned to the caller. | Separate runtime shutdown from network-clean completion, pop only confirmed-success/confirmed-absent operations, retain exact reverse-order cleanup state across `Close` calls, and use bounded independent retries before abandoning an unpublished install owner. |
| IMS-001 | P1 | IMS/IPsec | IMS establishment failure, protected-transport dial failure, and the Linux IPsec handle each lose cleanup ownership after a single failed `Close`; a retry can also falsely succeed because the Linux handle is already marked closed. | Make platform cleanup resumable, normalize confirmed-absent XFRM objects under a stable locale, and give unpublished IPsec owners bounded independent cleanup attempts while joining any persistent failure to the setup error. |
| IKE-001 | P2 | IKE/relay | `CloseWithDelete` consumes the relay and closes its transport even when the protocol DELETE send fails, but `Session.Close` retains that already-consumed relay and repeatedly sends through a closed transport on later cleanup attempts. | Report DELETE and local-close errors once, always clear the canceled/joined relay owner, and retain only a transport whose own `Close` did not confirm completion for a later direct retry. |
| INS-001 | P1 | Installer | `bootstrap-admin` runs against the live SQLite database before the old service is stopped and before payload rollback is armed. A later installation failure can restore an older executable after the candidate has migrated the schema. | Stop the service before candidate database access, back up the database and its WAL/SHM sidecars, arm rollback first, and restore the database together with the executable/payload when validation or startup fails. |
| REL-001 | P1 | Updater | Archive and `SHA256SUMS` downloads have no enforced transfer limit. The archive size is checked only after it is on disk, while the checksum response is accumulated in memory. | Reject implausible asset metadata and enforce independent streaming byte limits for archives and checksum manifests; test missing, understated, oversized, and exact-boundary responses. |
| REL-002 | P1 | Release | Every `v*` tag can publish Docker `latest`, while GitHub releases are not marked prerelease. Release candidates can therefore enter stable update channels; build metadata is also not a legal Docker tag as-is. | Parse and validate the release tag as SemVer, mark prerelease GitHub releases explicitly, publish `latest` only for stable versions, and reject or deliberately map build metadata for container tags. |
| INS-002 | P2 | Installer | A single `systemctl is-active` check immediately after restart commits the payload transaction. A candidate that starts briefly and then crashes loses its rollback backup. | Require a bounded consecutive-stability window before committing installation, matching the OpenWrt path's behavior, and roll back on any failed observation. |
| INS-003 | P2 | Installer | The shell installer caps the release archive but not the downloaded `SHA256SUMS` file. | Apply a small curl size limit and verify the resulting file size before parsing it. |
| UPD-001 | P2 | Updater | `--force` treats both equal and older releases as installable, so its documented same-version reinstall behavior also permits an implicit downgrade and reports an older version as an available update. | Keep `--force` for equal-version reinstall only; reject downgrades unless a separate, explicit downgrade option is introduced. |
| INS-004 | P1 | Installer | Older curl versions do not enforce `--max-filesize` during streaming, and a highly compressed archive can make the preliminary tar member listing grow without bound before the member-count check runs. | Enforce archive and checksum limits in the consumer with `max+1` bytes, validate producer and consumer status before publishing the temporary file, and abort the first tar scan immediately at the 1,025th member. |
| INS-005 | P2 | Installer | Payload rollback does not cover the generated service environment/configuration and `/usr/local/bin/vocat` command link, so a failed candidate can leave runtime state referring to the rejected installation. | Include runtime configuration and the command link in the same transaction as the database, binary, archive, and notices, restoring each exact prior state on failure. |
| INS-006 | P2 | Installer | Two root installers can interleave shared `.bak` files, database migration, service restart, and the stability window because the live-install transaction has no machine-wide mutex. | Acquire a root-owned machine lock after download verification and before stopping the service, hold it through commit or rollback, fail closed on a retained lock, and release only a lock owned by the current process. |
| UPD-002 | P2 | Updater/installer | A checksum-valid archive can contain an older or otherwise mismatched VoCat binary because validation checks only that `vocat version` runs, not that its version equals the selected release tag. | Parse one strict `vocat <SemVer> [(build time)]` line and require an exact match with the already validated target version before replacement or database migration. |
| REL-003 | P2 | GitHub Release | A release rerun deletes every `vocat-*` asset and `SHA256SUMS` before uploading replacements, temporarily destroying a working release and also deleting manually attached signatures or SBOMs. | Manage only an explicit asset set, preserve the previous set for rollback, replace archives before committing `SHA256SUMS`, retain manual assets, keep new releases draft until the asset transaction succeeds, and reconcile release flags only after commit. |
| REL-004 | P2 | Container release | Any stable tag can publish `latest`, so rebuilding an older stable tag after a newer image exists silently moves GHCR `latest` backwards. | Push the immutable version tag first, query the complete GHCR tag set, fail closed if the target is not visible or the query fails, and promote `latest` only when no greater stable SemVer exists. |
| REL-005 | P2 | GitHub Release | Rerunning a stable tag does not clear an existing prerelease flag, so a stable build can remain excluded from GitHub's latest-release channel. | Reconcile `draft` and `prerelease` in both directions after the asset transaction commits; release candidates must remain prereleases and stable tags must explicitly clear the flag. |
| WEB-001 | P2 | Web dependencies | The locked development dependency `nanoid@3.3.17` is affected by GHSA-2v37-7h3g-55p8, allowing a zero-size custom generator to loop indefinitely. | Refresh the compatible transitive lock entry to patched `nanoid@3.3.18` and require a clean `npm audit` result together with the existing test/build checks. |
| DOC-001 | P3 | Documentation | Six localized release tables omit the Windows ZIP assets they claim are published, and the Simplified Chinese installer table omits supported Linux `aarch64`. | Bring all localized artifact and architecture tables into agreement with the release matrices. |

## Implementation constraints

- Dynamic media routes may only target addresses admitted by the negotiated
  responder traffic selectors. An SDP body must not become an unrestricted
  route-creation primitive.
- Traffic sourced from an assigned inner address must never fall through to a
  physical default route when no authorized tunnel route exists.
- PC/SC cancellation must not race a successfully acquired transaction and
  cancel subsequent card work.
- Machine-wide synchronization must work across interactive users and Windows
  service identities without granting unrelated users control of the mutex.
- Update checks must remain useful on Windows even though in-place executable
  replacement remains unsupported.
- Release license packaging applies to every binary platform, not only Windows,
  because Go dependency code is compiled into the executable.
- Cleanup safety must be established from observed final state, not merely a
  successful wrapper return value when the underlying API can discard errors.
- Installer rollback covers persistent data migrations as well as binaries and
  notices; an older binary must never be restarted on a database migrated only
  by a rejected candidate.
- Prerelease artifacts must remain outside every stable discovery channel,
  including GitHub `latest`, container `latest`, and the built-in updater.

## Acceptance criteria

- Windows unit tests cover even SPI allocation, WFP IPv6 representation,
  deterministic adapter GUIDs, transient Wintun ring pressure, PC/SC buffer
  resize retry, DLL export validation, and platform release-asset checks.
- Media route tests cover add/remove idempotency, traffic-selector rejection,
  retryable cleanup, symmetric-port authorization, and fail-closed behavior.
- Windows address-lifecycle tests inject delete and re-enumeration failures and
  prove that stale addresses are cleared before `StartSession` and that the WFP
  guard remains installed until cleanup is observed.
- Update tests enforce archive and checksum transfer limits and reject
  downgrades; release workflow checks distinguish stable SemVer tags from
  prereleases.
- Installer tests cover database migration rollback, delayed service failure,
  and oversized checksum manifests.
- `go test ./...`, `go vet ./...`, the web test/build pipeline, and supported
  cross-compilation targets pass, apart from failures independently reproduced
  on the upstream baseline and explicitly documented in the delivery report.
- `git diff --check` passes and both the VoCat worktree and its superproject
  retain only the intentional source and gitlink state.

## Status

Implementation and repository-level verification are complete as of
2026-08-27. Every finding recorded above has a corresponding source, test,
workflow, installer, or documentation remediation. The remediation set is
organized as local commits on branch `codex/win11-native`; it remains unpushed,
and the Server superproject gitlink is intentionally unchanged.

### Remediation summary

- Windows now uses valid WFP SPI/address ABI representations, a real outbound
  interface source guard, verified stale-address removal, deterministic Wintun
  identity, nonfatal ring backpressure, continuous PC/SC cancellation, and a
  machine-wide instance mutex.
- Runtime and `doctor` share a locked-file Wintun validator. It checks PE
  architecture, Authenticode trust, required exports, canonical loaded-module
  identity, and the exact basename lookup used by the legacy wrapper before any
  Wintun API call. The module remains referenced for the process lifetime.
- IKE and IMS cleanup is ownership-aware: exact XFRM/WFP/routes are retained
  until successful or confirmed absent, runtime `Close` can resume, unpublished
  owners receive bounded independent rollback attempts, and a consumed relay or
  Wintun adapter is never called twice. Cleanup failures are joined to the
  triggering error instead of being discarded.
- Media routes are admitted only by negotiated traffic selectors. Symmetric RTP
  learning revalidates the complete negotiation generation after structural RTP
  validation, and failed route releases remain owned across re-INVITE, call
  termination, and session shutdown.
- The updater and installer enforce streaming archive/checksum limits, safe
  archive manifests, exact candidate-version binding, transactional binary and
  archive replacement, downgrade refusal, database/WAL/SHM rollback, runtime
  configuration/link rollback, service stability windows, and a machine-wide
  install lock.
- Release automation uses strict SemVer, isolates prereleases, packages license
  notices, replaces an explicit managed asset set with rollback and checksum-last
  commit semantics, and promotes GHCR `latest` only monotonically. The Web lock
  file now resolves the patched `nanoid@3.3.18` dependency.

### Verification evidence

The final working tree, including the last IKE relay and dependency-lock changes,
was checked as follows:

```text
Windows amd64: go test -count=1 ./...                         PASS
Windows amd64: go vet ./...                                   PASS
Windows arm64: go build ./...                                 PASS
Linux amd64:   CGO_ENABLED=0 go build ./...                   PASS
Linux 386:     CGO_ENABLED=0 go build ./...                   PASS
Linux arm64:   CGO_ENABLED=0 go build ./...                   PASS
Linux armv7:   CGO_ENABLED=0 GOARM=7 go build ./...           PASS
WSL Linux:     go vet ./...                                   PASS
Web:           npm ci; npm audit; npm test; npm run build     PASS
Installer:     bash -n scripts/install.sh                     PASS
Release:       all .github/scripts/*_test.sh                  PASS
Workflows:     PyYAML parse docker/release/windows.yml        PASS
Repository:    git diff --check                               PASS
```

Web tests passed 8/8 and `npm audit` reported zero vulnerabilities. The Vite
production build emitted only its existing large-chunk warning.

One-off fault-injection fixtures also passed for database/WAL/SHM restoration,
delayed service failure, runtime configuration and command-link rollback,
missing/understated/exact/oversized/partial-error downloads, 4,096- and
100,000-member compressed archives, and a real release archive plus checksum
manifest. Root-isolated Linux network-namespace checks installed real narrow
XFRM policies and inner-source block policies, removed them exactly, and
exercised the Linux userspace tunnel lifecycle.

`go test -count=1 ./...` under WSL has one failure:
`internal/vowifi/ims.TestProviderRequiresSecurityServerBeforeAKA` times out on
its UDP REGISTER fixture. The same failure was independently reproduced from
the unmodified `upstream/master` baseline; all other Linux packages pass.

### Remaining environment validation

The following checks require release infrastructure or physical/runtime
environments and were not performed here:

- real Windows WFP/Wintun data-plane traffic with an official DLL, installed
  driver, ARM64 host, and PC/SC hardware;
- an actual GitHub Release/GHCR push, interrupted upload, rollback, and `latest`
  promotion against the remote services;
- destructive power-loss and real systemd/OpenWrt service-failure injection;
  and
- Go race-detector execution, because the available toolchains have CGO
  disabled.

An unpublished install whose platform cleanup still fails after all bounded
attempts returns a joined hard error and may require operator cleanup before a
retry. No path reports successful establishment or fallback while such cleanup
is known to be incomplete.
