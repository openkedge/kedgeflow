# Linux readiness package qualification — 2026-11-01

This record binds an actual ARM64 Linux release containing protected operational
services, live primary/witness token sources and monitored readiness to bounded
native and installed-systemd observations. It does not establish production
readiness or a full live Linux authority/SQL deployment.

## Artifact and checks

| Check | Observation |
| --- | --- |
| Release build | Nine executables; Rust/Cargo 1.98.0, pinned Debian-based image, locked offline Cargo build; exit 0 and no OOM |
| Bundle | `kedgeflow-core-0.9.0-alpha.1-linux-aarch64-22c3fbfe206bc010.tar.gz`, 59,155,860 bytes |
| SHA-256 | `59dac3a300e0c1ece9294b9f8bc128a005bcbaf0c98c2c3e73a73489706c15f5` |
| Native monitored preflight | 108 cases across nine commands and eight staged role UIDs |
| Kernel file-access probes | 72 own/cross-role/agent cases |
| Actual installed systemd | 61 observations on systemd 255, eight service accounts plus one disposable agent account |
| Python checks | 70 tests passed; the 20 package tests additionally passed after final packaging |
| Static/frozen checks | Ruff, mypy (22 files), diff whitespace and frozen whitepaper verification passed (58 files, 24 pins unchanged) |

The v2 content-addressed bundle includes the service operations and custody
guides. The verifier still accepts the retained earlier v1 and v2 packages.
It explicitly reports `production_qualified=false`. The large executable archive
remains an ignored local build artifact; its manifest and hash are retained here.

## Installed observations

All nine local material preflights passed with the final generated configuration
under the appropriate non-root account before any startup failure was attributed
to unavailable prerequisites. This includes explicit monitor flags, protected
gateway monitor-client material and both worker monitor configurations.

Collector, governance, supervision, control and broker started, restarted and
stopped normally under their shipped accounts and hardening. Root-controlled
fixture drop-ins enabled monitor URLs without changing the restrictions; effective
unit contents are retained in command output. Their mTLS endpoints returned typed
unready/no-store observations before and after restart. The generated monitor
identity was accepted; a valid same-CA agent identity, running under the separate
agent UID with its own private material, received 403. Missing client certificates
also refused, including at the worker's separate listener.

Sandbox probes observed read-only system files, private temporary directories,
zero capabilities, no-new-privileges, seccomp and denied user-namespace creation.
Agent reads of all eight role configurations refused. Gateway and SQL-target
startup failed with unavailable prerequisites; SQL's incoming query endpoint was
preserved rather than accidentally rewritten as an outgoing dependency. Restore
status refused absent authority. Every outgoing authority destination was a
reserved closed loopback origin; no live authority or database workflow ran.

The fixture removed generated keys, users/groups, units and deployment paths,
with no cleanup errors. The completed task build container was removed, labeled
cache volumes retained, and the dedicated VM restored to its initial stopped
state. Earlier fixture resources and verification records were preserved.

## Retained inputs and reproduction

`build.json`, `build.log`, `build-script.py`, `build-source.json` and
`build-source.tar.gz` bind the pinned image, exact Cargo command, cache layout,
395 Rust/config/contract inputs and all nine executable hashes. Those hashes
match the binaries used by native qualification. `bundle-manifest.json` retains
the verified archive inventory. `native-preflight.json` and `systemd-smoke.json`
retain source bindings, native results, effective units and installed
observations for the exact bundle hash above. `package-source.json` and
`package-source.tar.gz` retain packaging, deployment and fixture inputs.
`backward-compatibility.json`, test/check logs and `summary.json` retain remaining
results. `artifacts.sha256.json` binds every record artifact except itself.

Rebuild and verify in Linux, then use the explicitly opted-in staged and installed
commands in [LINUX_DEPLOYMENT.md](../../../docs/LINUX_DEPLOYMENT.md). The installed
fixture requires an otherwise empty disposable systemd host and refuses existing
project paths/users/groups/units. Its generated credentials use software fixture
identity, not a production provider. Early container cache-layout and fixture
URL mistakes, plus a sandbox-denied Python test attempt, are excluded from passing
evidence. The final runs above use the corrected inputs and required permissions.

The same Rust source's 193 native macOS cases and 23 peer-authenticated SQL groups
are retained in the [role readiness record](../service-readiness-roles-2026-11-01/README.md);
they are not attributed to Linux here.

## Open gates

Live Linux authority-to-SDK-to-broker-to-SQL and recovery, actual provider-issued
monitor enrollment, deployed ledger renewal and PKI rotation, complete bypass and
egress, independent custody, metrics/alerts and workload SLOs, physical restore,
upgrades, AMD64/release CI/MSRV 1.88, independent reproduction and owner acceptance
remain open in [PRODUCTION_READINESS.md](../../../docs/PRODUCTION_READINESS.md).
