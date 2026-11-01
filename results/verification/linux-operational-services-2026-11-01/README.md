# Linux operational services qualification — 2026-11-01

This record qualifies a bounded operational-services increment. It does not
establish production readiness. The release worklist remains in
[PRODUCTION_READINESS.md](../../../docs/PRODUCTION_READINESS.md).

## Changes exercised

The Linux bundle contains nine executables and eight service accounts. Recovery,
supervision, receipt collection, governance and restore use protected config and
material reads with managed preflight. Governance loads public registration
without admission or issuer signing seeds. Restore status is a manual oneshot;
installation never automatically enrolls empty authority.

Managed supervision reloads the receipt-delivery token and DPoP proof key for each
request, without cached fallback. Expiry, mismatched rotation, missing/unsafe
files and successful renewal are exercised against the original receipt.
SIGTERM permits the current recovery/supervision page to drain for at most 30
seconds; restart retains the original attempt and accepted acknowledgement.

## Observed results

| Check | Result |
| --- | --- |
| Actual Linux ARM64 release build | Nine executables; Rust 1.98.0, pinned Debian-based image; exit 0, no OOM |
| Bundle | v2, 57,828,923 bytes; SHA-256 `a2bbfa034a1517963b6011584ae89c4bc3928d0f7ff95ac786f1259c93d1dbaf` |
| Native protected preflight | 108 cases, plus 72 kernel file-access cases across eight isolated role UIDs |
| Installed systemd smoke | 36 observations on systemd 255; exact bundle above |
| Rust integration tests | 54 cases across the affected suites, including one exact governance case; no ignored cases |
| Python tests | 70 passed |
| Static checks | Cargo fmt, workspace/all-targets pilot-feature clippy with warnings denied, ruff and mypy passed |
| Frozen paper evidence | 58 files and 24 pins unchanged |

Five actual services (collector, governance, recovery, control and broker) started,
restarted and stopped normally under their shipped users and hardening. Test-only
post-start probes observed read-only system files, private temporary directories,
zero effective capabilities, no-new-privileges, seccomp and denied user-namespace
creation. Journal evidence is scoped to each systemd invocation. Agent access to
all eight role configurations was denied. Gateway and SQL-target startup refused
their unavailable prerequisites; restore status failed without authority.

Control and broker can listen before backend authority is available. The smoke
records that behavior explicitly: process activity and a listening socket are
not application readiness. All outgoing authority destinations in this smoke
were reserved, closed loopback sockets. It did not run a live authority or SQL
workflow. TLS certificate verification remained enabled.

The smoke removed its generated keys, test users, units and deployment paths;
its cleanup report has no errors. The completed build container was removed,
task-labeled build caches retained, and the disposable VM stopped. The old
fixture VM and prior verification records were preserved.

## Reproduction and retained artifacts

[summary.json](summary.json) gives counts and open gates.
[build.json](build.json), [build.log](build.log) and
[build-source.json](build-source.json) bind the release build to its source and
all nine binary hashes. [build-source.tar.gz](build-source.tar.gz) retains those
inputs. [package-source.json](package-source.json) and
[package-source.tar.gz](package-source.tar.gz) retain packaging, fixture, CI,
deployment and documentation inputs. [bundle-manifest.json](bundle-manifest.json)
retains the verified bundle manifest. The large executable archive remains a
local ignored build artifact, not a committed release publication.

[native-preflight.json](native-preflight.json) and
[systemd-smoke.json](systemd-smoke.json) retain the actual Linux observations and
source/binary bindings. Rust, Python and clippy logs are retained alongside them.
[artifacts.sha256.json](artifacts.sha256.json) binds every record artifact except
the hash manifest itself.

For a new isolated disposable Linux/systemd host, use the build, verification,
native preflight and explicitly opted-in installed smoke commands in
[LINUX_DEPLOYMENT.md](../../../docs/LINUX_DEPLOYMENT.md). The installed smoke
requires root and refuses existing project users, groups or installation paths.
Never run that disposable-host fixture against an existing deployment.

## Remaining limits

Application readiness and operational reporting, ledger authentication renewal,
service certificate/CA rotation, a full live Linux authority-to-SDK-to-SQL path,
deployed bypass/egress, independent custody, production provider storage,
physical restore, upgrades, workload SLOs and owner acceptance remain open.
The generated smoke credentials use legacy fixture identity; live provider
issuance for these new operational roles is not claimed. No AMD64, release CI,
MSRV 1.88 or independent reproduction run is attributed to this record. Earlier
fixture-debug failures are not counted as passing evidence.
