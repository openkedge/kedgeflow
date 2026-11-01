# Linux core package and protected preflight

Status: **passed bounded Linux core package checks**, observed 1 November 2026.
This is an alpha core runtime artifact, not production acceptance.

The four actual ARM64 release executables were compiled from the archived inputs
using digest-pinned Rust 1.98.0 on Debian bookworm. The completed build exited zero
without OOM; its container was removed. A separate Ubuntu/systemd 255 VM ran the
shipping binaries under staged, distinct kernel UIDs. No host accounts or systemd
services were installed. All temporary roots and generated credentials were
removed, and both fixture VMs were stopped. Labeled compiler caches remain in the
dedicated stopped build VM for continued implementation.

The local ignored bundle is
`kedgeflow-core-0.9.0-alpha.1-linux-aarch64-27c2414bfd3a9183.tar.gz`.
Its SHA-256 is
`b6c4e464b7090fb21dfb3258ef6f38c8cdd753e89e32a69bd4b7cfe4c56da0eb`.
The 27,445,355-byte archive remains a local build output; Git retains its full
manifest and hash rather than binary payloads. The workflow now assembles and
uploads equivalent core artifacts, but no AMD64 GitHub run is claimed here.

## Observations

| Check | Observed result |
| --- | --- |
| Actual core package | All 16 manifest/payload files verified; hashes of four binaries match the native preflight binaries; architecture and content identity match |
| Linux native preflight | 44 cases: four own-role successes; other role/agent, group-readable/symlink key and applicable unmanaged/zero-peer cases refuse |
| Linux file boundaries | 56 actual open probes: seven own-role successes, 42 cross-role denials and seven agent denials |
| Account/unit assets | Seven staged non-login UIDs; sysusers rerun preserves account data; tmpfiles produces exact directory owners/modes; all five units parse without warnings |
| Darwin native regressions | 75 Rust cases: 24 core launch/broker/config, 19 authentication, 31 control and one protected SQL target commit/query case |
| PostgreSQL peer prerequisite | 23 same-host SQL groups; protected shipping commit/query remains intact |
| Python regressions | 69 tests, including archive corruption, traversal, links, modes, mixed architecture, immutable replacement/content identity and fixture opt-in refusal |
| Quality/contracts | Workspace/all-target clippy with pilot feature and warnings denied; format, ruff and mypy pass; 58 frozen files and 24 contract pins unchanged |

Managed unit entry points require protected material, managed controls, shared
proof consumption, witness, signed identity refresh and acknowledgement as
applicable. The SQL target requires a non-root peer UID. The shared server handles
SIGTERM through its existing bounded connection drain; the shipping broker test
observes a normal successful SIGTERM exit, with original consumption preserved.
Archive tests observe deterministic bytes for the same inputs/toolchain/epoch
and a distinct immutable directory identity after payload changes.

## Scope and reproduction

The staged account database is private to the fixture. Numeric UIDs are exercised
by Linux with supplementary groups and capabilities removed; this does not prove
installed NSS accounts or systemd namespace/seccomp restrictions. Native processes
run `--check` only. Their generated PKI, identity publication and dummy ledger
bearers/actor source establish local material validation, not provider issuance,
live authority, SQL peer authentication or a fresh end-to-end action. In particular,
the installed target's additional `--check-database` was not exercised on Linux
by these preflights. Darwin SQL evidence is separately labeled in its log.

Build and verify on Linux, then run the explicitly disposable root fixture:

```sh
SOURCE_DATE_EPOCH=1793491200 python3 scripts/package-linux.py --output dist/linux
for bundle in dist/linux/*.tar.gz; do
  python3 scripts/verify-linux-package.py "$bundle"
done
sudo python3 scripts/qualify-linux-package.py --ephemeral-host \
  --binary-dir /absolute/path/to/target/release > linux-preflight.json
```

The source archive and [build log](build.log) bind the actual local binaries;
`--binary-dir` alone does not authenticate arbitrary prebuilt executables.
`build-source.json`/archive retain all 381 build inputs. `package-source.json` and
its archive retain packaging/fixture/CI/docs inputs. `linux-preflight.json` binds
fixture source and tested binary hashes. The three native test logs retain their
commands' observed results; Python/clippy logs and `summary.json` record the other
checks. Tool setup for SQL/etcd remains in the repository scripts.

The original shared build attempt was stopped before exhausting that VM's small
disk. Its newly created container/cache volumes were removed, with existing
cluster images/disks preserved. The successful build used a separate VM without host filesystem sharing and
a resource-bounded container with only owned compiler-cache volume mounts. This record does not claim actual installed unit
start/stop/upgrade, sandbox/egress bypass, production storage recovery, service CA
rollout, operational budgets, complete role packaging, independent reproduction
or owner acceptance. Those [production gates](../../../docs/PRODUCTION_READINESS.md)
remain open. Root README and prior verification records are unchanged.
