# Protected Linux ledger credential publisher

This record qualifies the optional etcd token issuer and local installer under
systemd. It is bounded component evidence, not production acceptance or a full
managed workflow.

The rebuilt ARM64 v3 bundle is
`kedgeflow-core-0.9.0-alpha.1-linux-aarch64-66491da656613067.tar.gz`, SHA-256
`39b6c821805e073d8d8eed3ca3e6caac4bd17c1af106649adb59886385371d86`.
All ten executable hashes match `build.json` and `bundle-manifest.json`.
The publisher hash is
`27cf8be5a0338623d059294eab87be4ae2ff101760b521cfc18d9e3cabc18edd`.
The verifier retains v1/v2 compatibility and the bundle still explicitly records
`production_qualified=false`.

## Observed behavior

`qualification.json` records two independently audited principals, READ and
READWRITE, in one batch against an isolated real etcd 3.6.5 TLS node using signed
ES256 JWTs. READ permits a range query and refuses a write. Namespace escape
refuses. The publisher's password cannot authenticate root, and its UID cannot
read the fixture's JWT signing key. The administrative password is separate and
never supplied to the publisher.

The shipping unit templates run the issuer as its separate non-root account
without capabilities, and the installer as root with only `CAP_CHOWN`. Fixture
overrides select protected temporary paths and commands while retaining the
sandbox. Actual probes observe seccomp, no-new-privileges and the expected
capabilities; the installer cannot create an Internet socket. Three distinct
accounts represent issuer, service consumer and agent. The service reads its own
token while the issuer and agent cannot; service/agent password access refuses.

An issued token expires at the real server; a second systemd issue/install
replaces it with a working token. Wrong credentials or an extra etcd permission
prevent issuance and sink activation, preserving existing destination bytes.
Direct stale-batch and symlink-target publication refuse without changing the
protected mapping. Unit journals contain no tested passwords or issued tokens.
The batch is validated completely before preparation, but several destination
renames are not a multi-file transaction. Existing tokens are not revoked merely
because renewal fails.

`core-preflight.json` additionally records 108 protected native configuration
checks for the nine existing core/operational executables and 72 kernel-UID
file-access cases using their rebuilt binaries. Those processes do not start live
core services or contact a database. The optional management units are tested
separately by the publisher qualification, not counted as core preflights.

## Validation and provenance

`build.json`, `build-source.*` and `build.log` retain the successful locked,
offline Rust 1.98.0 ARM64 release build with one Cargo job in the pinned builder
image. All 398 captured inputs remain unchanged during that build. The prior
two-job final attempt exhausted its 4 GiB container while linking `kf-proxy`;
`parallel-build-failure.*` retain that failure. The successful serial build uses
the identical captured source and existing dependency cache; its container exits
zero and is removed.

`source.*` capture the implementation, packaging, documentation, qualification and
regression inputs. `run-qualification.py` and `core-preflight.py` retain the actual
VM adapters. Qualification source hashes remain unchanged during each run, and
the tested publisher matches the final bundle. No live private material is
archived. The disposable VM is restored to stopped state after cleanup.

The native real-TLS/authenticated-etcd tests cover root-role aliases, extra
permissions, failed second principals, safe staging, malformed configuration,
read-only protobuf defaults, normalized HTTPS origins and secret-free CLI errors.
All three pass. The focused Python suite passes 63 tests, including legacy bundle
compatibility. All-target Clippy with pilot features, formatting, lint and frozen
paper/contract checks pass. CI defines the new Linux qualification; no GitHub
Actions execution is claimed.

## Remaining boundaries

See [deployment instructions](../../../docs/LEDGER_CREDENTIALS.md). Role checks
are issuance-time observations and do not lock subsequent administrator changes.
The namespace example does not establish least privilege between interleaved
service keys. The local installer remains a trusted root administrative component.
The fixture uses generated PKI, one controller-administered etcd node and direct
consumer requests; it does not qualify every long-running daemon's renewal in the
complete provider workflow. Timer scheduling, service CA rotation, independent
storage/administration, full network bypass controls, physical recovery,
upgrades, capacity and owner acceptance remain in the production worklist.
