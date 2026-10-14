# M6d2a SQL file custody and peer fixture — 13 October 2026

[RFC 0028](../../../docs/rfcs/0028-postgres-custody.md) and the
[operator guide](../../../docs/POSTGRES_CUSTODY.md) supply explicit SQL-target
file loading from verified descriptor bytes plus actual PostgreSQL peer tests.
Based on `b3aceb8` and the tested working tree. Frozen records/fixtures/paper and
SQL migration are unchanged; earlier evidence remains byte-identical.
Rustix 1.1.5 was already pinned transitively. It is now directly declared with
fs/process features; Cargo.lock adds that dependency edge only, without changing
any package version/checksum.

## Reproduction

Darwin ARM64; Rust/Cargo 1.98.0; Node 25.2.1; Python 3.13.12; PostgreSQL 18.3
with the M6a official source checksum; etcd 3.6.5 with three loopback source members
and same-host independent fixture witnesses. One kernel OS UID administers the
cluster and runs all services. No independently provisioned accounts, container
runtime, enterprise deployment or production secret is involved.

```sh
PATH=/absolute/path/to/rust/bin:$PATH
CARGO_HOME=/isolated/cargo/cache
CARGO_TARGET_DIR=/isolated/cargo/target
ETCD_BINARY=/absolute/path/to/etcd
KF_REQUIRE_SDK=1
export PATH CARGO_HOME CARGO_TARGET_DIR ETCD_BINARY KF_REQUIRE_SDK
python scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin --peer \
  --command scripts/start-etcd.sh -- \
  cargo test --locked --offline --workspace --all-targets -- --nocapture --test-threads=1
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
python scripts/verify-whitepaper.py
python spec/validate.py
ruff check .
mypy src
pytest -q
```

All SQL/etcd/SDK dependencies are required; Rust cases are serialized for host
capacity with explicit actor concurrency still inside other tests. The SQL CI job
now selects peer mode and includes filesystem custody cases. CI YAML/run scripts
parse locally; remote Linux/GitHub/minimum toolchains remain unobserved.

## Final-source observations

[Combined log](tests.log): **269 Rust tests across 40 test binaries**, zero
failures/ignored/skipped. Five new filesystem groups and one shipping custody
case join the nine existing SQL target/enrollment cases and all eleven M6c failure
cases. [SQL/peer groups](postgres.json): **15 pass**, comprising eleven prior
storage groups and four peer groups. Clippy/format, Node vectors, frozen schema/
paper, Ruff/mypy and all 32 Python tests pass. [summary.json](summary.json) retains
source and evidence SHA-256 pins.

- Absolute protected root and every directory/file component are opened with
  verified descriptor-relative operations. UID/mode, single link, regular file,
  path containment, size and before/after metadata checks enforce the declared
  predicate. Symlink/escape/hard-link/FIFO and unsafe mode/size cases refuse.
- Retained root descriptors read the original tree after its pathname is replaced;
  newly opened roots select the replacement tree. No checked-path reopening is
  used to construct TLS or the target service.
- Native `--check-custody` verifies five files and local material without a listener
  or database. Missing root/conflicting flags/unsafe secret/config modes/symlink/
  root escape refuse before effect. Offline and active database modes stay distinct.
- Shipping protected startup retains its original token snapshot after the disk
  path is replaced by unsafe material; a new check refuses that replacement.
  Normal authorized commit and independent retained query succeed once. This
  demonstrates snapshot consumption, not automatic revocation/rotation.
- Actual kernel peer authentication allows exact target-role logins and refuses
  unmapped agent login. Anchored fixture-only maps allow randomized execution/
  query/mixed-case enrollment roles while denying an owner suffix.
- Wrong OS maps refuse both target logins; restoring the map preserves retained
  SQL outcomes. Parsed HBA/ident rules have no errors or trust method, TCP is
  disabled and the socket mode is 0700. All runtime SQL cases run under these maps.

## Preliminary fixture corrections

[Initial file compilation](preliminary-fifo-api.log) used rustix mkfifoat, which
is unavailable on this Darwin target. The test now uses the system mkfifo utility;
production loading remains safe rustix descriptor operations.
[Initial mode cases](preliminary-modes.log) expected non-executable set-ID modes to
be observable. [Kernel observation](setid.log) shows Darwin strips those requested
bits; corrected cases retain unsafe executable permissions and refuse. Isolated
set-ID-only behavior is not qualified on this host.

[The initial native peer run](preliminary-native.log) exposed a fixture regex with
a closing slash, although PostgreSQL treats only a leading slash as its marker.
The corrected anchored fixture regex adds explicit permitted/denied suffix probes.
The missing-outcome readiness check also now observes authenticated HTTP 404;
absence is not successful commit evidence. [Final native check](native.log) passes
ten cases before the complete required regression. No source guard, conservation
assertion or frozen contract was weakened.

## Limits and next work

This is a POSIX UID/mode and descriptor snapshot, not an OS security proof. Extended
ACLs, mounts/namespaces, privileged processes, same-UID interference, memory dumps,
remote filesystems, owner writes and cross-file generation atomicity remain
unqualified. The file loader does not inspect pg_hba, socket ownership or the
actual database server identity. Kernel peer maps are tested in a disposable
fixture with one UID; an agent running under that UID could request mapped target
or owner roles. Unmapped database-name refusal does not establish agent isolation.

Other service loaders remain unchanged. Custody root omission selects the existing
legacy loader and makes no custody claim. A protected launcher must enforce the
profile; downgrade prevention, independent service accounts, deployed descendant
socket/file/shell/SDK bypasses and key/token/configuration rotation remain M6d2b.
Physical/stale restore, retention, budgets, approved providers, routing and real
owner acceptance remain M6d3/M5c gates. This record closes only M6d2a mechanics.

Logs normalize local/disposable paths and trim terminal whitespace. Earlier
records and frozen artifacts remain unchanged.
