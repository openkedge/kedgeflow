# M6b1 native PostgreSQL target — 12 October 2026

[RFC 0024](../../../docs/rfcs/0024-postgres-target-http.md) and the
[target guide](../../../docs/POSTGRES_TARGET_SERVICE.md) define this bounded
service/driver/client increment. Based on `6dcbe9a` and the tested working tree.
Frozen wire records, fixtures, RFC 0023 SQL storage and previous evidence are unchanged.

## Reproduction

Darwin ARM64; Rust 1.98.0; Node 25.2.1; etcd 3.6.5 (three loopback members);
Python 3.13.12; PostgreSQL 18.3 from the same official checksum as M6a. The disposable
SQL launcher disables TCP and uses explicitly synthetic local trust/login roles.
Generated software workload certificates and preissued grants/permits are fixtures.

```sh
PATH=/absolute/path/to/rust/bin:$PATH
CARGO_HOME=/isolated/cargo/cache
CARGO_TARGET_DIR=/isolated/cargo/target
ETCD_BINARY=/absolute/path/to/etcd
KF_REQUIRE_SDK=1
export PATH CARGO_HOME CARGO_TARGET_DIR ETCD_BINARY KF_REQUIRE_SDK
python scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin \
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

The SQL launcher also runs its eleven storage groups, requires the exact 18.3
binaries, enables fixture function-only login roles for the Rust tests and exports
`KF_REQUIRE_POSTGRES=1`. The inner launcher requires etcd; SDK is also required.
All test services/databases are disposable. Rust cases are serialized; explicit
concurrent actors still race within tests. The existing isolated Cargo/SQL prefixes
were used; declared Rust 1.88 and Node 20 remain unqualified.

## Observations

[The combined log](tests.log) records **243 passed**, zero failures/ignored/skipped
across 39 Rust binaries, including six native SQL cases. [SQL groups](postgres.json)
record eleven passing PostgreSQL storage groups. Clippy, format, frozen-paper/schema,
Node vectors, Ruff/mypy and all 32 Python tests passed. New CI YAML/shell parses;
Linux/GitHub SQL job execution is not observed in this record.

Native cases verify:

- Fixed client dispatch over real verified mTLS, actual parameterized PostgreSQL
  transaction/COMMIT acknowledgement, eight concurrent original-request replays,
  and query under a separately authenticated role without another effect.
- Changed live database version retains correlated guard rejection, leaves its
  reservation unchanged and reports `fenced_no_effect` under query-only carriage.
- Wrong query/agent workload and forged identity header, missing client certificate,
  invalid or actually signed wrong issuer/audience/scope/root/gateway/expiry token,
  substituted parameters/attempt, extra SQL field and browser Origin all refuse
  without changing the row or allocating a SQL attempt.
- Client disconnection after actual database commit leaves the owned task and
  retained commit available to independent query, with one version transition.
- An accidentally configured owner/superuser database execution role refuses before
  effect. Fixed execution/query roles have no direct mutation/schema/opposite-function
  privileges. These are local role checks, not enterprise enrollment/bypass proof.
- Actual `kf-postgres-target --check` succeeds against unreachable SQL with valid
  local material. Shipping service then commits, is killed/reaped and restarted;
  query and exact replay reuse the original commit with no additional transition.

Original locked dependency versions/checksums are preserved; 26 new driver dependency
pins were added. The retained cpufeatures archive was checksum-verified after restoring
its existing version, rather than accepting the offline resolver's downgrade.

Verification repairs: generated permit IDs now use the existing digest shape, and
nested command separators are preserved by the disposable launcher. No failing
intermediate run is labelled passing. M6a's fixed SQL migration/schema were unchanged.

## Limits and next increment

The active gateway/control services and Node client still use the mock action.
M6b2 must integrate explicit CTD-driven SQL parameter mapping and demonstrate fresh
admission, issuance, original claim, actual broker mint, SQL dispatch and retained
M4 recovery in one path. Native tests use generated preissued grants and synthetic
permits; independent broker tests do not qualify that composition transitively.

Only a protected local Unix database is supported; no remote PostgreSQL TLS/password
mode is supplied. Local trust fixtures do not qualify protected peer maps/socket
custody or deployed SQL roles. Static target/query pins require protected restart;
rotation/revocation delivery and retained historical incarnation enrollment remain
operator acceptance work. SQL functions/schema owner, database clock and writer/fence
coverage remain trusted. M4 query recovery keeps absence and possible-send guard
observations conservative; no refund or redispatch is introduced.

Target service process SIGKILL/restart does not qualify PostgreSQL power/storage
loss, stale target backups or physical failure domains. Real providers, managed
control/witness composition, full bypass/writer/retention/restore qualification,
operational budgets and owner acceptance remain open. Full M6 and M5 enterprise
acceptance gates remain unchanged.
