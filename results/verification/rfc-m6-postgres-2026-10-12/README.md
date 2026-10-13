# M6a PostgreSQL reservation storage — 12 October 2026

[RFC 0023](../../../docs/rfcs/0023-postgres-reservation.md) and the
[integration guide](../../../docs/POSTGRES_RESERVATION.md) define this target-storage
prerequisite. Based on `f9782fc` and the tested working tree. Frozen paper contracts,
fixtures and earlier retained evidence remain unchanged.

## Reproduction

Darwin ARM64; Rust 1.98.0; Node 25.2.1; etcd 3.6.5 with three loopback members;
Python 3.13.12; PostgreSQL 18.3 built from the official SHA-256-pinned source.
PostgreSQL configure used a temporary prefix with ICU/readline/zlib disabled.
No TCP listener; trust authentication and role enrollment are explicit local
fixtures, with fsync enabled and no existing target contacted.

```sh
python scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
python scripts/verify-whitepaper.py
python spec/validate.py
ruff check .
mypy src
pytest -q
```

Local Rust commands used the stable toolchain in PATH, the isolated Cargo cache
`<tmp>/kedgeflow-cargo` and target directory `<tmp>/kedgeflow-paper-target`.
Python validation used the existing project virtual environment and specification
dependencies. Required Rust test cases were serialized; explicit concurrency actors
remain active within tests. Declared minimum Rust 1.88 and Node 20 stay unqualified.

## Evidence and observations

- [Rust log](tests.log): 237 passed across 37 binaries; zero failures/ignored/skipped,
  including the existing native etcd/SDK and nine process-kill cases.
- [SQL cases](postgres.json): 11 groups passed on an actual disposable database.
  Version/effect/outcome changes commit together; concurrent original replay keeps
  one update; competing covered writers get one version transition. Altered
  attempts or reused root/grant bindings refuse. Expiry, version, incarnation,
  domain, fence and tombstone guards preserve the row. Rollback removes both effect
  and outcome. An in-flight transaction has an absent lookup then commits. A
  discarded reply resolves by query without another dispatch. Scoped executor,
  reader and agent role checks refuse inappropriate access. Clean database restart
  preserves the original receipt and deduplication.
- Four new Rust cases cover closed application/target records, authority-field
  injection, safe integers/byte bounds/duplicate fields and exact terminal binding.
- Clippy, format, Node vectors, frozen-paper/schema checks, Python Ruff/types and
  all 32 compatibility/freeze tests passed. CI YAML and new shell bodies parse;
  the new Linux source-build job has not been observed running on GitHub.

The SQL role checks use `SET ROLE` in an operator-owned fixture connection. They
are not enterprise credential enrollment or deployed agent bypass qualification.
The discarded reply uses an output sink, not an injected network partition. Restart
is clean `pg_ctl -m fast`, not abrupt process/power/storage failure. Separate witness
clusters, where exercised by existing tests, share this host.

Verification repairs: fixed PostgreSQL's regex repetition limit by checking workload
length separately; corrected a test that had deliberately retained an other-tenant
rejection before checking absence; redirected restarted server output to its own
log to avoid a captured-pipe wait. The interrupted harness run is not retained as
a passing case. The final SQL run passed and removed its own disposable cluster.

## Remaining gates

The shipping gateway still enforces its mock action. M6b must supply native
independently authenticated SQL target/query, fixed driver operations, CTD-driven
admission/issuer/gateway/agent mapping, actual target-token enforcement and query-only
M4 recovery. The internal SQL functions and unsigned outcome records do not verify
grants or authenticate callers by themselves.

Approved resource/action/provider inputs, fence bootstrap/complete writer coverage,
production TLS/RBAC/custody/bypass, target partitions/abrupt loss/stale restore,
retention/migration/incident/workload/cost budgets and owner acceptance remain open.
The etcd restore gate alone does not qualify PostgreSQL restore. M5 enterprise
acceptance and the full M6 pilot gate are unchanged.
