# M6d1 PostgreSQL enrollment — 13 October 2026

[RFC 0027](../../../docs/rfcs/0027-postgres-enrollment.md) and the
[operator guide](../../../docs/POSTGRES_ENROLLMENT.md) add a shared fixed SQL-role
check to runtime connections and an explicit native `--check-database` mode.
Based on `7e30c8a` and the tested working tree. Existing offline `--check`, frozen
contracts/fixtures/paper, SQL migration and Cargo.lock remain unchanged.
Earlier verification records are preserved byte-for-byte.

## Reproduction

Darwin ARM64; Rust/Cargo 1.98.0; Node 25.2.1; Python 3.13.12; PostgreSQL 18.3
with M6a's official source checksum; etcd 3.6.5 with three loopback source members
and same-host independent fixture witnesses. Services, roles and databases are
local disposable software fixtures, with no enterprise target or secret used.

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

The SQL/etcd launchers require both dependencies; the pinned official SDK is also
required. Rust cases are serialized for host disk capacity, while explicit
concurrent actors remain inside tests. Private enrollment databases/roles keep
PUBLIC/membership negatives independent of other tests. The existing CI SQL job
includes the new native target cases. CI YAML/run scripts parse locally; remote
Linux/GitHub and minimum Rust/Node execution remain unobserved.

## Final-source observations

[Combined regression](tests.log): **263 Rust tests pass across 39 test binaries**,
zero failures/ignored/skipped. Three new isolated-database enrollment groups
and shipping CLI checks join all six existing native SQL target tests and eleven
M6c composed failure cases. [SQL storage](postgres.json): eleven real groups pass.
Clippy/format, Node vectors, frozen paper/schema, Ruff/mypy and all 32 Python tests
pass. [summary.json](summary.json) pins source and evidence SHA-256 hashes.

- Actual configured logins can exercise column UPDATE/INSERT/SELECT/REFERENCES
  while the corresponding table-wide privilege predicate remains false. The
  probes execute and roll back, then preflight/runtime refuse the excessive role.
- NOINHERIT direct and transitive membership can permit real SET ROLE and a column
  update despite no current effective column UPDATE. Preflight/runtime refuse
  membership, including currently non-settable membership, without mutation.
- Effective PUBLIC table/column grants, admin/replication flags, database owner/
  CREATE, protected-schema CREATE, schema/function grant-option delegation, wrong
  function execution and missing own
  function/USAGE refuse. Row version/fence/reservation and attempts stay unchanged.
- Removing each fixture excess restores successful checking. Final normal apply
  and independent lookup succeed. Valid mixed-case logins preserve exact role
  identity through an exact catalog OID lookup rather than a regrole text cast.
- Shipping `--check-database` checks both logins and emits only local enrollment
  metadata while its configured port is occupied. It creates no attempt or effect
  and binds no listener. Absent socket/admin query role/conflicting flags refuse;
  offline `--check` still succeeds with an absent database socket.

Both runtime operation connections and preflight use the same guarded catalog
query. This deliberately tightens enrollment: table SELECT, column privileges,
role membership and additional database/admin privileges previously tolerated by
the bounded driver are unsupported. There is no automatic revoke, migration,
connection fallback, role switch or source of new execution authority.

## Preliminary checks and corrections

[The initial fixture run](preliminary-setup.log) created its private database and
roles in one multi-statement batch, which PostgreSQL treats as a transaction.
CREATE DATABASE must run separately; the fixture was corrected.
[The second run](preliminary-reference.log) attempted a temporary-to-permanent
foreign key, which PostgreSQL forbids. The corrected REFERENCES probe uses a
private permanent DDL surface, rolls it back and removes its separate CREATE
grant before testing the protected resource guard.

[Focused native checks](focused.log) passed, and [an earlier regression](preliminary-regression.log)
passed before the final compatibility case was added. That earlier source does
not qualify the final source. [Mixed-case reproduction](preliminary-case.log)
exposed a role-name regrole cast that folds case; exact catalog OID selection
corrects it. A further enrollment review added actual schema/function grant-option
delegation probes and refusal. The [intermediate compatibility regression](preliminary-compatibility-regression.log)
predates those additions and does not qualify final source.
[Final native verification](final-native.log) passes all nine cases, including
mixed-case roles and grant-option delegation, before the final required full
regression. No refusal assertion or frozen contract was weakened.

## Limits and next milestone

Catalog observations do not certify actual peer authentication, OS/service-account
separation, socket/secret/configuration custody, deployed agent/descendant bypass
coverage, function-body custody or owner approval. Tests use disposable local trust
authentication. The approved administrator and function owner remain trusted;
concurrent privilege/function changes after an observation are a TOCTOU boundary.
The report is unsigned local metadata, not an acceptance record or permanent lock.

M6d2 must qualify protected OS/socket/peer and secret custody plus deployed bypass
paths. Physical/stale SQL restore, retention/migration, provider lifecycle, budgets,
incident routing and resource/security/SRE owner acceptance remain M6d3/M5c gates.
Independent collector storage and distributed failure domains remain unqualified.
This record closes only the bounded M6d1 software prerequisite.

Logs normalize local/disposable paths, trim terminal whitespace and preserve
semantic results. Earlier evidence, frozen contracts and migration are unchanged.
