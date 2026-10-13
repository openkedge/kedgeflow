# M6c fresh SQL failure qualification — 13 October 2026

[RFC 0026](../../../docs/rfcs/0026-sql-failure-qualification.md) and the
[qualification guide](../../../docs/SQL_FAILURE_QUALIFICATION.md) compose fresh
SQL authority with shipping process failures, restore quarantine and owned
incident/collector delivery. Based on `ec62f85` and the tested working tree.
This increment changes test support, CI labels and documentation; production
runtime, frozen contracts, SQL migration and Cargo.lock remain unchanged.
Earlier verification records are preserved byte-for-byte.

## Reproduction

Darwin ARM64; Rust/Cargo 1.98.0; Node 25.2.1; Python 3.13.12; PostgreSQL 18.3
with the M6a official archive checksum; etcd 3.6.5, three loopback source members
and a separate single-member same-host witness process per composed case.
No enterprise service or production secret is used.

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

The launchers require SQL and etcd; the official SDK is also required. Cases are
serialized for host disk capacity, with explicit actor races still active inside
other tests. Missing dependencies cannot silently pass required mode. The existing
PostgreSQL CI job includes the new governance cases. CI YAML/run scripts parse;
remote Linux/GitHub and minimum Rust/Node execution remain unobserved.

## Final-source evidence

[Combined log](tests.log): **260 Rust tests pass across 39 test binaries**, zero
failures/ignored/skipped. This includes **eleven new composed SQL cases** and all
legacy mock, fresh leaf, native target, restore and supervision regressions.
[SQL storage](postgres.json): eleven real groups pass. Clippy, formatting, Node
vectors, frozen schema/paper, Ruff/mypy and all 32 Python tests pass. Source and
evidence SHA-256 hashes are retained in [summary.json](summary.json).

The eleven cases obtain fresh admission/issuance after control installation,
acknowledgement and empty witness enrollment. Native broker verifies actual
Ed25519 subject and ES256 actor signatures; the shipping SQL target verifies
reference token/grant/gateway mTLS and commits a real conditional SQL update.
Test-owned mTLS relays count successful nested witnessed transactions and fixed
broker/dispatch forwarding, without identity-header substitution. Every kill
requires actual SIGKILL plus wait/reap.

- Gateway kills after witnessed claim/native mint seal the original attempt
  not_dispatched with the original nonce consumed. No additional token or SQL call.
- After dispatch authorization, native SQL absence and a target killed at an
  actual row lock remain consumed unknown. Backend rollback retains no effect.
- Kills after COMMIT preserve one retained target outcome and version 241-to-242
  transition; native query resolves the original attempt without another mutation.
- Broker death after mint preserves the original permit, without redelivery/remint.
- Pending witness finalization refuses recovery, new claim and removed-gate bypass.
  The interrupted original claim remains held; no repair is invented.
- A stopped preclaim logical prefix copy is quarantined against the independent
  witness, while native SQL query retains its commit. Restoring the exact latest
  values preserves the receipt, consumed nonce and original fence.
- Recovery-worker death after fully witnessed receipt persistence retains that
  exact receipt/head across restart.
- Supervisor death after native collector acceptance loses only its reply. Restart
  looks up the exact signed acknowledgement, escalates the same owner/deadline
  during target-query outage, then resolves from SQL commit and delivers its linked
  successor receipt with ordered signed acknowledgement progress.
- Separate Node processes resume query-only from persisted operations with current
  status-only delegation. Final SQL row/outcome equals its pre-recovery value and
  no additional claim, permit, mint or target call occurs. Pending quarantine
  deliberately remains unavailable to normal status.

## Preliminary harness failures

The preliminary logs are retained separately and do not qualify final source.
An initial compile failure came from moving a Drop-guarded task handle. The first
runtime relay ignored nested witnessed writes; counters/barriers were corrected
to inspect the actual nested transaction and successful application response.
PostgreSQL detects a killed blocked Unix-socket client after its row-lock wait
wakes; the owner lock is released after kill/reap and backend rollback is observed.

The stopped logical restore initially combined overlapping delete/put operations,
which etcd rejects. The corrected fixture deletes first, then uses bounded put
batches while all writers remain stopped. The collector case initially assumed
independent receipt storage; the draft native collector queries shared retained
source receipts, so this fixture now uses that supported ledger contract. Neither
runtime behavior nor assertions were weakened. The two remaining cases passed
in [focused verification](remaining.log) before the final full regression.

## Limits and next milestone

Generated enrollment, static signed evidence, fixture role tokens and same-host
witness qualify mechanics only. The source-ledger rollback copies values, not
physical etcd revisions/history; SQL and witness are not rolled back. Physical
storage/host failure, stale SQL backup and pending-witness repair remain open.
The collector has separate authentication/signing roles but shares receipt storage.
Independent collector storage/access and external incident routing are unqualified.

The eight-second grant and one-second incident deadline are fixture budgets, not
accepted performance objectives. The exact CTD covers one transition; automatic
version rollover, real provider refresh/custody, production etcd RBAC, writer/bypass
coverage, retention/migration/restore custody and owner acceptance remain open.
M6d should prepare and qualify those deployment/pilot gates alongside M5c provider
acceptance. This evidence closes only the bounded M6c software increment.

Logs normalize local/disposable paths and strip terminal color; earlier evidence
is unchanged. Frozen v0.9 fixture/schema/paper and migration hashes match the baseline.
