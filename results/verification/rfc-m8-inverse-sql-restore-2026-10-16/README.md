# M8d3e native inverse stale SQL restore — 16 October 2026

Baseline: 9e2bef7. [RFC 0051](../../../docs/rfcs/0051-inverse-sql-restore.md)
and the [restore guide](../../../docs/COMPENSATION_SQL_RESTORE.md) qualify existing
native consumed inverse authority across real stale logical SQL copy restoration.
Production execution, admission, storage protocols and migrations are unchanged.

The final complete required run passed **441 Rust tests across 52 binaries**,
**26 SQL storage/peer/restore groups**, **32 Python tests**, both Node suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips occurred. All **509 source files** remained
unchanged through and after the full run. No source repairs occurred during or
after it. `summary.json` pins tools, commands, source and raw logs;
`source-observations.json` retains freeze checks; `final-source.json` pins the same
source and new evidence. Shipping commands remain 22. Earlier committed evidence
and frozen schema, fixtures, paper and both SQL migrations remain unchanged.

## New native qualification

Both cases start from actual SQL forward commit, protected inverse snapshot,
original-result barrier, separately signed applicability and permanent native
compensation mode. Real custom-format pg_dump captures the storage before fresh
inverse issuance. Native admission, verified subject/actor signatures, original
claim, one-shot broker authorization and mandatory signed compound binding precede
one shipping target dispatch. An external mTLS relay holds its actual COMMIT
reply; the target is killed, restarted and an unavailable reply is delivered.
Shared root stop and actual grant expiry precede the restore/recovery phase.

A fresh random database is created with CONNECTION LIMIT 0. Actual logins for
forward executor/reader and inverse executor/reader/barrier refuse both before
and after real pg_restore. Restore uses no owner/ACL adoption; with the copy still
fenced, the owner removes PUBLIC and application database/schema/table/function
privileges, rotates its resource incarnation, and admits only the inverse reader
with CONNECT, schema visibility and exact lookup-function execution. Old executor,
barrier and forward logins remain denied after query-only reopening. Reader apply
refuses specifically on function privilege; normal native database preflight
refuses. No original request is reapplied, including as a negative test. No native
service resumes on the copy. The original database, authority ledger and separate
write-ahead witness remain intact.

- **Original native uncertainty:** the actual inverse committed at SQL but no
  native terminal receipt was retained before restoring the copy. Query-only
  recovery against the stale copy observes missing original lookup and retains
  the same original unknown attempt, signed unknown receipt and held spend. The
  test-owner's external commit record cannot silently promote native history.
- **Original signed commit:** native query-only recovery retains a committed
  signed receipt from the original target before restore. Repeated native
  recovery against the stale-copy configuration returns that exact signed
  receipt without querying or overwriting it. Missing SQL cannot erase it.

Both verify identical held inverse spending and forward budget, original
root/grant/attempt correlation, same witness enrollment, refusal of replacement
claim/dispatch, one original target send, no additional mint/send/refund/resume,
and unchanged restored row/version/fence/incarnation through reconciliation.
Actual source commit remains queryable and stale-copy lookup remains absent.
Dump and externally retained actual-result hashes are pinned in the native test
reports in `required-runtime.log` and `native-restore-observations.json`; the dump
files themselves are disposable.

The complete public compound-lineage verifier returns unresolved or historically
compensated. In the committed case the historical report is compensated although
the restored live row is the earlier forward booking. This evidence explicitly
distinguishes original history from the copy's live state and grants no execution
authority. No externally retained test-owner record becomes trusted receipt input.

Development boxed large test admission/restore futures to fit the normal test
stack and supplied read-only schema visibility required by runtime ACL inspection.
Temporary diagnostics were removed before this final freeze. Production stack,
policy, timing defaults and privilege checks remain unchanged. The runner passes
its pinned PostgreSQL tool directory to native tests; no production repair tool or
new wire/schema profile is added.

## Limits and remaining milestones

This is stopped logical-copy qualification in one disposable Darwin cluster with
generated identities, fixture providers and one OS UID. External history is
fixture-owned and the witness is a separate local process. It does not qualify
physical backup/PITR/cutover, independent storage/key/history custody, accepted
external outcome ingestion, fresh deployed CTD/contract/authority enrollment,
complete writer coverage or enterprise restore acceptance.

M8 remains incomplete: multi-contract inverse families, dynamic delegation,
full/independent A2A peers, wider process/partial-failure matrices, independent
whole-saga acceptance, physical inverse SQL restore/cutover and actual Kubernetes
drain remain open. No automatic service resume, rollback, refund, global atomicity
or blind retry is claimed.
