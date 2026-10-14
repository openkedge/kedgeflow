# RFC 0030: PostgreSQL stale restore rehearsal and storage budgets

- Status: Draft
- Profile/version: KF-POSTGRES-RESTORE-0.1-draft
- Milestone: M6d3a disposable logical restore/budget prerequisite
- Baseline: RFCs 0023–0029
- Owners/reviewers: unassigned

## Restore contract

An operator stops target/gateway execution, fences application connections and
retains external attempt/outcome history before restoring SQL. Keep the authority
ledger and restore witness independent of the SQL backup; never restore consumed
allowances from this backup. A dump without a later outcome proves neither absence
of an effect nor safe redispatch. Original attempts remain consumed/unresolved.

The disposable rehearsal uses a fresh isolated database only. Dump the database
before a confirmed commit, retain the outcome outside it, then restore that older
custom-format dump into a new database with CONNECTION LIMIT 0. Demonstrate that
the actual executor login cannot connect. Restore without ACLs, explicitly remove
PUBLIC schema/function permissions, and rotate the restored resource incarnation.
Re-enroll only the fixed function-only executor/query privileges before lifting
the database connection fence. Verify the original lookup is absent and retain
the externally observed commit as lost-from-restored-database, not no-effect.
Never call apply with the original request after restoration.

The rehearsal does not enroll or exercise an authority-ledger allowance. Its report
explicitly states authority_consumption_tested=false. Holding consumed authority is
a required deployment contract, not an observation from these direct storage calls.

A real deployment must rotate its signed CTD/target registration and relevant
authority enrollment before restart, retain immutable original history, and
reconcile unresolved effects under an accepted procedure. This rehearsal does not
automatically resume an existing service, repair pending witnesses, prove physical
restore safety, or delete retained attempts. No production repair command is added.

## Storage budget contract

Measure a declared number of serial unique SQL reservation operations and
authoritative queries in this same disposable database. Publish attempted,
committed, refused and unresolved counts separately, with monotonic wall-clock
latency quantiles. A local default p95 budget of 3000 ms is a fixture expectation,
not an enterprise SLO. Failed budgets fail the rehearsal. No grant, admission,
broker, browser queue, network intermediary or comparative throughput claim is
made from direct storage timings.

## Acceptance

Run real pg_dump/pg_restore, retain source and backup hashes, externally observed
original commit and lost lookup, connection-fence refusal, incarnation change,
fresh storage workload and conserved outcomes. Keep all older evidence immutable.
M6d3 owner/cost/on-call decisions, physical backup/failure domains, production
retention/key history and accepted abort/upgrade/restore/exit remain open.
