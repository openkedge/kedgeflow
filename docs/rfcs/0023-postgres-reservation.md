# RFC 0023: PostgreSQL conditional reservation and retained target outcomes

- Status: Draft
- Profile: `KF-POSTGRES-RESERVATION-0.1-draft`
- Milestone: M6a target-storage prerequisite; M6 pilot remains open
- Baseline: `f9782fc`; frozen KF-JSON-0.2 and RFC 0021
- Owners/reviewers: unassigned; resource, security, deployment and SRE owners

## Problem and scope

Move beyond a fenced software target with one actual PostgreSQL transaction.
The action `postgres.reservation.set.v1` sets a reservation label on one existing
row, increments its version and retains a correlated outcome. It does not reserve
a shared capacity budget, execute arbitrary SQL, drain a node or coordinate a saga.
The predicate covers the row's incarnation, version and increasing fence only.
Any deployment requiring aggregate capacity policy also needs M8.

This increment implements records and database functions. [RFC 0024](0024-postgres-target-http.md)
supplies the M6b1 authenticated SQL target/query, local driver and reference-token
verification. [RFC 0025](0025-postgres-leaf-binding.md) separately supplies M6b2's
named CTD mapping, explicit gateway adapter and fresh admission/issuer/Node/native
broker/SQL/recovery path. Installing this migration alone does not enroll that path.

## Authority and trust

Keep a dedicated schema owner and migration credentials outside agent and target
execution identities. No agent receives a database login, schema ownership,
function execution, table access or target backing credentials. The future target
service alone obtains `apply` execution; a separate query identity obtains `lookup`.
The database functions are privileged internal ports, not grant verifiers. The
caller must independently authenticate the gateway connection, verify the signed
grant and actual RFC 0021 target token, and compare exact role/audience/scope,
grant/root/attempt, tenant, workload, resource/action and expiry before invocation.
Query authorization must check tenant and disclosure scope before invoking lookup.

The SQL executor can name rows within this schema; application verification and
database-role custody are trusted. A multi-tenant deployment needs independently
accepted tenant isolation or dedicated namespaces/roles. Direct owner/superuser
writes, uncontrolled writers and stale database backups violate the guarantees.
No production identity, TLS/RBAC, native bypass or real owner acceptance is inferred
from local `SET ROLE` tests.

## Contract

[The closed schema](../../spec/drafts/postgres-reservation-v0.1.schema.json) defines
three unsigned target-side records. They are a separate draft, not additions to
frozen signed grants or a reinterpretation of the mock CTD.

- `Parameters`: exactly `resource_id`, positive integer `expected_version` and a
  bounded `reservation` label. Agents cannot supply fence, SQL, routing, tenant,
  attempt, root, credential or gateway identity fields as action parameters.
- `DispatchRequest`: exact profile/action plus tenant/conflict domain, original
  attempt/grant digest/root, resource ID/incarnation, expected version, fence,
  reservation, authenticated gateway workload and authorization expiry in UTC ms.
  The future target constructs these fields from verified request/grant/context,
  never copies unverified credential claims as its expectations.
- `Outcome`: exact profile, complete original request, `committed` or
  `guard_rejected`, and `post_version`. Committed requires expected version plus
  one; guard rejection requires null. The Rust verifier compares every original
  field. An unsigned outcome is trusted only through an independently authenticated
  target channel/custody; shape or correlation alone is not target authentication.

All counters stay within JSON's safe integer range. Expected version leaves room
for one increment. Wire decoding rejects unknown/duplicate fields, floating numbers
and records exceeding 32 KiB. SQL takes already-decoded JSONB, whose serialization
is not KedgeFlow canonical JSON and must never substitute for a signed digest.

### Atomic storage transition

Apply [migration 0001](../../migrations/postgres/0001-reservation.sql) once to a new,
approved namespace; reapplication refuses rather than resetting history. A resource
row contains tenant, conflict domain, ID, incarnation, version, last fence,
reservation and an active tombstone flag. The operator enrolls rows and bootstraps
the authority fence allocator above every covered target fence before writers start.
Retire/delete by tombstone; recreation requires a new incarnation and retains the
fence floor. This increment has no automated bootstrap or recreation endpoint.

`kf_reservation.apply(jsonb)` runs in one caller transaction:

1. Validate the closed request. Insert a provisional rejection/outcome row under
   unique `(tenant, attempt_id)`, `(tenant, root_id)` and `(tenant, grant_digest)`.
   Conflicting attempts serialize on uniqueness. An exact original replay returns
   the retained outcome; a changed binding or reused root/grant refuses.
2. Lock the exact resource row with `FOR UPDATE`. Require active state, matching
   conflict domain/incarnation/version, a strictly greater fence and an unexpired
   authorization at the effect check after lock acquisition.
3. If checks fail, retain `guard_rejected` with no resource mutation. Otherwise
   increment version, replace reservation/fence and retain `committed` atomically.
4. Return only as the encompassing transaction commits. Rollback or statement
   failure undoes both resource and outcome writes. The provisional row is invisible
   to other transactions. PostgreSQL's transaction boundaries and row locks provide
   this local atomicity; there is no atomic transaction with etcd.

Use a fresh single-command READ COMMITTED/autocommit connection per application
operation. The future driver must acknowledge PostgreSQL COMMIT before reporting a
terminal result. A caller-owned long transaction is not the target service contract.
Changing isolation can cause serialization failures; such errors establish neither
commit nor permission to dispatch again. Functions have a fixed safe search path,
qualified relations and PUBLIC access revoked in the same migration transaction.
See PostgreSQL's [row-locking contract](https://www.postgresql.org/docs/18/explicit-locking.html)
and [security-definer guidance](https://www.postgresql.org/docs/18/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY).

### Retention and query

`lookup(tenant, attempt)` returns the original immutable terminal record or SQL
NULL in its current transaction snapshot. Absence can precede an in-flight commit;
it is not proof of no effect and never authorizes resend or allowance refund.
After possible dispatch, loss/timeout/unavailable lookup stays unknown until an
authenticated retained outcome resolves it. Replaying a stored request is database
idempotency, not authorization for gateway recovery to call `apply` again.

Retain attempts/root/grant uniqueness beyond every outstanding grant, credential,
replay, delayed-effect and recovery horizon. No pruning, refund, forced repair or
schema downgrade is implemented. A stale target restore must remain quarantined
until its effect/attempt/fence history and independent authority state are reconciled
under a separately accepted procedure. The etcd witness alone cannot certify a
restored PostgreSQL target.

## Compatibility and rollout

This action needs a new registered CTD/action digest, closed parameter schema,
predicate and Level A adapter contract. Claim only the single-row reservation
transaction as the commit point. M6b must bind CTD-approved fields without widening
the mock action implicitly, negotiate the new target profile and refuse unknown
profiles/actions/fields. Native dispatch/query routing stays fixed by operator pins.
Schema ownership, full covered writer inventory, counter bootstrap and retention
are prerequisites before observe → isolated pilot → accepted privilege cutover.

## Implementation and acceptance

- `postgres_action.rs`: closed records, bounded decoding and exact outcome checks.
- `migrations/postgres/0001-reservation.sql`: atomic conditional effect, deduplication,
  retained query and explicit owner/executor/query privilege boundaries.
- `tests/postgres_action.rs`: authority-field injection, substitution, numeric,
  duplicate and terminal-correlation negatives.
- `scripts/test-postgres.py`: an actual disposable PostgreSQL 18.3 Unix-socket
  cluster; concurrent writers/replay, changed bindings/root/grant reuse, guards,
  rollback, in-flight absence, discarded reply, role refusals and server restart.

These qualify a target-storage prerequisite only. RFC 0024 supplies native
target/query and RFC 0025 supplies fresh agent-to-SQL execution/recovery. Real
target partitions, abrupt target process/storage loss, stale restore, production provider/credential enforcement,
deployed bypass, latency/workload budgets, costs, on-call and owner acceptance
remain M6 pilot gates. Required M5 custody/provider acceptance remains open.
See the [retained M6a verification](../../results/verification/rfc-m6-postgres-2026-10-12/README.md).

## Open decisions

Resource owners must approve the actual action, target/version, namespace, covered
writers, incarnation lifecycle, fence bootstrap and retention. Security/platform
owners must approve target/query identities, token pins, TLS/database roles and
restore quarantine. SRE owners must approve failure/incident/cost budgets and
abort/upgrade/exit procedures. No repository fixture supplies these decisions.
