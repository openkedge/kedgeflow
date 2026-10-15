# M8d3a conditional SQL inverse and target barrier — 15 October 2026

Baseline: 11fdbb4. [RFC 0048](../../../docs/rfcs/0048-postgres-compensation-target.md)
and the [operator guide](../../../docs/POSTGRES_COMPENSATION_TARGET.md) add actual
conditional SQL restoration, an original committed-effect barrier, a separate
applicability evaluator and an explicit native target/gateway adapter. A new
migration supplies immutable protected snapshots and original inverse results;
the original migration and forward action remain unchanged.

The complete required run passed **428 Rust tests across 51 binaries**, **26 SQL
storage/peer/restore groups**, **32 Python tests**, both Node suites, formatting,
Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures, ignored
tests or required-mode skips occurred. All **495 source files** stayed unchanged
through and after the final run. No source repairs were needed during or after
that run. `summary.json` pins source, commands and logs; `final-source.json` pins
the same source and evidence. The two new commands bring shipping binaries to 21.

## New observations

Six native groups compose:

- The original independently admitted forward effect actually commits in
  PostgreSQL. A target barrier verifies its exact retained result, protected
  snapshot and locked current row; a distinct evaluator signs applicability.
  Fresh inverse admission, native compound binding/spending and cryptographically
  verified subject/actor broker identities produce one original credential permit.
  Actual restoration advances version/fence and independent query returns the
  original retained result. Costs remain held.
- A writer advancing the row after qualification prevents restoration. The target
  cannot create a new affirmative barrier for that old version. Its original
  inverse guard-rejected result is retained and the native held spend stays unknown.
- Native mTLS target/barrier/query endpoints enforce distinct workloads and
  credentials. A lost reply after actual inverse COMMIT leaves the original spend
  unknown; service restart and query-only recovery after stop/expiry retain one
  signed committed receipt for that same attempt, without remint or resend.
- Shipping target/evaluator commands validate protected configuration and separate
  signer roles. The real-time target runs with a canonical Unix-socket path and
  kernel peer pin; the native adapter exports original ledger-bound proof and
  executes the actual inverse through that process. SQL-role preflight passes;
  changed profiles, endpoints, credentials and signer aliases refuse.
- Cryptographically re-signed compound substitutions of topology, contract,
  qualification, original grant/certificate/parameters or outcome trust refuse.
  Replaced attempts, expired authority, a false barrier, absent binding, unknown
  fields and wrong evaluator/outcome roles cannot reach SQL mutation.
- A delayed actual broker permit transaction loses to a stop of the original
  forward reservation. No permit is retained and the original inverse spend stays
  held. This race uses an explicit synthetic identity boundary; the separate
  positive tests use native cryptographic identity verification.

Eight additional real-SQL groups cover protected capture/digest correlation,
concurrent original replay, conflicting/replacement identities, stale fence /
version/deadline/original/snapshot substitutions, missing or noncommitted forward
effects, intervening writers/recreation/inactivity, transaction rollback, deadline
after lock contention, owner-only capture and closed record/role bypass refusal.
Expanded Node vectors check explicit inverse discovery/schema/contract/parameters;
this record does not yet establish an official-SDK inverse workflow.

## Scope and remaining M8 gates

This is disposable local Darwin software qualification with one fixture OS UID
and generated identities. PostgreSQL peer authentication and role checks are real;
separate-account isolation, protected file/credential custody, deployed writers,
independent acceptance and Linux/MSRV are not observed here. The restore rehearsal
still covers the original forward profile; inverse storage-rollback/restore
acceptance requires a separate qualification. SQL atomicity establishes only this
one-row effect and original terminal replay, not a general physical barrier.

One exact inverse contract is selected per paired service. Complete inverse SDK
orchestration, multi-contract families, independently verified whole-saga history
and wider failure/deployment acceptance remain M8d3. Actual Kubernetes Level C
drain remains M8e; dynamic delegation and complete independent A2A peers also
remain open. M8 is incomplete. No refund, mutation retry, version rewind or global
cross-namespace/cluster atomicity is claimed.
