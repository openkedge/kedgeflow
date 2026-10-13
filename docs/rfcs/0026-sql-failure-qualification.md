# RFC 0026: Fresh SQL failure, restore and incident qualification

- Status: Draft
- Profile/version: KF-SQL-FAILURE-QUALIFICATION-0.1-draft
- Milestone: M6c bounded software qualification
- Baseline: ec62f85; RFCs 0010, 0016, 0017, 0024 and 0025
- Owners/reviewers: unassigned

## Problem and scope

Compose fresh signed admission/issuance, the official Node client, native broker,
shipping gateway/SQL target/recovery processes, the restore witness and retained
incident/collector delivery. Qualify one conditional reservation version transition
on a disposable PostgreSQL database and same-host independent witness process.
This is a qualification profile, not a new execution or authority interface.
Frozen records and existing draft contracts remain unchanged.

## Authority and trust

Generated certificates, subject/actor signing keys, exact CTD/policy/evidence pins
and function-only SQL roles are software fixtures. Services retain separate grant,
target, outcome and collector signing roles. The actual target enforces its grant,
reference credential, gateway peer and SQL version/incarnation/fence checks.
Recovery uses the separately enrolled query identity and bearer. Test-owned mTLS
relays validate real peer identities and scoped role tokens; they inject barriers
without adding identity headers or exposing authority to agents.

The namespace is enrolled empty under RFC 0016 before control installation. Every
subsequent mutator of the enrolled source namespace uses the same witness binding.
The native collector shares retained source receipts in this software fixture;
independent enterprise collector storage/access remains unqualified. Privileged logical namespace
copies are a stopped fixture-only rollback model; witness and SQL state remain
independent. No production credential, deployment, paging or cutover is involved.

## Contract

Use RFC 0025's named action, schema and original operation/attempt binding. Record
actual SIGKILL plus wait/reap before restart. Observe barriers at completed claim,
broker response, completed dispatch authorization, real SQL lock/COMMIT and
retained collector acceptance. A relay holding a response after COMMIT observes
the external delivery boundary, not an internal target instruction pointer.

For each case retain original grant/root/attempt/fence, SQL row and outcome,
claim/permit/dispatch counts and recovery/receipt/delivery results. A new Node
process resolves its persisted operation with current status-only delegation.
No additional claim, target token mint or SQL dispatch may follow recovery.

Quorum/witness checks precede mutating transitions. A stale local snapshot or
pending witness refuses new authority writes. Native SQL query can still establish
retained target outcome. Restoring the exact latest logical namespace must preserve
consumption and monotone fence; this does not qualify disk/power/stale SQL restore.

Unknown observations open an owner-bound incident, pass the retained deadline and
escalate under RFC 0017. Correlated later commit closes it. Collector acceptance
and signed acknowledgement progress survive supervisor death/lost replies under
the same receipt identity and order.

## Failure and retry

A kill before a completed dispatch authorization can eventually seal the original
attempt not_dispatched after its budget expires, while keeping authority consumed.
After authorization, missing SQL outcome, rolled-back SQL transaction, unavailable
query or lost COMMIT reply remains unknown until correlated commit evidence exists.
Absence never permits resend, remint, grant replacement or refund.

A process killed inside the witnessed write window can leave pending quarantine.
Restart must refuse bypass; this profile does not invent pending-witness repair.
Operator repair, production restore custody and acceptance remain separate gates.
Collector retries are query/report operations; they cannot mutate the SQL resource.

## Compatibility and rollout

No frozen schema or existing signed meaning changes. Barriers and logical rollback
utilities stay in test support. Use required PostgreSQL/etcd/SDK mode for this suite;
missing dependencies must fail required mode. Keep earlier evidence immutable.
Scope this evidence to declared binary, clock, host and database versions.

## Implementation and acceptance

Acceptance matrix: shipping gateway and target kills around claim, exchange,
authorization and SQL lock/COMMIT; native broker/recovery/supervisor restart;
original-attempt status after Node restart; witnessed stale/pending refusal;
unknown incident escalation and ordered collector acknowledgement/resolution.
Eleven composed cases pass in the [required verification record](../../results/verification/rfc-m6-failure-2026-10-13/README.md).
The [guide](../SQL_FAILURE_QUALIFICATION.md) maps exact barriers to observations.
Preserve consumed state through every observed failure and keep unresolved
operational gates explicit. No production runtime, wire schema or SQL migration
changes are required by this increment.

## Open decisions

Pending-witness repair and existing-state enrollment, SQL stale-backup/storage
loss, real evidence and approved provider/certificate/peer custody, deployed writer
and bypass coverage, budgets and owner acceptance remain open. Version-template or
automated descriptor rollover and independent peers remain unqualified.
