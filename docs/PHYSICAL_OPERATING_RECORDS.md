# Physical operating records — O1 prerequisite

[RFC 0056](rfcs/0056-physical-operating-records.md) defines
`KF-PHYSICAL-OPERATIONS-0.1-draft`. Its O1 Rust library and offline command model
bounded reconciliation of an original physical operation. The [separate managed-drain foundation](MANAGED_KUBERNETES_DRAIN.md) adds native/controller
CAS and bounded delivery source paths; shipping managed integration, actual polling,
current SQL provider and combined qualification remain O2–O4 work. This profile does not enable managed
execution or change the existing drain action's contract.

## Original identity and physical evidence

A record binds the protected policy and enrollment digests, complete family
registration and selected child, native operation/root/grant/attempt, controller
contract, realm/node/resource incarnation and original native dispatch digest.
Its fixed deadline is original `dispatch_authorized.event_time` plus
`reconcile_for_ms`. Waiting for a target acceptance reply cannot postpone it.
Verified target acceptance/deferred times are separately retained when available.

The library verifies complete signed family aggregates using separately pinned
trust. Every retained aggregate must match the same original operation. A
committed native receipt can accompany unresolved physical work. Only the complete
aggregate verifier's original `observed_completed`, `no_physical_dispatch` or
`no_physical_effect` classification resolves the physical record. Historical
completion does not establish a current application SLO or legalize an inverse.

## Closed bounded policy

`Policy` requires the profile, tenant, `resource_owner_id`, `on_call_team_id`,
`incident_sink`, `initial_backoff_ms`, `maximum_backoff_ms`,
`maximum_automated_queries`, `reconcile_for_ms`, `post_deadline_observation` and
`expiry_action`. The only expiry action is `stop_consequential_work`.

The incident sink pins its ID, exact canonical HTTPS URL, standard-base64 Ed25519
acknowledgment keys and `maximum_delivery_attempts`. These are public pins, not
credentials. O1 retains the delivery budget but does not spend it or authenticate
sink replies. The operating checkpoint observer has separate keys; sink,
controller, physical/family observers and native authority signer roles cannot
substitute for it.

Pre-deadline query and delivery limits are each 1–64. Backoff starts positive,
doubles with checked arithmetic and caps at a positive maximum. Maximum backoff
and reconciliation duration are at most seven days. Post-deadline observation is
exactly `{"mode":"disabled"}` or
`{"mode":"query_only","maximum_queries":N,"observe_for_ms":M}`, with N 1–64
and M positive and at most seven days. The latter deadline derives once from the
original reconciliation deadline. Numeric tokens must be safe integers; missing,
null, unknown, duplicate and substituted fields refuse closed decoding.

## Planning and replay

`History::reserve_query` returns a proposed hash-linked history. It reserves a
unique monotonically numbered slot before a caller can begin query I/O. **The
caller must persist that proposal with a native expected-head CAS before I/O.**
O1 does not supply that CAS. An in-memory plan is not a durable reservation and
cannot prevent two workers from using the same slot. The separate O2 foundation
adds a native store; that store and the shipping managed integration still need
actual managed concurrency/physical qualification.

A pending slot survives serialized restart. The record refuses another slot
until a matching observation or transport/malformed/interrupted result accounts
for it. An interrupted slot stays consumed, and elapsed time never restores the
query budget. Backoff/counts/deadlines are replayed from the complete event chain.

At or after the original deadline, unresolved work requires an `escalated` event
before any further recorded action. It binds one stable incident ID, owner,
on-call team, sink and outbox-event digest. Optional post-deadline queries consume
their separate finite budget and cease at their fixed final deadline. The
`stop_required` field is a replay result requiring enforcement; it is not evidence
that a live controller has stopped. Opening the record after its deadline also
records the escalation. A checkpoint cannot hide the overdue unknown by signing
a stale pre-deadline event prefix at a later capture time.

No event can mark physical work resolved merely because an owner acknowledged or
closed an incident. There is no redispatch, mitigation, refund or inverse method.
A separately admitted mitigation remains outside this record. Terminal physical
resolution or an escalation permanently retains `stop_required`; it cannot
reopen consequential work.

## Signed offline verification

An independently configured operating observer signs a checkpoint binding the
entire history, original/policy/enrollment, complete event count/head and capture
time. Verification checks all retained signed physical aggregates, exact
correlation, no unused/omitted evidence, monotone event time, hash predecessors,
numbered queries, budgets, backoff and deadlines. Histories have at most 258
events, at most 129 distinct physical aggregates and at most 32 MiB. These bounds
cover 64 pre-deadline and 64 post-deadline reserve/result pairs plus opening and
escalation. Oversized command inputs are refused before unbounded reads.

```sh
kf-physical-operations --bundle operating-bundle.json --trust protected-trust.json
```

The returned state includes `execution_authority: false`. Correct retention,
latest-head selection, clocks and independent observer custody remain trust
assumptions. A valid historical checkpoint is not a current service health or
execution authorization statement. O1's protected enrollment digest is a pinned
record prerequisite identifier; full managed descriptor/native/target/aggregate
enrollment still requires the new explicit O2 profile/action version.

The qualification uses hash-pinned immutable M8e2b real-cluster aggregates for
unknown, completed, closed-no-dispatch and accepted-with-no-effect physical work. It tests record
serialization/restart and a separate shipping offline command; it does not claim
new managed live-cluster behavior. O2 must integrate and qualify native CAS and incident routing,
O3 current SQL evidence and O4 combined shipping/SDK qualification. Independently
administered writers/custody, production maintenance, physical node failure,
accepted SLOs and independent whole-saga acceptance remain open. M8 is incomplete.

The [frozen-source qualification record](../results/verification/rfc-m8-physical-operating-records-2026-10-23/README.md)
retains the exact software population, pinned historical inputs, generated
operating bundles and separate shipping offline replay. Prior verification
records and frozen inputs remain unchanged.
