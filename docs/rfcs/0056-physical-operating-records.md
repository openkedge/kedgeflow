# RFC 0056 — Physical operating records and current reservation evidence

- Status: Draft; bounded O1 record/replay implemented; O2 shipping read-only supervision and O3 SQL source implemented; complete managed audit added; shipping managed mutation/SDK qualification open
- Milestone: M8e2b remaining software; independent deployment acceptance remains M8e3
- Proposed record profile: `KF-PHYSICAL-OPERATIONS-0.1-draft`
- Prerequisites: RFCs 0017, 0030, 0048, 0054 and 0055
- Protocol owner/reviewer acceptance: open

This RFC specifies the next software increment after the bounded
[RFC 0055 SDK/query implementation](../KUBERNETES_DRAIN_AGENT.md). It does not
enable or qualify managed physical execution. The existing drain profile remains
bounded mechanical software and is not silently upgraded by this document.
The [frozen whitepaper execution contract](../whitepaper/v0.9/whitepaper/05-execution.tex),
“Bound automated recovery for legacy targets,” requires retained correlations/status evidence, polling/backoff
limits, escalation deadline and accountable resource owner/on-call. It also
requires declared limits on automated recovery at that deadline. An acknowledgment
or administrative incident closure is not outcome evidence or refund authority.

## Explicit enrollment and version boundary

Introduce a closed versioned managed-drain enrollment that pins the original
complete drain contract, complete family/selected child, operating policy,
physical evidence trust and current SQL reservation query registration. Its
digest must be bound in the named descriptor/schema, native authority, target
acceptance and independent aggregate trust. Use a new explicit profile/action
version rather than adding a nullable operating policy to RFC 0055 v0.1 and
calling existing records qualified. Legacy mechanical-profile records remain
verifiable with their original semantics. Missing, explicit null, unknown fields,
policy substitution or downgrade refuse managed enrollment/dispatch.

A record-only operating-policy library may be delivered first as a prerequisite;
it cannot enable the protected action or claim that controller CAS enforcement
and independent aggregate integration already exist.

## Operating policy

Closed fields: profile; tenant; accountable resource_owner_id; on_call_team_id;
protected incident sink identity/origin, acknowledgment trust and finite delivery
attempt limit; initial_backoff_ms;
maximum_backoff_ms; maximum_automated_queries; reconcile_for_ms;
post_deadline_observation (disabled or bounded query_only with its own count and
final deadline); expiry_action fixed to stop_consequential_work. All integers are
safe, positive and bounded. Backoff uses checked arithmetic and capped growth.
No configured callbacks, executable scripts, arbitrary target URLs or runtime
caller-selected owner. Independent physical evidence trust is separately pinned.

## Original operation record

Hash-linked durable events bind managed enrollment/policy digest, full family
registration/selected child, operation key, root, exact original grant/attempt,
controller contract, node/realm incarnation and original native dispatch.
The reconciliation deadline is derived once from the retained
`dispatch_authorized.event_time`; missing or ambiguous acceptance cannot postpone
escalation. Verified target acceptance and deferred times remain separate evidence. A process
restart or later observation never creates a later deadline or fresh query budget.
Native committed acceptance cannot be used as physical resolved.

Required retained status: current native acceptance head; verified original
controller state digest; complete physical aggregate/capture digest and effective
physical classification; reserved query number, next_allowed_at and remaining
count; incident id/owner/on-call/state; updated_at and previous_event_digest.
Every query is durably reserved before I/O. A crash after reservation consumes
that query slot. No unbounded polling on unavailable or malformed evidence.

Only a complete verified physical completion or positively verified closed
original no-dispatch/no-effect boundary can end automated reconciliation.
Physical partial/failed/blocked/Pending/unknown, missing evidence, forged or
substituted signatures, stale current observations and native committed alone
cannot end it. Historical verified completion stays historical; it is not a
current application SLO or permission to compensate an irreversible action.

## Deadline and incident

Before every newly authorized physical mutation, validate the original deadline
under the protected clock/uncertainty model, retain that check time, and compare
the original operating record/policy and unresolved/stop state in the same final
native Pending CAS used for root/phase/control comparisons. Recheck the deadline
before beginning network I/O after CAS. No-worker downtime must not permit a
fresh post-deadline authorization. A request already authorized before stop can
arrive later and remains held.

The native CAS compares durable stop/generation state; it does not compare the
etcd server's wall clock to an arbitrary timestamp. Do not claim a hard real-time
send or physical-effect cutoff from a client clock check. Specify the allowed
clock uncertainty and authorization-to-send interval; if the required bound is
not enforceable by the deployment, refuse managed enablement. A pause or network
delay after the last local check can produce a late original effect. It never
creates permission to resend or infer no effect.

At or after the original deadline, atomically retain stop state plus an owned
incident outbox event. No network delivery success is needed to establish the
stop. Query-only delivery/observation has separate finite budgets. Retries to
incident sink use stable original incident and event ids; the sink's receipt is
not a physical outcome. Missing/outage sink keeps a visible undelivered incident.
Owner acknowledge/administrative close can annotate but cannot establish no
effect, refund allocation, reopen mutation or authorize inverse. Mitigation needs
its own fresh admission/budget/guard and cannot erase the unknown operation.

Existing OutcomeSupervisor cannot be reused unchanged: supervision_ledger.rs
resolves incidents on a committed native receipt, while this drain receipt only
means acceptance. Keep its SQL semantics intact; new physical supervision must
consume verified effective physical evidence and retain a distinct versioned
record and independent verifier.

## Current SQL reservation prerequisite

Historical committed SQL predecessor is insufficient. A protected readonly
registration binds exact original SQL resource incarnation, grant, attempt,
fence, expected current reserved version/state, storage generation and declared
covered/external writers. Obtain an independently authenticated bounded response
and exact proposal evidence with source observation/freshness bounds. Refuse
restored/recreated storage, changed version/fence/state, missing reservation,
substituted original identity and stale/unknown results before consequential work.

Do not edit SQL migrations 0001/0002. If a new read function is needed, add a new
migration with separated privileges, closed records and original-effect joins.
Specify the effect of external writers/cutover explicitly; fresh query evidence
cannot make the SQL-to-Kubernetes interval atomic. Native inverses remain blocked
while original physical work is live or unresolved. Independent writer/storage
acceptance remains a deployment gate even after local software tests pass.

## Required tests and evidence

- Closed profile/policy bounds and exact complete descriptor/native/target/aggregate
  digest pins; absence/null/downgrade/substitution refusal.
- Native committed plus original Pending remains physical unresolved, escalates at
  the original deadline, and retains both costs with SQL inverse refused.
- Query reservation precedes I/O; concurrent workers cannot double-use a slot;
  crash/restart retains count/deadline/backoff; malformed or outage consumes a
  bounded slot and never authorizes mutation/retry/refund.
- Paused final mutation CAS loses to operating stop or deadline; no-worker deadline
  check refuses new mutation; original Pending stays unknown and query-only.
- Incident outbox retained before sink I/O; lost reply/restart deduplicates one
  owned incident; acknowledgement/closure cannot resolve physical unknown.
- Complete signed physical completion and positive closed no-effect classify
  correctly; omitted/wrong/stale/forged captures do not resolve; irreversible
  completion still blocks inverse.
- Real shipping controller/supervisor/recovery commands, actual peer SQL and real
  Kubernetes under unchanged five-second grant/transport and existing inverse
  windows; no fake clock in physical cases. Use short enrolled recovery policies
  for tests, never extend production windows to mask latency failures.
- Readonly SQL reservation query refuses original identity/fence/version/state/
  storage substitution, forward-row advancement, writer race and stale evidence;
  report the remaining observation-to-mutation interval honestly.
- Serialize operating history and complete physical aggregate, then independently
  replay with separately pinned trust and all hashes. Preserve failed frozen
  source attempts before any repair and require the complete unchanged-source
  corpus before a software qualification commit.

Independent custody, all writers, production maintenance, physical node failure,
accepted workload SLO and independent whole-saga/authority-peer decisions remain
external gates. This prerequisite design does not declare M8 complete.

## Reuse candidate found during source audit

The immutable existing kf_compensation.barrier function already joins the exact
snapshot, original retained committed forward and current locked resource, and
requires original incarnation/domain, expected post-version, original fence and
reservation value. Its BarrierObservation is a bounded typed response. Investigate
an explicitly registered readonly evidence adapter around this existing primitive
before adding migration 0003. Do not equate the inverse evaluator's barrier with
permission for physical dispatch, and do not omit protected storage generation or
the declared writer/restore boundary from new evidence trust. This is a reuse
candidate to qualify, not a completed current-reservation integration.


## Implementation milestones and exit evidence

| Increment | Concrete implementation | Exit evidence |
| --- | --- | --- |
| O1 closed record prerequisite | Versioned operating-policy/correlation/event types; strict bounded decoding; deterministic deadlines/backoff/query-slot planning; complete hash-linked replay | Negative profile/field/null/digest/clock/overflow tests; restart and bounded history replay; explicitly no execution enablement claim |
| O2 native enforcement and incidents | New protected managed enrollment binds policy at descriptor/native/target/aggregate boundaries; CAS query reservations and final mutation gate; durable incident outbox and bounded delivery | Real-etcd concurrent workers, paused mutation CAS versus stop/deadline, shipping restart and sink reply loss; native committed cannot resolve physical unknown |
| O3 current SQL evidence | Separately registered readonly original/current reservation query, storage-generation and writer-boundary pins, fresh exact-proposal provider integration | Actual peer SQL role refusal, changed incarnation/version/fence/reservation, intervening writer, restored storage and stale/substituted evidence negatives; unchanged migrations 0001/0002 |
| O4 combined software qualification | Shipping managed controller/supervisor/recovery and official SDK under real SQL/etcd/Kubernetes with complete independent physical/operating aggregate | Frozen-source full corpus; unknown at deadline retains costs and blocks inverse; positive no-effect/completion classification; bounded query-only restart and standalone CLI replay |

Every increment must update the implementation boundary to distinguish delivered
code from this proposed protocol. O1 alone cannot enable managed execution. O4
is local software qualification; independently administered custody/writers,
production maintenance, physical node failure, accepted SLOs and independent
whole-saga/authority peers remain external acceptance gates. Neither this RFC nor
a locally generated signature closes M8 or the overall current phase.

## O1 implementation boundary

The [record/replay guide](../PHYSICAL_OPERATING_RECORDS.md) specifies the closed
O1 types, 64+64 query budgets, checked backoff/deadlines, complete original signed
aggregate classification, hash-linked events and separately pinned signed offline
checkpoints. `kf-physical-operations` verifies serialized records without network
I/O or execution authority. In-memory query reservation and `stop_required` are
proposals/results, not durable CAS or proof of a stopped live controller. O2–O4
remain required before managed enablement. The guide links the frozen-source
software qualification record.

## O2 foundation implementation boundary

The [managed-drain foundation guide](../MANAGED_KUBERNETES_DRAIN.md) records the
concrete new named action `kubernetes.node.drain.managed` version `1.1` and profile
`KF-MANAGED-KUBE-DRAIN-0.2-draft`. The exact parameter schema binds enrollment and
mechanical contract digests; the legacy action/schema/adapter cannot substitute.
The native anchor is prepared with original dispatch, shared query slots use
expected-head CAS, and the explicit managed controller path binds current SQL
witnesses and operating proofs to acceptance/Pending and a separate final send
CAS. Stop retains an owned outbox independently of sink I/O. Delivery has durable
finite attempt slots and a stable report body; sink acknowledgement cannot resolve
physical unknown.

A query slot bounds one inventory-plus-SQL or complete-observation cycle, not
each individual Kubernetes GET. Control slots last at most five seconds and
observation slots at most thirty seconds, also clamped to their applicable
original grant/deadline/final observation boundary. Interrupted work consumes its
slot. The pure state machine refuses an early interrupted result; losing a send
check after mechanical Pending never creates no-effect or permission to resend.

The clock uncertainty is enrolled at 0–1000 ms and the maximum interval from
Pending authorization through final send checks is enrolled at 1–1000 ms. These
are local authorization checks, not a hard real-time physical cutoff or an
atomic SQL-to-Kubernetes interval. A separate deadline task cannot depend on
inventory or incident network I/O completing.

The version-0.2 current SQL source includes a protected shipping read-only service,
separate mTLS query/evidence roles and credentials, exact-proposal admission
evidence and native one-use read claims. It pins the database OID/postmaster
lifetime; restart/recreation requires new enrollment even if restored rows match.
The allocation reservation root and issued execution root are distinct and both
are bound by version-2 evidence. The foundation prototype 0.1/action 1.0 is not
silently upgraded. Protected head publication, a durable latest floor across
service restart and all declared writers/restore custody remain external gates. The named
admission obligation is mandatory in managed trust. Its separately pinned SQL
provider can be that evidence signer while remaining distinct from controller,
physical/operating/storage observers, incident sink and native authority roles.

The shipping protected controller configuration still selects the legacy
constructor, which refuses managed trust. The shipping read-only supervisor and
complete managed operating audit now carry and replay the per-CAS native/mechanical
prefix. Local managed completion and deadline/sink SIGKILL cases are covered.
Gateway/SDK, shipping managed controller configuration and wider native
concurrency/paused-CAS/closure/exhaustion qualification remain open. O2–O4 and M8
are not complete.

## O3 current SQL source verification boundary

Admission precedes the physical grant. Its separate preflight claim binds the
exact signed proposal, original committed SQL grant/attempt and protected native
family/phase heads before SQL I/O. Four claims per enrolled child are allowed;
failed or lost source work stays consumed. A successful retained reply may be
returned unchanged while fresh, without another SQL query or renewed expiry.
Native original dispatch compares the exact retained statement and proposal
evidence. Later Accept/Advance SQL reads consume one-use claims within the
already reserved shared operating slot; they cannot create inverse authority.

`kf-verify-current-reservation` replays historical source/storage signatures,
proposal evidence and retained admission/issuance authorization. It deliberately
does not attest the full native CAS prefix or physical effects. The live source
case uses the shipping service, actual peer SQL/native etcd, mTLS roles, unchanged
SQL rows, concurrent reads and restart replay refusal. It collects actual
Kubernetes availability separately and performs no managed physical mutation.
The separately implemented complete managed audit supplies native/mechanical
prefix carriage, and the read-only supervisor has protected shipping configuration.
Shipping managed controller and gateway/SDK integration, closure/race/exhaustion
and combined qualification remain required. O2–O4 and M8 remain incomplete.

## Managed supervision and audit implementation boundary

The managed operating format represents missing native receipt explicitly, without
changing the legacy O1 observation/receipt contract. A missing or committed native
acceptance never substitutes for complete physical classification. The read-only
shipping supervisor reserves complete observation cycles before I/O, bounds managed
captures, and runs deadline retention independently of source or sink I/O. Separate
bounded delivery attempts preserve the original incident/report identity across a
lost acknowledgement and process restart.

A physical capture includes the complete observer-attested original control prefix,
source claims and preflight evidence. Verification reconstructs mechanical signature
prefixes and supplements accepted/Pending authority with every final send authority
view. The outer complete operating bundle replays every referenced aggregate/ACK,
exact native event prefix and checkpoint with separately pinned trust. It reports
historical physical and operating times and never confers execution authority.
No recursive aggregate embedding, fabricated native receipt or renewed budget is
permitted. Missing source bodies and later control hidden by old capture refuse.

The controller's last pre-I/O check compares the just-verified send event, mechanical
Pending, source claim and all original native authority values, then samples the
protected clock again. Reusing immutable verification does not cache a successful
live comparison or extend the one-second maximum send interval. A failed check
retains unknown Pending and never authorizes another send.

Actual managed controller primitives plus shipping source/supervisor cases cover
completed cordon/eviction and original missing acceptance, original deadline,
withheld sink acknowledgement, SIGKILL/restart and complete offline replay. They
do not yet qualify shipping managed mutation configuration or named gateway/SDK,
all native concurrency/exhaustion/paused-send/closure cases or independent operator
acceptance. M8 remains incomplete.

### Pending original-dispatch carriage

A managed original dispatch can have no retained native outcome receipt. The
separate `KF-MANAGED-PENDING-OUTCOMES-0.1-draft`,
`KF-MANAGED-PENDING-LINEAGE-0.1-draft`,
`KF-MANAGED-PENDING-RESERVED-0.1-draft` and
`KF-MANAGED-PENDING-CONTROL-0.1-draft` supplements disclose that case explicitly.
They retain the actual managed grant and correlated claimed/dispatch journal,
carry zero receipts or receipt evidence, and report only pending. Enclosing
native observer checkpoints compare the disclosed context/journal, original
nonce and absent receipt head. Reservation events keep their original profile;
only the wrapper/checkpoint uses the new profile. This is observer-attested
absence, with no no-effect, completion, refund or inverse authorization. Existing
receipt-based formats remain unchanged.

### Acknowledgement retention conflicts

A valid signed sink reply must not be discarded merely because a concurrent
native write wins the retention CAS. Retrying local retention is bounded to three
comparisons of the same original outbox, delivery slot and acknowledgement, within
that slot's unchanged five-second expiry. Sample the protected clock after each
read and again before CAS. No new sink call, reservation or physical outcome
transition is permitted by this local retry. Exhausted or refused retention keeps
the consumed slot until expiry. The live restart case injects a real etcd epoch
change immediately before the ACK transaction and requires one refused CAS with
successful local retention on the same second delivery attempt.
