# RFC 0043: Durable query-first saga observation

- Status: Draft
- Profile: KF-SAGA-OBSERVATION-0.1-draft
- Milestone: M8d1; execution and compensation remain M8d2/M8d3
- Baseline: 53abc13; RFCs 0039, 0041 and 0042; frozen v0.9
- Owners/reviewers: unassigned

## Problem and scope

A restarted orchestrator must recover the original forward operations and their
known or unresolved effects before considering compensation. This prerequisite
retains a protected, bounded DAG, stable admitted-operation identities, registered
inverse intent and a durable journal of verified observations. It offers no
admission, issuance, claim, dispatch, inverse execution or refund capability.
Dependency edges describe protected intent; the existing leaf runtime does not
enforce DAG ordering. Observed ordering violations require operator attention.

The observer supports one dedicated, freshly enrolled audited static hierarchy
and its fixed executable contract. At most eight nodes refer to independently
approved subject/workload assignments. Existing executable grants continue to
reject saga fields. Temporal integration, live DAG edits, dynamic delegation,
cross-root transactions and actual inverse execution are excluded.

## Authority and trust

The operator approves the plan and complete `reserved_lineage::Trust`: original
registration, namespace, historical policy/input/admission/issuer/outcome pins,
subject set and distinct delegation/observer roles. No signer or target URL comes
from observed records. Etcd TLS/credentials and optional restore gating remain
deployment responsibilities. This observer needs no signing key, target credential
or target mutation client. It queries retained native authority/outcome records;
the existing query-only recovery worker separately resolves uncertain targets.

An inverse registration pins its full proposed scope on the forward resource /
incarnation and conflict domain, semantic/applicability/late-effect-barrier digests,
and compensation units within the forward leaf's held allowance. These pins
register intent only. A committed forward outcome still yields
`requires_fresh_admission_and_barrier`, never executable permission. Unknown,
pending, not-found, failed and dispatched no-effect wording cannot enable an
inverse. Neither a timeout nor an operator's compensation request proves an effect.

## Closed contract and enrollment

`spec/drafts/saga-observation-v0.1.schema.json` defines a closed plan, snapshot,
journal event and head. Plans bind an immutable saga ID, exact reservation
registration digest, node IDs, unique stable operation keys, principal assignments,
dependency edges and optional inverse registrations. No A2A/task/RPC ID is an
operation identity. Refuse cycles, duplicate/dangling edges, duplicate operations,
widened principals, unsupported registration profiles, impossible hypothetical
capacity and inverse costs exceeding the fixed leaf compensation reservation.

Enrollment compares active native root/history/original composite records and
requires that only the static skeleton exists: no previously issued child may be
adopted. One transaction retains the plan, genesis state/event/head, one permanent
root-to-saga marker and operation ownership markers. Markers bind a digest of the
complete approved historical trust (including evidence/review/lease definitions,
policy, subject/workload/scope, all role keys, source and observer identity).
Changed trust refuses even status; there is no implicit key/policy rotation. Exact enrollment replay reads
the original state; changed plan/root/operation ownership refuses. Admission
preparation alone is allowed before enrollment; it cannot execute or spend costs.
Plan enrollment itself allocates no execution capacity. Native leaf issuance
still holds its forward and compensation costs before claim. Whole-DAG capacity
is checked hypothetically, not exclusively reserved against other native callers.
Unplanned leaves on this dedicated root refuse reconciliation.

## Reconciliation and durability

Always resolve the same operation key. Absence remains `planned` with
`execution_authority: false`; it never authorizes reissuance or resend. An issued
leaf must have its original retained admission inputs/certificate/issuance,
matching protected principal, native parent binding and held costs. Reevaluate
the signed inputs and Cedar policy at original admission/issuance times.

Claimed leaves retain their original attempt and remain unknown until a verified
native receipt chain and audited budget classification agree. Committed becomes
`committed`; a signed pre-send outcome with budget `proven_no_effect` becomes
`proven_no_effect`. Failed receipts stay held and require operator handling.
Dispatched uncertainty stays `unknown`, including no-effect wording. Unsigned
gateway success alone remains unknown until native recovery signs its receipt.

Reconciliation writes only observer state, immutable proof blobs and a hash-linked
journal event/head. Compare original plan/root/operation markers, native snapshot /
history/composites/bindings, exact retained issuance and current attempt/outbox /
receipt head, and the prior observer state/head/latest event. Concurrent progress
or restore quarantine refuses stale writes. There is no local fallback or blind
mutation retry. Recreated processes requery the original identities.

Grant, attempt and terminal outcome cannot be replaced or rolled back. A retained
receipt must remain in the complete original predecessor chain. Compensation
requests are durable, one-way intent; repeat requests/reconciliation with no
change append nothing. Every registered inverse remains blocked. Dependency
satisfaction describes current observed predecessors; a violation observed on an
already-issued node remains recorded, even if a predecessor later commits.

## Bounds, history and compatibility

Plan/snapshot: 64 KiB each; proof blob: 64 KiB; event: 128 KiB; journal: 128
events. Deduplicate identical native comparisons and bound transactions to 96 comparisons,
32 operations and 1 MiB before
writing. Exhaustion refuses changed observations without pruning, capacity release
or authority replacement. Status validates the retained head/latest snapshot;
complete history reads refuse missing, reordered or inconsistent older events.
Canonical digests use separate `saga-observation-*` domain labels. Duplicate JSON
fields/unsafe integers and unknown fields refuse before typed decoding.

This profile is additive observer state, not a saga execution enrollment. Older
leaf services may continue enforcing their own native profiles; they do not enforce
this plan's dependencies or inverse intent. Never advertise this as a complete
saga runner. Existing root/leaf history formats and frozen fixtures stay unchanged.
Status/history are custody-dependent records without a new observer signature or
independent consensus/physical-effect claim.

## Implementation and acceptance

Implement the bounded plan/state machine, native retained-proof reconciliation,
create-only identity markers, monotonic journal and shipping `kf-saga` operator
commands. Require real-etcd/TLS tests for restart, exact operation reuse, changed
plans/keys/roles, unknown holding, original committed/no-effect receipts, partial
forward outcomes, blocked inverses, concurrent observers, stale outcome CAS,
missing/tampered/exhausted history and shipping CLI lifecycle. Preserve the full
existing corpus and source-pinned verification evidence.

## Remaining M8d milestones

M8d2 must define an explicit executable saga profile with native dependency and
compensation admission/issuance/claim/dispatch comparisons. A registered inverse
needs independently accepted applicability, fresh admission, reserved compensation
spend, exact original forward correlation and an accepted late-effect barrier.
Existing fixed-contract roots cannot silently become inverse-capable.

M8d3 must qualify the actual inverse target, late commits, partial compensation,
compensation failure/unknown, process loss and independent complete saga replay.
Unknown forward effects never trigger inverse execution. Kubernetes drain remains
M8e; physical custody/writer acceptance, independent peers and release remain open.
