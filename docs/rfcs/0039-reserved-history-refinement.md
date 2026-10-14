# RFC 0039: Reserved history and native outcome refinement

- Status: Draft
- Profiles: KF-RESERVED-LEAF-0.2-draft; KF-RESERVED-LINEAGE-0.1-draft
- Milestone: M8b2
- Baseline: 0334e9a; RFCs 0010, 0012, 0016, 0032, 0038
- Owners/reviewers: unassigned

## Explicit opt-in

Use the same approved registration shape with reserved leaf profile v0.2. Keep
v0.1 bytes, semantics and unknown holding unchanged. Registration, root, scope,
costs, issuer keys and generation are immutable. No implicit upgrade, synthesized
history, replacement, reactivation or refund is provided. v0.2 enrollment creates
an empty active snapshot and history genesis together. Services without exact
approved configuration cannot create authority in an enrolled domain.

## Atomic bounded history

Retain a create-only, contiguous, hash-linked per-budget history. Each event binds
registration digest, sequence, previous digest, phase, operation/attempt context
and the resulting full conserved snapshot. Allocation also binds its exact fence;
verification checks increasing allocations and issuer-grant equality. Append allocation with the fence,
issuer binding with grant issuance, unknown consumption with claim and dispatch
comparison with dispatch authorization, in their original etcd transactions.
Record permanent stop without clearing held allocations. Exact retries append
nothing. History head and snapshot comparisons serialize competing operations.
Missing/corrupt current head or snapshot refuses authority; gaps in older events
refuse complete historical export. Older state-only coordination
mutation ports refuse v0.2 roots. Queries remain non-authorizing.

Bound history to 256 events, each snapshot to 128 KiB and exported carriage to
64 MiB. Reserve the final event for stop. Exhaustion refuses new authority rather
than truncating history. Repeated stop is read-only. Every mutation still passes
through the existing optional independent restore quarantine; this does not
qualify physical restore or repair of old roots.

## Original-attempt refinement

Only native recovery retaining an OutcomeService-signed receipt can refine a
v0.2 allocation from unknown. In the receipt/outcome CAS, compare original nonce,
root, execution context, allocation/attempt, immutable issuer binding, current
budget snapshot and history head; retain the resulting budget/history together.
Permit reported committed, or proven no effect only when dispatch authorization
is absent and the original pre-dispatch attempt is sealed atomically. A dispatch
intent, missing query, not-found, pending, timeout or uncertain failure remains
unknown. Never refine another attempt or reverse a known result. A stopped budget
can still accumulate query-only resolution of an already consumed attempt.
Forward and compensation costs never change or return to free capacity.

## Versioned historical carriage

A new reserved-lineage wrapper carries existing signed admission/outcome lineage,
issuer reservation binding and complete budget history, plus a separate observer
checkpoint covering their exact digests, approved namespace/root/registration and
captured head. Checkpoint signatures are observer attestations, not etcd consensus
proofs. Independent public verifier trust pins the complete registration, observer
identity/namespace/key and existing admission/issuer/outcome roles. Reject role
key overlap, omitted/reordered/forked events, wrong pins, invalid transitions,
reused operations/attempts, scope/cost widening, missing authority phases and
substituted signed outcomes. Re-evaluate admission lineage and correlate the
selected attempt's refinement receipt with the retained outcome chain.

Legacy reserved exports continue to refuse through the unversioned API. The
new wrapper is privileged operator disclosure, never an agent capability. Its
closed bounded decoder and shipping offline CLI report the historical budget
classification, both held allowances and explicit runtime/observer/writer gaps.
Approved history from another root, namespace or role cannot satisfy verification.

## Qualification and remaining gates

Exercise real etcd with native managed producer/consumer transactions, concurrent
operations, allocation/claim/dispatch/stop races, receipt races, query-only late
resolution after stop/expiry, original-attempt preservation, missing/corrupt
history, retry/recreation and history exhaustion. Verify an official SDK workflow
and shipping recovery/offline verifier configuration. Negative carriage must fail
with both invalid and correctly re-signed observer checkpoints.

This is a software qualification. Physical storage/custody, accepted writer and
predicate coverage, hardware and independent release acceptance remain open.
Hierarchical execution grants, A2A, saga, compensation and actual Kubernetes drain
remain subsequent M8 work. Admission/governance history gaps from the existing
inner lineage remain explicit; no signed target effect is invented.
