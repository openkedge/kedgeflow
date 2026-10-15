# RFC 0042: Retained static hierarchy and outcome history

- Status: Draft
- Profiles: KF-HIERARCHICAL-LEAF-0.2-draft; KF-HIERARCHICAL-LINEAGE-0.1-draft
- Milestone: M8c3
- Baseline: 6b7a9bf; RFCs 0039 and 0041; frozen v0.9
- Owners/reviewers: unassigned

## Problem and scope

RFC 0041 enforces static ancestry and capacity but leaves consumed budgets
unknown even after a known outcome. This opt-in profile retains complete bounded
hierarchy history and refines original leaves using native signed receipts.
Independent offline replay checks the original signed skeleton, every issued
leaf's admission inputs/certificate/grant/binding, conservation, original attempt,
dispatch, permanent stop and outcome. Costs are never refunded.

The executable contract, static graph and subject/workload assignments retain
RFC 0041's bounds. Dynamic delegation, branch replacement, generation changes,
sagas, compensation execution and cross-cluster transfer remain unsupported.

## Authority and trust

Protected registration selects the new leaf profile before create-only enrollment.
Composite and binding signatures retain RFC 0041's formats and signature domains;
the registration digest binds the new history requirement. Delegation pins must
be distinct from input, admission, issuer, outcome and observer roles. The
verifier independently approves the complete registration, namespace, historical
policy/input/issuer/outcome pins and observer identity/key. Exported keys never
create trust. The observer attests a retained snapshot, not ledger consensus,
runtime authentication, physical target effects or permission to execute.

## Contract

The history/checkpoint/bundle profile is
`KF-HIERARCHICAL-LINEAGE-0.1-draft`, with a separate closed local schema.
Canonical event/state/inner-lineage digests retain RFC 0039's domain labels;
profile fields provide separation. Checkpoints sign
`KedgeFlow:KF-HIERARCHICAL-LINEAGE-0.1-draft\0` followed by canonical unsigned
checkpoint fields. A new checkpoint digest binds the exact complete map of
per-operation authorization proofs, including unclaimed leaves. Each proof
contains the original retained admission record, raw signed inputs, issuance
record and, when applicable, both original lease-authority bindings.

Genesis contains exactly the signed static composite skeleton. An `issue` event
atomically adds one allocated leaf and retains its signed grant/binding and
original positive safe-integer fence, alongside ordinary issuance and native
authority records. There is no separate capacity `allocate` event. Fences are
unique across issued leaves but issuance order may differ from earlier fence
allocation order; gaps carry no capacity. Reuse produces no second event.
Every issued operation must have exactly one matching authorization proof;
missing, extra or substituted proofs refuse. Historical inputs and Cedar policy
are reevaluated at original admission/issuance times for every leaf. Exact workload
identity comes from independently approved subject/workload assignments; the
historical subject set and all shared signer/policy pins must also be approved.

Claim changes only allocated to unknown and binds the original attempt. Dispatch
requires that claim and an active root. Stop is permanent and changes no costs.
A correlated native signed committed receipt refines unknown to committed only
after dispatch. A signed pre-send not-dispatched receipt refines to proven-no-effect
only with an atomic absent-dispatch-journal comparison. A dispatched unknown,
pending, not-found or not-dispatched result stays unknown. Known classifications
cannot reverse, repeat refinement or release any forward/compensation allowance.

All authority and refinement transactions compare the original composite records,
snapshot, history head and last event. History is hash linked, create only and
bounded to 256 events, 256 KiB/event and 128 KiB/snapshot. Event 256 is reserved
for stop. Exhaustion refuses further mutations without pruning or refunds.
Complete exports refuse any missing event or authorization record, check every
transition and hold an exact final root/head comparison. Bundles are at most
64 MiB; each authorization proof is at most 16 MiB, with at most 256 proofs.
Closed raw schemas and strict duplicate-field/safe-integer parsing precede set
decoding. Signed composite scope order remains significant as in RFC 0041.

## Failure and retry

Uncertain replies require lookup of the original operation/grant/attempt.
Contention may refuse and be retried by the trusted caller after lookup; it never
authorizes speculative execution. Missing/corrupt/exhausted history or original
records fails closed. Recovery without the exact audited registration refuses;
it cannot silently retain an outcome without the required budget transition.
Stop racing issuance, claim or dispatch invalidates the stale transaction.
Receipt CAS racing dispatch cannot manufacture a pre-send no-effect proof.

## Compatibility and rollout

Fresh roots only: an existing enrollment cannot be upgraded, adopted or reset.
Hierarchical 0.1 retains its unknown/held behavior and refuses audited export.
Reserved-leaf 0.1/0.2 and their lineage bytes/semantics remain unchanged. The
existing reserved-lineage CLI accepts either explicitly selected audited profile;
profile substitution refuses. Frozen executable grants continue refusing parent
and saga fields. No agent-facing allocation/refund API is added.

## Implementation and acceptance

Extend native reservation history/refinement and hierarchical snapshot guards;
share historical admission verification with ordinary lineage. Extend the
reserved-lineage exporter/verifier and CLI using explicit profile dispatch.
Required tests cover atomic issue/history/cost, original static ancestry,
all-leaf proofs, conservation and correctly re-signed semantic negatives,
pre-send/committed refinement, unknown/no refunds, exhaustion/corruption,
contention/stop/dispatch/receipt races, shipping CLIs and official SDK recovery.
Run the complete source-pinned corpus and retain explicit deployment limits.

## Open decisions

Owner review, independent implementations/A2A peers, deployment custody and
writer/predicate acceptance remain open. Later profiles must qualify dynamic
delegation and broader executable contracts independently. M8d follows with
durable saga/compensation; M8e follows with actual governed drain and Level C
physical limits.
