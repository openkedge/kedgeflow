# RFC 0041: Static hierarchical leaf authority

- Status: Draft
- Profiles: KF-HIERARCHICAL-LEAF-0.1-draft; KF-COMPOSITE-GRANT-0.1-draft
- Milestone: M8c2 bounded static hierarchical issuance/claim/dispatch
- Baseline: bcc7ef0; frozen v0.9 and RFCs 0032, 0038–0040
- Owners/reviewers: unassigned

## Problem and supported scope

A planner's reserved allowance must not also be executable while its children
spend it. This increment enrolls an immutable, independently signed hierarchy of
nonexecutable composite grants. Each freshly admitted leaf receives a separately
versioned issuer-signed hierarchical binding to its selected parent. Child cost
reservation and native grant/root/issuance/binding retention share one authority
transaction. A resource fence may be allocated earlier; a fence alone holds no
hierarchical capacity and conveys no execution permission.

This static profile supports one fixed executable action/resource/incarnation /
complete predicate/adapter/audience and fixed leaf costs. Composite scopes and
principal sets can be broader, but every child narrows them. Protected assignments
select the parent from the verified child's subject/workload; agents cannot pick
parent IDs, costs, roots or generations through HTTP or A2A task/reference fields.
Recursive live delegation, dynamic parent allocation/replacement, multi-resource
execution, compensation and cross-cluster transfer remain unsupported.

## Signed contracts and trust

`spec/drafts/hierarchical-leaf-v0.1.schema.json` defines closed composite grants,
hierarchy configuration and hierarchical reservation bindings. Composite grants
bind tenant/domain, budget root/generation 1, parent signed-grant digest or null,
policy/ownership, exact executable-scope digest, allowed action/resource sets,
subject/workload principals, forward/compensation units and validity interval.
They explicitly declare `execution_authority: false`. Their digest is
`digest("hierarchical-composite-grant", signed_record)`; signatures use a distinct
`KedgeFlow:KF-COMPOSITE-GRANT-0.1-draft\0` domain followed by canonical unsigned
envelope fields. Protected delegation keys are separate from leaf issuer,
admission and all registered input/evidence roles. This key authorizes the static
composite skeleton; it does not produce admission certificates or executable leaves.

Every nested composite has narrower scope/principals, the same root/generation /
policy/ownership/executable contract, a contained validity interval and conserved
costs. The skeleton has at most 16 composites/assignments and seven composite
levels, leaving room for a leaf under RFC 0032's depth-eight limit. Cycles, missing
parents, duplicate records/principals/assignments, overdraw and overflow refuse.
All static composite allocations are irreversibly `composite`, never executable.
Signed scope arrays MUST be unique and in ascending UTF-8 byte order. Receivers
reject reordered arrays/duplicate fields before typed set normalization, so the
signature authenticates the received canonical JSON value without reinterpretation.

The `reservation` registration selects `KF-HIERARCHICAL-LEAF-0.1-draft` and includes
an explicit `hierarchy` object. Other reservation profiles refuse that object;
this profile refuses its omission. Absent legacy fields retain exactly the old
serialization/digests. Raw schemas validate scope arrays before set decoding.
No frozen grant, fixture or receipt field changes.

## Enrollment and native authority

Privileged create-only enrollment atomically creates the coordination snapshot
with conserved composite allocations, domain/native-required markers and original
signed composite records. Existing roots cannot be upgraded or adopted. Every
live native gate checks the immutable skeleton, original records and current
snapshot in its CAS comparisons. Missing/corrupt records or configuration omission
refuse; there is no inferred parent or unreserved fallback. RFC 0032 state-only
mutation ports refuse this profile, including stop; use native permanent stop.
Root stop is the revocation mechanism for this version. Branch revocation,
rotation, replacement, reactivation and generation changes are unsupported.

The native issuer verifies the ordinary complete signed admission chain and
retained certificate, independently of the parent. It selects the configured
assignment from the verified subject/workload, verifies narrower leaf scope and
identity, fixed cost and validity contained in every ancestor, and checks live
root/control/policy/ownership/review/lease/restore authority. The grant cannot
outlive its ancestor; overlong certificates refuse rather than broaden authority.

The resource-fence transaction retains only the stable operation/fence. Then one
native issuance transaction allocates the immutable leaf under its parent and
retains the exact leaf grant/root, global admitted-operation issuance key,
certificate correlation, signed hierarchical binding and native seal/index.
There is no capacity allocation without that grant in this profile. A failed or
ambiguous transaction cannot authorize speculative execution or a refund.

The hierarchical binding uses `KF-HIERARCHICAL-LEAF-0.1-draft` as both profile and
signature domain. In addition to RFC 0038's immutable fields it requires the
selected `parent_grant_digest`; its allocation digest includes that same parent.
The existing frozen leaf grant remains nondelegated on the wire. It is the
executable leaf component of this explicit compound profile, not a standalone
hierarchical capability. The enrolled ledger requires the matching retained signed
hierarchical binding at issuance reuse, claim and dispatch. The frozen verifier
continues refusing `parent_grant_digest`/saga execution variants and composite
records. Native marker comparisons prevent omission of the compound profile from
bypassing it. This supplements the frozen format instead of reinterpreting it.

Claim atomically marks the leaf unknown with one original attempt and consumes
the ordinary native nonce/root. Dispatch rechecks the active root, original
composite lineage/records, signed leaf binding, allocation and original attempt
with current native control checks. Composite parents cannot claim or dispatch.
All known/unknown child costs remain held. Stop racing any authority transaction
invalidates its snapshot comparison; it cannot undo an earlier authorized send.
The existing A2A resolver can disclose the scoped state, but neither its views nor
new task/context/request IDs create or duplicate a child.

## Failure, compatibility and retention

Keep the stable operation key across issuer restart and lost replies. A retry
returns the original grant/fence/parent/costs; a changed binding refuses. Concurrent
last-slot contenders cannot both issue. Distinguish a harmless reserved fence from
a retained issued grant. Raw issuance/replacement and state-only allocation cannot
synthesize hierarchical authority. Retain original composite records and leaf
bindings for the existing replay horizon; no expiry-based deletion/refund.

Legacy v0.1/v0.2 roots retain their existing allocation/history behavior. The new
profile is not an upgrade to v0.2 and does not claim its complete budget history.
Native recovery can retain ordinary signed outcomes, while hierarchical budget
classification stays unknown/held. Existing lineage exporters refuse this profile;
M8c3 must add bounded complete hierarchy replay and outcome refinement. Offline
binding verification proves signed static lineage and leaf correlation only,
never reconstructed admission inputs/role history, live root activity, consumption,
control freshness or an actual target effect.

## Implementation and acceptance

`hierarchical_leaf.rs` verifies signed static hierarchy, assignments and live
snapshot invariants. `reserved_leaf.rs` adds explicit profile enrollment,
compound bindings and gates. `ledger.rs` separates early fence retention from
atomic hierarchical cost/issuance. Existing control/gateway/recovery configuration
and operator enrollment/stop load the same protected registration; the offline
reservation CLI recognizes the explicit profile. Ordinary MCP leaf carriage can
stay unchanged because the authoritative ledger requires the compound binding.

Required native tests: fresh managed admission/issuance; nested/parallel conserved
children and last-slot contention; original operation/parent/fence after restart;
scope/identity/time/cost/signature/role/profile substitution; composite execution
and raw-port refusal; missing/tampered static records and snapshot; stop races at
allocation/issuance/claim/dispatch; recovery without refunds; shipping CLI and
actual SDK/native TLS/etcd composition. Preserve the legacy corpus and frozen
artifacts. Record complete source-pinned conformance evidence and explicit limits.

## Remaining milestones

M8c3: complete signed hierarchical allocation/claim/dispatch/outcome history,
bounded exhaustion rules and independent replay. Further delegation needs a live
admitted-parent/delegation protocol and separately qualified scope variants.
M8d/M8e: durable saga/compensation and actual governed Kubernetes drain. Independent
A2A peers, accepted writer/predicate coverage, production custody/clock/storage,
hardware and enterprise/release acceptance remain open.
