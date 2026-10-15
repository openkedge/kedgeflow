# RFC 0032: Durable hierarchical reservation conservation

- Status: Draft
- Profile/version: KF-COORDINATION-0.1-draft
- Milestone: M8a capacity-state prerequisite; saga/A2A/drain integration open
- Baseline: RFCs 0001–0004, 0016, 0023
- Owners/reviewers: unassigned

## Authority boundary

An operator enrolls a create-only root with tenant, conflict domain, resource/action
scope, a forward capacity and separately reserved compensation capacity. A trusted
root enrollment atomically installs a create-only tenant/conflict-domain marker
in the same authoritative namespace. A second root ID cannot create another budget
for that domain; every mutation compares the marker. Stopping does not free it.
A trusted
controller validates current policy/admission/delegation before using the library
ports. These ports are not agent APIs. This record is a reservation, never a signed
ExecutionGrant, admission certificate or target credential. Existing leaf runtime
continues refusing composite/saga grants until integration is qualified.

## Atomic conservation

One real-etcd record is bounded to 128 KiB, 256 allocations and nesting depth 8.
Each allocation binds an immutable admitted-operation digest, parent, narrower
action/resource scope and forward/compensation units. A2A/task/RPC IDs are not
allocation keys. Repeating the exact operation returns its original allocation;
changing any binding refuses. Compare the entire current record in one transaction.
Concurrent last-slot attempts cannot both allocate. Contention may refuse safely;
there is no optimistic local fallback.

Top-level sums fit the root's forward and compensation budgets independently.
Direct child sums fit their parent; deeper allocations spend their parent's held
budget, not additional global capacity. A parent becomes permanently composite
when it allocates a child and cannot consume as an executable leaf. All children
must narrow their parent's registered action/resource sets. Units are positive for
forward work; zero compensation is allowed. Overflow and malformed retained state
refuse. Revalidate conservation before every mutation.

Consumption binds one immutable attempt. Repeating that attempt is idempotent;
another attempt refuses. Unknown and committed consumption continue holding both
budgets. Only authoritative query may refine unknown to committed or proven
no-effect; this prerequisite records known states but supplies no automatic
refund, release, replacement, compensation dispatch or inverse authorization.
Stopping a root prevents new allocation/consumption while preserving status and
query-based refinement. Existing restore quarantine applies to every transaction.

## Remaining coordinated profile

Native authenticated controller/issuer/claim integration must compare current root
generation and allocation with the grant in the same authority transaction.
Authenticated A2A AgentCard capability activation/root-reference ACLs; durable
query-first orchestration; fresh compensation admission/applicability and accepted
late-effect barriers; a separately enrolled Kubernetes drain controller and real
observed Level C completion remain required. Uncordon does not restore evicted
workloads. No cross-cluster transfer/global capacity claim is supported.

## Verification

Real-etcd last-slot contention, exact operation replay and substitution, nested
scope/budget conservation, composite-parent consumption refusal, original attempt
reuse, unknown holding, stopped-root refusal and recreated-client status. Synthetic
scope enrollment is not proof of a complete production writer/predicate boundary.

## M8c1 checkpoint — 14 October 2026

[RFC 0040](0040-a2a-root-resolution.md) now supplies activated authenticated
root-reference resolution, immutable reader ACLs and narrowed non-authorizing
views through the native control service. It never calls these allocation or
consumption ports. Hierarchical executable grants, full A2A peers, saga and drain
remain open; RFC 0038/0039 native execution is still a root-level leaf.
