# RFC 0038: Native reserved leaf issuance and claim

- Status: Draft
- Profile: KF-RESERVED-LEAF-0.1-draft
- Milestone: M8b1 fixed-cost native leaf integration
- Baseline: 1a3f42a; RFCs 0003–0006, 0016, 0032
- Owners/reviewers: unassigned

## Scope and enrollment

Opt in to a fixed-cost, root-level, single-resource leaf reservation under the
existing complete conflict domain. Independently pin tenant, create-only budget
root, generation one, exact action/resource/incarnation/audience/predicate/adapter
scope, policy/ownership, forward/compensation budgets and per-operation costs,
and issuer keys. Require managed control. Root IDs, allocation IDs, units and
parent choices are never agent HTTP fields. Frozen leaf grants and HTTP requests
remain unchanged; composite/saga/compensation execution remains unsupported.

Operator enrollment atomically creates the RFC 0032 snapshot/domain budget marker
and a native required marker at the enforcement domain. Native authority paths
compare this marker even when their configuration omits the profile. They cannot
fall back to ordinary unreserved authority. Existing roots/operations require an
approved migration; no automatic upgrade, reset, replacement or generation bump
is provided. Stop is permanent in this profile and preserves all held budgets.

## Issuance and immutable binding

Only the native producer with independently verified full admission inputs can
issue a reserved leaf. Allocate the configured units under the stable admitted
operation key in the same transaction as the resource fence. Recreated issuers
reuse that allocation and fence; failures after allocation hold capacity and do
not refund it. Last-slot competitors cannot both allocate. Fresh current control,
review and lease checks remain independent.

The issuer signs a closed reservation-binding supplement under its approved grant
role. Bind the exact grant/certificate digests, operation key, root/generation,
registration digest and immutable allocation digest. Retain the binding atomically
with grant/root/issuance creation, under both grant digest and root/operation seal.
Missing or changed bindings refuse. Ordinary trusted-context/raw-grant issuance
ports cannot synthesize the supplement. Native issuance reuse rechecks current
budget state and the original signed binding.

RFC 0032 library ports compare the operation seal: a sealed allocation cannot
become a composite parent or be consumed/refined outside the native execution
path. Unrelated library allocations still conserve the same budget.

## Claim, dispatch and recovery

Verify the exact issuer-signed binding against independently approved registration
and the presented verified frozen grant. Require an active generation-one root,
matching immutable leaf allocation and both retained seal/index records. Claim
changes the allocation to unknown with the original attempt ID in the same
transaction that consumes the leaf nonce/root and records execution context.
Competing claims cannot both consume. Composite allocations cannot execute.

Dispatch compares the active root and exact original unknown allocation/attempt
again with the signed binding. Stop before claim or dispatch blocks new work;
stop raced against a transaction makes its comparison fail. Unknown allocations
and both budgets remain held after lost replies, known outcomes and stop. Native
outcome-to-reservation refinement is subsequent work; no timer refund, replacement,
compensation or blind retry is introduced. Status remains query-only after expiry /
stop. Existing restore quarantine covers every mutation.

## Compatibility and qualification

Legacy unenrolled domains compare absence of the required marker and keep existing
wire behavior. An enrolled domain refuses omitted configuration, missing/bad
signatures, changed pins/units/scope/attempt, low-level issuance and generation
replacement. Pre-enrollment grants cannot acquire a reservation by synthesis.
An authorized operator may read/independently verify the retained signed binding;
it proves an issuer statement, not current budget permission or consensus.
Existing lineage carriage does not contain budget history: reserved export must
refuse until an explicitly versioned supplement is implemented.

Qualify actual native mTLS/DPoP/managed control/etcd admission and issuance, one
last slot across competing proposals, immutable retry/recreation, seal/library
bypass refusal, original claim/unknown holding, stopped-root and transaction race
refusal, offline binding substitutions and unchanged legacy corpus. Exercise the
shipping operator CLI. Record software fixtures separately from accepted writer /
predicate coverage, production custody and physical failures.

Remaining M8 work: versioned reserved history, native known-outcome refinement,
hierarchical/composite grants, A2A, durable saga and compensation contracts, and
actual governed Kubernetes drain. Cross-cluster transfer and global coordination
are outside this profile. M7 ceremony and enterprise owner acceptance remain open.
