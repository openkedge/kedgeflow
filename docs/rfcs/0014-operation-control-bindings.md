# RFC 0014: Operation-bound control comparisons

- Status: Draft
- Profile: `KF-CONTROL-BINDINGS-0.1-draft`
- Milestone: bounded M4b4
- Baseline: `44c44c2`; RFCs 0012 and 0013
- Owners/reviewers: unassigned; runtime, policy and security owners

## Contract

Admission, admitted issuance, claim and dispatch authorization retain an immutable
control binding in the same etcd transaction as the authority transition. The
binding identifies the phase, certificate or grant digest, optional attempt ID,
observed governance head sequence/digest, installation and acknowledgement digests,
authority clock sample and exact revocation targets compared absent. Admission
compares the domain target; later transitions compare domain, root and grant.

The control read includes the history head in its linearizable snapshot. The final
authority CAS compares that exact head, installation, acknowledgement, managed
marker and absence of applicable revocations. Governance appends update the head
atomically, so a concurrent mutation invalidates the pending comparison. Retained
bindings require absent keys; failed transactions and idempotent admission/issuance
lookups cannot overwrite the original binding. Unmanaged legacy authority retains
no binding and cannot export this supplement. Managed state without history refuses
these transitions; migration is a separate contract.

## Export and authentication

A privileged operator exports RFC 0013 history plus three or four bindings:
admission, issuance, claim and dispatch when the retained journal contains that
phase. Missing or unexpected dispatch bindings refuse. A separate observer
attestation binds the exact history bundle and ordered binding array, operation
key, tenant, namespace, grant digest, attempt, observer identity and capture time.
Sign canonical profile/kind/key_id/payload with domain
`KedgeFlow:KF-CONTROL-BINDINGS-0.1-draft\0`; kind is `operation_bindings`.
Use `control-bindings-history` and `control-bindings-records` digest domains.

The existing public history trust independently approves the observer and all
historical registrations and signing roles. The new closed bundle is bounded to
40 MiB, reuses the bounded RFC 0013 decoder and permits exactly 3–4 bindings.
`kf-verify-control-bindings --trust FILE --bundle FILE` runs offline.

## Verification

Authenticate both observer assertions and the original signed lineage/governance
chain. For each phase, bind the exact operation authority digest and attempt,
require nondecreasing history sequences and clock samples, and locate the named
head within the authenticated prefix. Replay through that sequence to obtain the
latest installation and acknowledgement and applicable revocations. Require exact
digests, operation scope/policy/ownership/trust/issuer membership, acknowledgement
validity at the checked clock, and exact compared-absent target coverage. Any
applicable revocation already present at that sequence refuses, even with an
observer signature. Later revocations do not invalidate earlier historical
observations. Equal millisecond times do not determine governance ordering.

Checked times must be within signed certificate/grant lifetimes and follow the
signed admission/issuance samples. Claim and dispatch are correlated with their
retained journal times. Capture must cover all observed clocks. Verification
returns observer-attested historical control comparisons, never live permission.

## Acceptance and boundaries

Qualify native authenticated governance plus actual etcd admission, issuance,
claim and dispatch CAS; acknowledgement renewal between phases; same-clock later
revocation; retries and failed transitions; independently re-signed incorrect
snapshots, omissions, substitutions, sequence rollback, target coverage and expiry;
missing legacy retention; a separate offline CLI process after expiry.

This authenticates the observer's assertion about retained transaction records.
It is not a consensus proof, trusted clock, authenticated fence allocation or
target commit proof. Operator disclosure/RBAC, protected observer deployment,
pagination, independent peers, hard crashes, backup restore fencing and M4/M5
enterprise release acceptance remain open. Frozen wire contracts and RFC 0013
carriage/signing domains remain unchanged.
