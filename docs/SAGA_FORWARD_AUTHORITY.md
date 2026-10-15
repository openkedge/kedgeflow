# Native forward-saga authority — M8d2a

[RFC 0044](rfcs/0044-native-forward-saga.md) adds an explicit fresh-root draft:
`KF-SAGA-FORWARD-0.1-draft`. A protected DAG of at most eight fixed operations
reserves all leaf forward and compensation costs at enrollment. Each node then
needs its own fresh input verification, policy admission and signed grant/binding.
Native admission, fence/issuance/reuse, claim and dispatch require every direct
predecessor's original signed committed outcome and matching audited budget state.
Pending, unknown, not-found, failed and proven-no-effect do not enable successors.
Independent ready branches may progress without each other's outcomes.

This supplies software forward dependency gates. An orchestrator still proposes
each fixed operation; there is no autonomous workflow runner or inverse execution.
The RFC 0043 observer keeps its separate query-only contract and cannot adopt this
profile. Dynamic plans, key migration, cross-root transfer and production acceptance
remain open.

## Configure a new root

Use [the registration example](../config/saga-forward.example.json) as a structural
example only. Its fixed operation digests and synthetic public pins are illustrative;
it cannot authorize a deployment. Approve the exact operation identities, subject /
workload, descriptor/resource/incarnation, policy, costs, signed static parents and
validity interval before enrollment. Derive each stable operation key from tenant,
subject, workload and proposal QID through the existing admission identity contract.
A changed QID is an unplanned operation and refuses admission.

Set the registration's `profile` to the new name and include both `hierarchy` and
`saga`. Other profiles reject a present saga; null or omitted fields refuse. Pin
OutcomeService keys/source separately from input/evidence, admission, leaf issuer
and composite-delegation signers. Saga validity must fit every assigned parent's
ancestry. Every issued leaf validity must fit the saga. Independently approve
matching lineage trust; exported keys never create trust.

Install the identical protected registration at the control, gateway and recovery
services via their existing reservation configuration. `kf-control --check` checks
local protected material; `--enroll-reservation` atomically creates the plan, static
parents, complete preallocation, domain marker and history genesis. Re-enrollment,
adoption and replacement refuse. Old roots cannot upgrade to this profile.

## Execute and recover original operations

Use the existing Agent Adapter/admission/issuer/gateway path for each planned QID.
A successful grant includes a separately signed reservation binding with exact saga
ID, node ID, plan digest, principal's parent and complete registration digest. Frozen
executable grants still require null parent/saga fields. The native compound profile
is mandatory; raw issuance and allocation cannot bypass it.

Each successor authority transaction compares the original predecessor issuance,
admission chain, binding/seal, attempt/outbox/context, signed complete receipt chain,
receipt evidence/head, original saga plan and budget/history state. Missing proofs
or a concurrent stop refuse a stale write. Comparison bounds may refuse a larger
otherwise valid plan; there is no blind fallback. Resolve an ambiguous reply under
the same original operation instead of issuing or sending a replacement.

Use the existing `kf-recover` worker with the exact pinned outcome key/source.
Gateway success alone does not refine a predecessor. Native signed original-outcome
recovery produces committed or pre-send no-effect budget state. Both costs remain
held after any outcome, stop or expiry. `kf-control --stop-reservation` permanently
blocks further forward authority; original recovery and historical export continue.

## Verify history and understand limits

`kf-verify-reservation` verifies the new signed issuer statement using protected
registration and original grant. It supplies no live execution permission.
`kf-verify-reserved-lineage` accepts the separately identified
`KF-SAGA-FORWARD-LINEAGE-0.1-draft` wrapper. Its genesis includes every planned leaf;
issue adds no capacity. Replay verifies all issued admissions and requires signed
committed predecessor refinement before successor issue, claim and dispatch.
Unissued nodes remain held without invented grants. Existing history/export bounds
and observer/custody/clock trust gaps apply. Offline history does not attest the live
admission CAS or any physical target effect.

[Verification](../results/verification/rfc-m8-saga-forward-2026-10-15/README.md)
retains native dependency/parallel, refusal, proof-deletion and stop CAS races, shipping
operator/offline CLIs and official SDK normal/lost-reply/query-only restart coverage.
The previous profiles, schema, paper, fixtures and verification records are preserved.

M8d2b remains next: an inverse-capable CTD/adapter contract, accepted applicability
and late-effect barriers, fresh compensation admission, deadlines and atomic use of
held compensation authority. M8d3 must qualify the actual inverse, late effects,
partial/failed/unknown compensation and complete independent saga evidence. M8e
adds actual governed drain. Enterprise/writer/physical and release gates stay open.
