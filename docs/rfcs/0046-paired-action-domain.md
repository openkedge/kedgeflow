# RFC 0046: Paired action domains with one physical resource fence

- Status: Draft
- Profile: KF-PAIRED-ACTION-DOMAIN-0.1-draft
- Milestone: M8d2b2 control prerequisite
- Baseline: 2e48421; RFCs 0044–0045; frozen v0.9
- Owners/reviewers: unassigned

## Purpose

A forward saga and its registered inverse need different exact action contracts
over the same physical resource. The old control profile installs one action per
conflict domain. It cannot acquire a second action through an in-place upgrade.
This profile explicitly enrolls a fresh physical domain with two immutable
protected control registrations, named `forward` and `inverse`.

Each registration retains its own signed publication, installation,
acknowledgement, policy, revocations, grants and consumption roots. Both retain the
same tenant, physical conflict domain, resource/incarnation and ownership epoch.
Action IDs differ; their complete scopes, policy, trust, issuer and acknowledger
pins are immutable. This is bounded static pairing, not dynamic delegation or
cross-cluster coordination. Pairing by itself never authorizes compensation.

## Enrollment and storage

Protected operator configuration supplies the complete topology and one selected
lane. Requests and grants cannot select or switch lanes. Enrollment is create-only
and requires an empty legacy domain. A sentinel at the legacy `control-required`
key makes existing native ports refuse the unknown profile. The same CAS retains
the topology at `domains/<domain>/paired-topology`. Repeated exact enrollment is
idempotent; changed registrations, existing legacy state and stopped domains refuse.

Lane authority lives at `domains/<domain>/paired/<lane>`. Global operation,
admission, issuance, fence-allocation and resource fence-counter indices stay in
the original authority namespace. Therefore a new task ID cannot bypass native
operation identity, and actions cannot create separate counters for one resource.
The allocator continues to serialize tenant/resource/incarnation fences across
both lanes and other physical domains.

Every paired-ledger transaction compares the original complete topology and legacy
sentinel, including read/duplicate paths and restore-witness transactions. Native
control checks additionally require the selected exact scope, policy, ownership
and trust plus absence of a permanent physical-domain stop. These comparisons join
the actual admission/fence/issuance/claim/dispatch transaction. Publication and
installation must match the selected protected registration. Per-lane revocation
does not revoke the other lane; the operator stop blocks both lanes.

Stop is create-only and permanent. It does not delete grants, reset fences, release
budgets or forbid historical query-only recovery. A stop racing an authority
transition wins or loses by the same etcd CAS. No restart or re-enrollment removes
it. Lost enrollment/stop replies require lookup of the original exact marker.

## Carriage and deployment

New optional `action_domain` configuration is explicit on control, governance,
gateway (including acknowledgement), broker, review, outcome collection, recovery
and query-only saga/compensation services. Its omission preserves
old paths; omission in a paired domain fails closed through the legacy sentinel.
The shipping `kf-action-domain` operator CLI validates protected material, enrolls,
queries or permanently stops the pair using fixed mTLS etcd configuration. It has
no execution endpoint, signer or inverse adapter.

Existing lineage envelopes remain historical evidence for one exact installed
action. They do not attest the paired topology or acceptance of an inverse; a
complete saga evidence wrapper must independently pin and verify both lanes and
their native binding/spend histories before claiming end-to-end acceptance.

## Qualification and remaining work

Native tests must cover fresh/duplicate/conflicting enrollment, legacy refusal,
scope/lane substitution, independent installed controls, shared monotonic fences,
cross-lane operation deduplication, missing/changed topology, stop races and
query-only recovery after stop. Frozen schema, fixtures and grant parent/saga
refusals remain unchanged.

RFC 0045 qualification remains nonauthorizing. Fresh inverse admission, mandatory
compound inverse binding, atomic spending from held compensation, registered
target execution/barrier and complete independent saga acceptance remain separate
required M8 work. A paired installation must not make the inverse operation usable
through an ordinary issuance port.
