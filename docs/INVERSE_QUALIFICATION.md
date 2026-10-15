# Protected inverse contracts and proof qualification — M8d2b1

[RFC 0045](rfcs/0045-inverse-contract-qualification.md) adds the separate
`KF-INVERSE-QUALIFICATION-0.1-draft` prerequisite. It verifies the original committed
forward operation, a signed target barrier and an independently signed applicability
statement, then retains the exact proof with its deadline. Qualification is evidence
for future fresh admission. It issues no grant, spends no allowance and dispatches
nothing. Classic control installations still accept one action per conflict domain.
[RFC 0046 paired controls](PAIRED_ACTION_DOMAINS.md) explicitly enroll a fresh
domain with separate forward/inverse installations; [RFC 0047](NATIVE_COMPENSATION_AUTHORITY.md)
separately enables fresh inverse authority. Its inverse scope/policy must match this contract, and the retained
qualification marker additionally pins the complete topology digest.

## Approve the contract before forward issuance

Start with an enrolled [RFC 0044 forward root](SAGA_FORWARD_AUTHORITY.md). Approve one
inverse contract for a selected planned node before its forward grant is issued.
It binds the complete original registration and operation, inverse operation key /
principal, separately registry-signed inverse CTD, exact inverse scope/policy,
compensation units, restore-state digest, validity and deadline after the signed
forward committed receipt. No new budget is allocated and both existing allowances
remain held.

The [contract example](../config/inverse-contract.example.json) matches the public
forward registration and contains a cryptographically checked demonstration CTD.
Its operation IDs, public test keys, policy, dates and restore state are illustrative;
they do not approve a deployment, applicability or target implementation. Independent
protected trust must approve the complete forward registration/history and signer
pins, and separately approve inverse semantics, policy and the proposed target.

The fixed draft action is `kedgeflow.compensation.restore.v1`, version `1.0`.
Its application arguments contain exactly resource ID, expected version, original
forward grant/attempt and restore-state digest. The protected contract declares
one forward version increment. Qualification requires the original signed baseline
state digest and version plus one; an intervening writer version refuses. The
proposed target must atomically enforce original-attempt terminality, that same
version, registered restore state, fencing and original inverse idempotency. [RFC 0048](POSTGRES_COMPENSATION_TARGET.md) implements that conditional SQL
target/barrier with local software qualification; deployed writer acceptance remains open. Restoration
cannot reverse downstream or physical effects outside the accepted scope.

Pin target-barrier and applicability public keys/source IDs separately. Those keys
must be disjoint from each other and from forward input, registry, evidence,
admission, issuer, composite, outcome and observer roles. Submitted keys never
create trust. Native contract markers pin the complete approved forward trust;
changed contracts, identities, costs or pins cannot adopt an existing enrollment.

## Configure the operator

A protected JSON file contains:

- `contract`: the approved contract;
- `trust`: the complete reserved-lineage trust shape, with the original RFC 0044
  registration, namespace and independently approved historical role/policy pins;
- `etcd_endpoint`, `etcd_ca`, `etcd_certificate`, `etcd_private_key`,
  `etcd_token_file`: fixed HTTPS origin, pinned mTLS and protected credential files;
- optional `restore_gate`: the existing independently retained witness configuration.

The CLI has no listener, target client, admission/issuer client or statement signing
key. Restrict etcd writes to its `inverse-contracts` and `inverse-operations` paths;
original authority records require read access. Actual signer enrollment/custody,
writer coverage, physical barriers and enterprise acceptance remain unqualified.

```sh
kf-compensation --config /etc/kedgeflow/inverse.json --check
kf-compensation --config /etc/kedgeflow/inverse.json --enroll
kf-compensation --config /etc/kedgeflow/inverse.json --qualify --proof /protected/proof.json
kf-compensation --config /etc/kedgeflow/inverse.json --status
kf-compensation --config /etc/kedgeflow/inverse.json --history
kf-compensation --config /etc/kedgeflow/inverse.json --verify-proof \
  --proof /protected/proof.json --at 1800000006000
```

`--check` validates local protected configuration/TLS material without contacting
etcd. Offline `--verify-proof` requires an explicit historical epoch-millisecond
instant and performs no remote call. `--enroll` compares the unissued planned leaf,
original native root/plan/history and permanent inverse-operation ownership marker.
Ordinary native admission/fenced issuance refuse a reserved inverse operation ID;
enrollment refuses its preexisting admission/fence/issuance.
Enrollment, native qualification and journal append use etcd CAS; no target call is
made. Re-enrollment or adoption after forward issuance refuses.

## Supply independently signed evidence

The proof contains the complete `KF-SAGA-FORWARD-LINEAGE-0.1-draft` forward bundle,
closed inverse parameters, target `barrier` statement and separate `applicability`
statement. [The local draft schema](../spec/drafts/inverse-qualification-v0.1.schema.json)
defines their exact closed envelopes and payloads. Signatures use the RFC's separate
canonical domain; they are not frozen grants or admission certificates.

Both statements bind the original registration/root/saga/node/operation/grant /
attempt/committed receipt/resource. The barrier affirms original terminality and no
late re-commit under the registered contract, with the observed target version.
Applicability binds that exact signed barrier, inverse operation/principal,
parameters and restore state. A bare operator request, digest reference, unsigned
success, unknown outcome or pre-send no-effect cannot substitute for either proof.

Barrier time follows the committed receipt; applicability follows the barrier.
Both fit the contract and fixed deadline, and applicability cannot outlive the
barrier. Qualification independently verifies signed forward history and requires
matching original native committed state. Every supplied budget-history event,
selected original authorization/lease binding, attempt/context/journal, receipt
chain/evidence/head and native plan/state joins the retention CAS. A concurrent stop
or proof deletion refuses without changing budget or execution state.

Duplicate proofs return the original qualification and timestamp. Explicit fresh
signed statements may append within the original deadline, with no automatic
renewal. Clock regression cannot append an out-of-order qualification or damage
retained history. The journal retains at most 32 records, 512 KiB per proof, 96 comparisons
and a 1 MiB transaction; combined bounds can refuse earlier. Missing/corrupt head,
prior record, contract or proof refuses without reset. Status exposes the time
window and current active-root observation separately from required live revalidation.
Every output has `execution_authority:false` and `fresh_admission_required:true`.
Expiry or stop releases no capacity.

[Verification](../results/verification/rfc-m8-inverse-qualification-2026-10-15/README.md)
retains ten native groups covering signatures, original identities, deadline/version /
role substitutions, uncertainty, concurrency/restart, stop/proof CAS races, bounded
history and shipping mTLS/offline CLI. Synthetic signer statements qualify verifier
software; they are not observations of a deployed physical barrier.

## Fresh inverse authority and remaining work

[RFC 0047](NATIVE_COMPENSATION_AUTHORITY.md) now connects this evidence to fresh
independently verified inverse admission, mandatory signed compound binding and
native held-spend/claim/dispatch/recovery. Qualification alone remains nonauthorizing.
It selects one exact inverse contract per protected paired service.

M8d3 implements and qualifies the actual inverse target/barrier, late effects,
partial/failed/unknown compensation, process loss and complete independent saga
history. M8e actual drain and enterprise/writer/physical/release gates remain open.
