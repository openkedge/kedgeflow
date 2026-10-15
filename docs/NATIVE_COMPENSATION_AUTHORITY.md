# Fresh native compensation authority — M8d2b2

[RFC 0047](rfcs/0047-native-compensation-authority.md) defines the explicit
`KF-COMPENSATION-LEAF-0.1-draft` execution opt-in. It connects a separately
installed [paired inverse lane](PAIRED_ACTION_DOMAINS.md) to fresh verified
proposal/CTD/manifest/evidence/Cedar admission, a mandatory issuer-signed compound
binding and spending from the original held compensation allowance.

## Protected configuration

Approve and enroll the [original contract](INVERSE_QUALIFICATION.md) before forward
issuance. The bounded execution configuration selects one exact inverse contract
and operation for its paired service. It does not establish a multi-contract
compensation family or a complete multi-node inverse runner.

The inverse control, gateway, broker and recovery configurations carry
`inverse_execution`, a closed object containing:

- `profile`: `KF-COMPENSATION-LEAF-0.1-draft`;
- `contract`: the complete approved RFC 0045 contract;
- `forward`: the complete reserved-lineage trust configuration, including the
  original registration, namespace and independently approved historical pins;
- `outcome_keys`: inverse outcome-role public keys in standard base64;
- `source_id`: the exact protected inverse outcome source identity.

Select `action_domain.lane: "inverse"` and the same complete approved topology.
Governance uses `control.inverse_execution`. The inverse service must not configure
another `reservation`; it spends the original forward allocation's already held
compensation units. Forward services retain the forward selection and registration.
The complete forward trust must match the topology's forward trust digest. The
inverse control trust digest additionally pins the selected contract. Calculate
both lane registrations from their actual independently approved configurations
before enrolling the topology.

Each inverse gateway tool explicitly carries that same `inverse_contract`, with
the contract's exact action, resource, adapter and closed five-field parameters.
Ordinary tools refuse the named inverse action. Admission uses separately verified
inverse inputs and the inverse policy/evidence predicate; a forward certificate
cannot authorize the inverse. Historical lineage verification opts in through
its separately pinned `inverse_contract`. Request metadata cannot select any of
these registrations, endpoints, keys, policies or contracts. Explicit null refuses.

Barrier/applicability keys remain disjoint from inverse input, admission, issuer
and outcome roles. The signed compound binding pins inverse outcome keys/source,
so a restart cannot substitute another recovery role. Service custody and writer
coverage still require deployment acceptance.

## Enter compensation mode

After retaining a current original committed forward proof and independently
signed target barrier/applicability:

```sh
kf-compensation --config /etc/kedgeflow/inverse.json --begin-compensation
```

Use the forward operator configuration from RFC 0045. In addition to the original
qualification paths, the operator needs create/read access to the original
namespace's `saga-compensating` path. Mode entry compares the exact native proof,
current reservation and physical stop in the actual transaction. Unknown forward
allocations refuse. Forward claims/dispatch compare mode absence in their own
transactions, closing the claim/transition race. Mode is permanent: restart,
expiry, a refreshed qualification or another operation ID cannot resume forward
execution or release capacity. The CLI itself issues no grant or target request.

Fresh inverse admission/issuance/reuse/claim/dispatch each require the original
contract, live exact qualification, registered operation/principal/parameters,
active controls and deadline. Issuance atomically retains the compound binding,
original spend and seal together with native issuance. Claim records one original
attempt and changes its spend to unknown in the nonce/root/outbox transaction.
Dispatch checks that same binding and attempt. Refreshing the qualification head
after issuance cannot silently replace the bound proof. Reverse dependencies
require committed descendant inverses; unknown descendants refuse. Unclaimed
forward descendants remain held and cannot start after mode entry.

## Outcomes and qualification boundary

Signed query-only native recovery refines the original inverse attempt after
expiry or stop. Committed and pre-send no-effect remain distinct. Failed, partial,
pending, not-found and unknown observations keep capacity held and cannot permit
a replacement send. Neither terminal success nor no effect refunds allowance.
The shared tenant/resource/incarnation fence allocator supplies inverse fences.
A bare frozen grant, unbound public issuance call, qualification or installed
inverse lane cannot supply the mandatory compound authority.

The native tests cover independent fresh admission, common fences, mandatory
binding, exact operation/parameters, held costs, mode/stop/proof races and original
query-only refinement. These software checks use synthetic barrier/applicability
statements. [RFC 0048](POSTGRES_COMPENSATION_TARGET.md) adds the actual conditional SQL inverse
and target barrier with separate software qualification. Complete independent
saga history, wider late-effect/crash/failure and deployment acceptance remain M8d3.
The separately accepted Kubernetes Level C drain controller remains M8e. Dynamic
delegation, full A2A peers and enterprise/writer acceptance also remain open.
