# Static hierarchical leaf authority

[RFC 0041](rfcs/0041-static-hierarchical-leaf-authority.md) implements M8c2's
bounded static compound profile. Independently signed composite grants reserve a
hierarchy of forward/compensation allowances. They cannot execute. Every leaf
still needs its own fresh signed admission chain and certificate, native issuer,
exact protected action/predicate and original-attempt enforcement.

## Prepare protected material

The [example registration](../config/hierarchical-leaf.example.json) uses public
demonstration keys, fictional descriptor/policy digests and fixture times. Its
signatures are valid for those illustrative bytes; it is not an enrolled or usable
deployment. Changing any signed field requires new authorized signatures and
updated descendant digests/assignments. Never copy the public demonstration seed
into a deployed authority.

Build an independently approved registration using:

- `profile: KF-HIERARCHICAL-LEAF-0.1-draft`, a fresh root ID/generation 1 and the
  complete accepted tenant/domain/action/resource enrollment with separate forward
  and compensation capacity;
- one exact executable `scope`, policy/ownership and fixed positive forward /
  nonnegative compensation cost, as in the [native leaf guide](NATIVE_RESERVED_LEAF.md);
- `hierarchy.delegation_keys`, independently approved public composite-grant keys
  separate from leaf issuer, admission and registered input/evidence signers;
- `hierarchy.grants`, the original signed nonexecutable composites; and
  `hierarchy.assignments`, mapping each approved subject/workload to one composite
  parent digest. The authenticated proposal determines identity; HTTP/A2A request
  IDs and references cannot select a different parent or cost.

The trusted operator can use Rust `hierarchical_leaf::scope_digest` and
`sign_composite` to produce records with protected signing material. That library
signer is not an HTTP or agent tool. `CompositeGrant::digest` supplies the parent
identifier. Each record binds root/generation, complete executable-scope digest,
policy/ownership, allowed action/resource and principal sets, both costs and a
validity interval. A child composite must narrow its parent's scope/principals
and interval. Direct-child totals must fit their parent; root-level totals must
fit enrollment. The leaf scope must fit its assigned parent, and its whole grant
validity must fit all ancestors. Overlong fresh certificates refuse; the service
does not silently extend parent validity or clamp a certificate into new authority.

Use at most 16 composites and 16 assignments, seven composite levels plus a leaf,
16 KiB per signed composite and 128 KiB for the complete hierarchical registration.
RFC 0032's 128 KiB/256-allocation/depth-eight snapshot limits remain. Signed scope arrays must contain unique strings in ascending UTF-8 byte order;
reordered arrays and duplicate signed fields refuse before set decoding. Every composite is enrolled permanently as
`composite`, including unused leafless parents; it has no executable nonce.

## Enroll and run

Put the same protected `reservation` object in the control service, gateway and
recovery configuration. The gateway still exposes exactly one managed executable
tool. Identity assignments do not bypass the control service's current caller
permissions or policy: a parent permits a narrower grant but does not admit it.
Existing review/lease, managed control and restore requirements remain independent.
An optional [A2A read-only resolver](A2A_ROOT_RESOLUTION.md) must pin the same root
and full enrollment; its views confer no execution authority.

```sh
kf-control --config /etc/kedgeflow/control.json --check
kf-control --config /etc/kedgeflow/control.json --enroll-reservation
kf-control --config /etc/kedgeflow/control.json
kf-proxy --config /etc/kedgeflow/gateway.json --check
kf-proxy --config /etc/kedgeflow/gateway.json
```

Enrollment atomically creates the conserved composite skeleton, original signed
composite records and domain/native-required markers. It requires a new root and
refuses reenrollment or adoption of a v0.1/v0.2 root. Every authority gate compares
those original records and the current immutable skeleton. Wrong/missing material
or omitted configuration refuses with no ordinary-leaf fallback.

Each native issuance verifies the complete fresh child admission independently.
A preliminary resource-fence reservation records only the stable operation/fence;
it allocates no hierarchical cost and cannot execute. The later native issuance
transaction atomically retains child cost, grant/root/issuance, issuer-signed
hierarchical binding and native seal/index. Last-slot contenders cannot both
spend the same parent allowance. Confirmed contention can refuse safely. After an
ambiguous reply, resolve the stable admitted operation; changing task IDs does not
supply another allocation key or permission. Never treat a retained fence as an
issued grant.

The compound profile keeps ordinary frozen leaf carriage through MCP. The signed
hierarchical supplement is retained authoritatively, bound to that exact leaf /
certificate and required at every native issuance reuse, claim and dispatch. It
contains the selected parent signed-grant digest and immutable allocation digest.
Neither the frozen leaf alone nor the supplement alone suffices in an enrolled
domain. The frozen verifier still refuses composite records and grants carrying
parent/saga execution fields. Existing Node transport needs no unsigned parent
selection field or scope-widening fallback.

Claim atomically binds the original attempt, marks the leaf unknown and consumes
its ordinary execution root/nonce. Dispatch rechecks current root activity,
original static lineage, exact signed binding/allocation and attempt with native
control comparisons. Composite capacity cannot also execute. A child cannot
become a parent through the state-only coordination library; that library refuses
all mutation of hierarchical roots.

## Stop, recovery and audit

```sh
kf-control --config /etc/kedgeflow/control.json --stop-reservation
kf-verify-reservation --registration /approved/reservation.json \
  --grant /retained/grant.json --binding /retained/binding.json
```

Native stop is permanent/idempotent and retains all costs and original material.
It serializes against fence, child issuance, claim and dispatch. It cannot undo an
earlier authorized send. This version stops the whole root; it supplies no branch
withdrawal, dynamic delegation, replacement, transfer, generation bump or rotation.
Retain protected originals and accepted custody/restore procedures.

After expiry/stop, ordinary status and native query-only recovery may retain a
signed original outcome. Both hierarchical budgets remain held, and budget
classification stays `unknown` even after a known original receipt. No timer,
not-found result or proven pre-send receipt refunds it. Do not reconstruct an
allocation, rerun an effect or use a compensation inverse from that observation.

The offline CLI verifies the separate hierarchy signature role, narrowed static
ancestry and exact issuer-signed leaf/certificate/allocation/parent correlation.
It reports the explicit hierarchical profile and no live execution authority.
It does not reconstruct the child admission inputs or their historical role
memberships, or prove current activity/consumption, ledger consensus, complete
hierarchical history or actual target effects. Existing complete lineage exporters
refuse this profile; M8c3 must introduce an explicit history/refinement contract.

The [verification record](../results/verification/rfc-m8-hierarchical-leaf-2026-10-14/README.md)
uses generated keys/clocks, actual local etcd/TLS, official SDK flows and a software
fenced target. It does not qualify an enterprise SQL reservation, a complete A2A
peer, multi-resource execution, production key/storage custody, dynamic recursive
delegation, hardware or Kubernetes drain. Those acceptance gates and M8c3/M8d/M8e
remain open.
