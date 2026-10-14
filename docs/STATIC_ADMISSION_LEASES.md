# Static admission leases (M7c)

[RFC 0035](rfcs/0035-static-admission-leases.md) adds exact-proposal static
prevalidation to `kf-control`. It issues the frozen KF-JSON-0.2 AdmissionLease
record with `execution_authority: false`. A lease retains verified static evidence;
final admission still rechecks the original records and requires fresh JIT evidence.
Prevalidation produces no certificate, root, nonce, fence, reservation or credential.
Full Cedar authorization runs at final admission.

## Configure and administer

[control-leases.example.json](../config/control-leases.example.json) is a software
example combining a static reviewed-evidence obligation with JIT capacity. Its
public test keys, synthetic enrollment and placeholder descriptor pin are examples;
replace them with approved material. The [review provider](NATIVE_REVIEW.md) must
use the same repinned proposal/CTD, policy, ownership and enrollment context.

The optional `leases` object selects a fixed `/leases` URL, a separate `kf.lease`
scope and registration containing admission-role verification keys, maximum lease
lifetime and JIT maximum age. Require both static and JIT obligations. Lease keys
must equal the configured issuer's admission-role keys and cannot overlap input or
issuer keys. Adding/removing/changing lease registration changes obligation and
Cedar policy digests. Use `kf-control --config ... --print-pins`, update the provider
policy pin and install the new policy/ownership/scope before prevalidation.

Enroll the configured subject/workload membership explicitly:

```sh
kf-control --config /etc/kedgeflow/control.json --check
kf-control --config /etc/kedgeflow/control.json --enroll-lease-members
kf-control --config /etc/kedgeflow/control.json
```

`--check` validates local configuration/TLS/keys without publishing membership or
contacting the authority ledger. Initial enrollment is create-only generation one.
An existing membership cannot be silently reset by enrollment. Operator withdrawal
increments generation and deactivates it; explicit replacement also increments
generation and binds the current complete registration:

```sh
kf-control --config /etc/kedgeflow/control.json --withdraw-lease-members
kf-control --config /etc/kedgeflow/control.json \
  --replace-lease-members --expected-lease-generation 2
```

These privileged commands operate only on configured subjects. A batch may partly
succeed before an error; it is not one transaction. There are no agent HTTP routes
for membership administration. One active registration exists per tenant/subject /
workload in this authority namespace, matching the current single-leaf service.
Admission registration, policy, provider or descriptor replacement needs a new
operator generation.
Generation replacement invalidates old leases even when the new pins are identical.
Membership withdrawal blocks ordinary full-evidence admission/issuance too when
leases are configured; omitting a lease cannot bypass withdrawal.

This feature uses existing control key/TLS/etcd material. The control loader's prior
custody/rotation and deployed isolation limitations remain open. Configure the
existing shared replay store and independent restore gate for the intended deployment;
managed control compares installation, acknowledgements and revocation as before.
Generated keys and local file permissions alone do not certify production custody.

## Native workflow

The [closed HTTP schema](../spec/drafts/static-lease-http-v0.1.schema.json) uses
`KF-STATIC-LEASE-HTTP-0.1-draft` at the exact configured `/leases` endpoint. POST
application/json with verified workload mTLS and a current OAuth/DPoP token for the
registered initiating subject/workload, action scope and separate lease scope.
Origin, alias URLs/Host/path/query, grant metadata, unknown fields/profiles and
oversized inputs refuse. Responses are no-store; owned bounded tasks survive a
client disconnect.

1. Freeze the exact signed proposal and CTD. Submit `prevalidate` with profile,
   request_id, proposal, descriptor, a static-only signed manifest and the original
   signed static witnesses. The response is `prevalidated` with the signed lease.
   Validate and keep its original bytes and static evidence. Prevalidation verifies
   static rules and context; it does not promise that full Cedar admission will allow.
2. Acquire the pending JIT witnesses immediately before final admission. Their
   observation time must be at or after lease issue, and their age must be below
   both registered and lease-configured limits. Assemble a complete signed manifest
   over static plus JIT evidence. Reusing a lease does not avoid verification of
   static signatures/rules or make any expired evidence current.
3. Submit `admit` to `/leases` with those signed records, all witnesses and `lease`.
   Final admission verifies exact static discharges/pending JIT IDs and proposal /
   delegation/subject/workload/policy/descriptor/ownership. The authority transaction
   compares active membership, original retained lease, review facts and current
   control state. The certificate binds the verified `lease_digest` and the strictest
   validity bound of lease, evidence, baseline, proposal, delegation and policy.
4. Submit that certificate and proposal to the existing `/issuance` endpoint under
   its normal issuance scope. The issuer revalidates the retained leased packet and
   current membership/lease/review/control facts at lookup, fence allocation and
   grant creation/reuse. A lease alone cannot be redeemed there or by a gateway.

Cache identity binds original static inputs, signer and membership generation.
Usage recomputes that identity from retained input binding, membership and the
independently verified signer; rewritten cache membership cannot reactivate an old
generation.
Exact fresh authenticated retries across replicas/restart return the original
signed lease without extending its issue/expiry timestamps. An expired cache is
not overwritten or renewed. A genuinely different signed static manifest/witness
selects a different cache, still bounded by original evidence validity. A changed
proposal or delegation needs its own prevalidation. Withdrawal keeps old caches
and allocations; if a fence was already allocated before withdrawal it stays held.
Already issued grants use normal explicit authority revocation, independently of
lease membership withdrawal.

## Verification and limits

The [source-pinned software record](../results/verification/rfc-m7-static-leases-2026-10-14/README.md)
qualifies actual mTLS/DPoP and real etcd: competing replicas, immutable retries,
full admission/issuance, expired/static/JIT/delegation and altered context negatives,
Cedar denial after successful prevalidation, membership generation replacement,
withdrawal races at cache/admission/allocation/issuance, and continued review
credential/consumption enforcement. The shipping `kf-control` process is killed
with a durable cache and a withheld reply; restart returns identical signed bytes,
then admits/issues with fresh JIT evidence. Operator CLI enrollment/withdrawal /
expected-generation replacement is tested.

The original no-lease wire flow and serialized packets remain unchanged when this
feature is absent. Old issuers refuse non-null lease digests; legacy context-only
library ports still refuse them. Existing v0.1 lineage/history/control-binding
export/verifiers refuse leased packets because their closed schemas cannot carry
this new retained input. Internal lease/admission records remain retained; a
separately versioned leased lineage profile is the next audit integration step.
The Node Agent Adapter does not yet acquire/cache leases automatically.

These observations use software providers, enrolled fixture memberships and
synthetic authenticators. Approved membership/provider lifecycle, deployed custody,
protected browser rendering/ceremony, physical enrollment/attestation, hardware-bound
review and enterprise owner acceptance remain open. No latency/cost advantage or
full M7 hardware qualification is claimed.
