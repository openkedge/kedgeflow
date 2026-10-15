# Authenticated A2A root-reference resolution

[RFC 0040](rfcs/0040-a2a-root-resolution.md) implements M8c1: an optional native
control-service endpoint for scoped reservation-root views. It uses A2A 1.0
extension activation and a structured Part. A view carries **no execution
permission**. This resolver does not implement child admission/issuance or core A2A tasks.
[RFC 0041](HIERARCHICAL_LEAF_AUTHORITY.md) separately supplies static native
hierarchical authority with fresh admitted leaves.

## Protected setup

Start with the existing [control service](CONTROL_SERVICE.md) and merge the
`a2a` object from [the configuration fragment](../config/a2a-root.example.json).
Replace every illustrative identity/resource/boundary with approved material.
The root must already be enrolled through the trusted RFC 0032 library or the
[native reserved-leaf operator path](NATIVE_RESERVED_LEAF.md). This endpoint
cannot create a capacity root. Pin its exact existing enrollment, generation 1
and reader delegation ID. The HTTPS authority must match the control service and
the path must be `/a2a/root:resolve`. If a native reservation is configured, its
root and complete enrollment must match the A2A registration.

Each reader pins subject issuer/sub, independently verified mTLS SPIFFE workload
and allowed action/resource scope. Readers may only ask for subsets of that
scope and of the selected parent allocation or root scope. The required token
scope is a separate disclosure permission. These set filters do not qualify a
complete executable predicate or independently verify child admission.

Protect the control configuration, OAuth/workload pins, etcd credentials and
namespace ACLs using the deployment's accepted custody procedure. Shared DPoP
configuration, if enabled, must also register each reader and `kf.root.resolve`
(or the chosen scope). It consumes proofs in the existing shared replay store;
resolution itself never writes budget, grant, attempt or dispatch state. Restore
quarantine applies through the same ledger transaction boundary.

```sh
kf-control --config /etc/kedgeflow/control.json --check
kf-control --config /etc/kedgeflow/control.json --print-a2a-extension
kf-control --config /etc/kedgeflow/control.json --enroll-a2a-root
kf-control --config /etc/kedgeflow/control.json
```

`--check` validates local service material; it does not probe/enroll the root.
The print command emits one `AgentExtension` object for an existing peer's
`AgentCard.capabilities.extensions`. That peer must implement its own core A2A
operations and advertise this exact draft extension. The control service serves
no AgentCard or A2A task endpoint. Advertising a fragment does not attest deployed
enforcement or establish independent interoperability.

Enrollment creates an immutable ACL marker beside the existing root, comparing
its complete enrollment/domain binding. Repeated enrollment refuses. Retain the
original protected configuration: changing readers, endpoint or enrollment does
not replace the marker. There is no rotation/replacement or generation-update
API in this draft.

## Activated request

An authenticated peer POSTs `application/json` with a fresh token-bound POST DPoP
proof whose `htu` is the exact protected authority endpoint, plus:

```http
A2A-Version: 1.0
A2A-Extensions: urn:kedgeflow:a2a:root-resolution:0.1-draft
```

Use the [closed draft schema](../spec/drafts/a2a-root-resolution-v0.1.schema.json).
A request example, with illustrative identifiers matching the fragment, is:

```json
{
  "profile": "KF-A2A-ROOT-RESOLUTION-0.1-draft",
  "request_id": "resolve-original-operation",
  "part": {
    "data": {
      "type": "urn:kedgeflow:root-reference:1.0",
      "root_id": "operator-approved-existing-root",
      "root_generation": 1,
      "delegation_id": "operator-approved-reader-delegation",
      "assurance_profile": "KF-COORDINATION-0.1-draft",
      "cryptographic_profile": "KF-JSON-0.2",
      "authority_endpoint": "https://localhost:9443/a2a/root:resolve",
      "saga_budget": null
    },
    "mediaType": "application/json"
  },
  "scope": {
    "actions": ["capacity.reserve"],
    "resources": ["operator-approved-resource"]
  },
  "parent_operation": null,
  "task_id": "correlation-task",
  "context_id": "correlation-context"
}
```

For a parent view, set `parent_operation` to its existing 64-character admitted
operation digest; it is a selector, never an allocation request. All nullable
members are explicit. Allocation-bearing saga references, legacy `kind: data`,
extra fields, duplicate object keys/scope entries and unsupported generation /
assurance/crypto profiles refuse. The exact extension must be activated; duplicate
header fields/entries, empty entries or conflicting versions refuse. Unrelated
unknown extension URIs are ignored.

The server reads ACL/root/domain state in one linearizable transaction and
validates complete hierarchical conservation before selecting the view. Responses
include the requested scope, optional selected parent state, observed root activity
and snapshot digest, with `execution_authority: false` and
`child_grants_supported: false`. They expose no sibling list, free/remaining
budget, signed grant or target credential. A composite/unknown/stopped view never
permits execution or reopens held capacity. A stopped root remains visible to an
active reader for reconciliation.

The Rust `HttpsRootResolver` takes an independently approved registration and a
`tls::PinnedClient`. It refuses reference/configuration substitution before
sending credentials, sends only authorization/DPoP headers to its fixed pin,
refuses redirects/compression/oversized or malformed replies and verifies response
identity/scope/correlation. It accepts no URL discovered from a Part or AgentCard.
Authentication and signing-key custody remain the caller's responsibility.

## Withdrawal, retries and limits

```sh
kf-control --config /etc/kedgeflow/control.json --withdraw-a2a-root
```

Withdrawal is permanent and idempotent, including across process recreation.
It withdraws disclosure through this ACL; stopping the reservation or revoking
existing grants uses their separate native operations. Previously returned views
remain non-authorizing. An in-flight view is ordered before or after stop /
withdrawal at the single read transaction.

Retry a failed read only with fresh DPoP. New request/task/context IDs do not
allocate, deduplicate, recover or release anything. Missing/corrupt root/domain /
ACL, missing restore witness or unavailable etcd refuses. There is no cached view
fallback or synthesized permission. HTTP replies use no-store. Successful views
are observations of trusted retained state, not signed checkpoints, freshness
leases, consensus proofs or resource commit evidence.

Registration and wire messages are bounded to 64 KiB, with at most 64 readers.
RFC 0032's snapshot bounds and depth/capacity checks remain unchanged. Native
reserved v0.2 views leave its history, held costs and original attempt unchanged.
Keys, peers and clocks in the [verification record](../results/verification/rfc-m8-a2a-root-2026-10-14/README.md)
are local software fixtures. Dynamic delegation/complete hierarchical history, deployed peer/custody
acceptance, durable saga/compensation, actual Kubernetes drain, cross-cluster
transfer and independent protocol interoperability remain open.
