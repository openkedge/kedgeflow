# RFC 0040: Authenticated A2A reservation-root resolution

- Status: Draft
- Profile/version: KF-A2A-ROOT-RESOLUTION-0.1-draft
- Extension: urn:kedgeflow:a2a:root-resolution:0.1-draft
- Milestone: M8c1; hierarchical executable grants remain M8c2
- Baseline: aece222, frozen v0.9, RFCs 0032, 0038 and 0039
- Owners/reviewers: unassigned

## Problem and scope

An A2A recipient needs authenticated access to a reservation root before requesting
narrower child authority. Possessing a root reference or changing a task ID must
not create an allocation or confer execution permission. This increment provides
a separate read-only resolution endpoint, a capability-extension fragment for an
existing AgentCard and a pinned native HTTPS client. It does not implement core
A2A messaging/task operations or advertise a complete A2A server.

The wire conventions are pinned to the official [A2A 1.0.0 specification](https://a2a-protocol.org/v1.0.0/specification/),
sections 3.2.6, 4.1.6, 4.4.4 and 4.6. Extensions require advertisement and explicit
activation; structured Parts use `data` and `mediaType`, without legacy `kind`.
See also the [versioned extension guidance](https://a2a-protocol.org/v1.0.0/topics/extensions/).
The extension-specific HTTP operation below is a KedgeFlow draft, not a new core
A2A method. Independent SDK/peer/intermediary acceptance remains M9.

## Authority and trust

An operator pins one root ID, generation 1, complete RFC 0032 enrollment, logical
delegation ID, exact HTTPS authority endpoint, required token scope and up to 64
reader registrations. Each reader binds OAuth issuer/subject, verified mTLS
workload and an allowed action/resource set. Authentication uses the existing
pinned OAuth, workload and fresh POST DPoP verifier; optional shared replay and
restore quarantine retain their existing boundaries. A reference is never an
identity credential. Tenant/domain/root/delegation/assurance/version substitution
refuses, including from an otherwise authenticated peer.

A privileged create-only enrollment compares the existing root and its domain
marker while installing an ACL marker. The logical root/delegation key is
independent of configuration digest: changing readers or endpoint cannot create a
second ACL under the same logical key. Withdrawal is permanent and idempotent;
there is no automatic reenrollment, replacement, generation bump or ACL update.
Protected operator configuration and etcd ACLs are part of the trust boundary.
No agent route enrolls, withdraws, allocates, claims or dispatches.

## Contract

The closed local schema is `spec/drafts/a2a-root-resolution-v0.1.schema.json`.
`POST /a2a/root:resolve` uses `Content-Type: application/json`, `A2A-Version: 1.0`
and an `A2A-Extensions` comma-separated field containing the exact extension URI.
Duplicate version/extension header fields, duplicate/empty activation entries,
unsupported extension versions and omitted activation refuse. Other unknown
extension URIs are ignored, never interpreted as a supported version.

The request contains the profile, bounded request ID, one structured root-reference
Part, a requested action/resource scope, optional parent operation digest and
optional task/context correlation IDs. All nullable members are explicit. The
Part contains the frozen reference type, root/generation, delegation ID,
`assurance_profile: KF-COORDINATION-0.1-draft`, explicit `KF-JSON-0.2` and
`saga_budget: null`. Allocation-bearing frozen references remain unsupported.
The receiver compares the authority URL to its protected pin; the native client
checks the same pin before sending credentials and never follows reference URLs.
No remote schema/card/authority discovery or redirects are allowed.

A single linearizable transaction reads the ACL marker, root snapshot and domain
marker. It validates their exact protected bindings and the complete conserved
snapshot, then checks that requested scope is a subset of both reader scope and
selected parent scope (or root scope). Parent selection is a status selector,
not permission to delegate or execute. The response returns only the requested
scope, selected parent state, observed root activity, snapshot digest and echoed
correlation. It always declares `execution_authority: false` and
`child_grants_supported: false`. It does not disclose sibling allocations or
remaining/free budget. The digest identifies observed state; it is not a signed
checkpoint, fence, freshness promise or target receipt. A stopped root may be
resolved by an active reader for historical reconciliation.

Resolution does not write capacity or issuance/claim/dispatch state. Shared DPoP
replay consumption, when configured, is an authentication write. Task, context
and request IDs are never storage, deduplication or authority keys. Fresh retries
read current state, even if the IDs differ. Replayed DPoP proofs refuse.

## Failure and retry

Malformed/unsupported carriage returns 400, missing authentication 401, invalid
ACL/scope/reference or withdrawn access 403, wrong endpoint/method/content type
use their existing HTTP status, and unavailable/timeout authority returns 503.
Refusals have no-store caching and reveal no root contents. No local cache,
negative-result synthesis or allocation fallback is permitted. Read-only retries
require fresh DPoP. A stop/withdrawal concurrent with resolution is ordered at the
single read transaction; any previously returned view remains non-authorizing.

## Compatibility and rollout

Omitting the optional control-service `a2a` configuration keeps the route absent.
Explicit operator enrollment is required after provisioning the existing root.
`kf-control --check` validates local material without enrolling/probing the root.
`--print-a2a-extension` prints a fragment for an existing peer's AgentCard;
`--enroll-a2a-root` and `--withdraw-a2a-root` perform protected ACL operations.
The service exposes no public AgentCard or core task endpoint. Frozen fixtures,
leaf grants and reserved v0.1/v0.2 authority paths stay unchanged. Withdrawal does
not stop the budget or revoke independently issued grants; use their native stop
and revocation operations separately.

## Implementation and acceptance

`a2a_root.rs` owns strict carriage/registration validation, capability fragment,
create-only ACL, atomic resolution and pinned HTTPS client. `a2a_root_service.rs`
mounts authenticated native HTTP. `ControlConfig` and `kf-control` provide opt-in
material and privileged operator operations.

Required tests cover actual TLS/DPoP/etcd exchange, hierarchy scope attenuation,
unknown/composite/stopped views, changed task IDs with unchanged capacity, ACL and
identity substitution, duplicate/legacy/unknown fields, activation/version errors,
wrong authority URL without credential forwarding, withdrawal/restart and
configuration drift, missing/corrupt root/domain/ACL, unavailable storage and
shipping configuration/CLI. A full required conformance run pins final sources.
Software-generated keys, clocks and local peers do not establish production
identity, writer coverage or independent interoperability.

## Next milestones and open decisions

M8c2 must introduce a separately versioned signed hierarchical execution profile.
Its controller independently verifies each child's fresh admitted operation,
identity, audience, exact predicate/incarnation, expiry and narrower parent rights.
One native authority transaction must reserve immutable child costs and bind the
child grant/certificate, current parent generation, active root, policy, ownership,
review/lease membership, restore witness and deduplication key. A task ID must
never replace the admitted-operation key. A parent becomes irreversibly composite
before child execution and can never spend the same allowance. Claim/dispatch
must compare current lineage; original attempts and unknown costs stay held.
The frozen leaf verifier must continue refusing parent/saga execution fields.

M8c3 must retain and independently replay complete hierarchical allocation and
signed-outcome history under explicit bounded storage/exhaustion rules. M8d adds
durable orchestration/compensation with fresh admission and late-effect barriers;
M8e adds the separately enrolled Kubernetes drain with accepted Level C limits.
Cross-cluster transfer, ACL rotation/replacement and external owner acceptance
need further contracts. The c1 scope filter and root view satisfy none of those
execution gates by themselves.

## M8c2 checkpoint — 14 October 2026

[RFC 0041](0041-static-hierarchical-leaf-authority.md) delivers an explicit bounded
static compound execution profile: pre-enrolled signed nonexecutable composites,
fresh admitted leaf grants and native mandatory signed parent bindings. It keeps
frozen parent/saga grant variants refused. Dynamic delegation and M8c3 complete
hierarchical history remain open. This resolver remains read-only.
