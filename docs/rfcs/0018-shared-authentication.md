# RFC 0018: Shared DPoP consumption and subject/workload registration

- Status: Draft
- Milestone: M5a software prerequisite
- Baseline: `91442da`; existing pinned Ed25519 dual identity profile
- Owners/reviewers: unassigned; identity, workload, deployment and security owners
- Profile: `KF-SHARED-AUTH-0.1-draft` (internal protected state)

## Purpose and compatibility

A process-local proof cache cannot establish single use across replicas or
restarts. An optional operator-owned shared authentication configuration adds
durable proof consumption and explicit subject/workload/scope registration.
Frozen proposals, grants, receipts, delegation digests and MCP carriage remain
unchanged. Unconfigured services retain their declared local-cache profile and
must not claim shared replay protection.

This profile follows [RFC 9449 section 11.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1)
for replay tracking in a target URI context. It retains the existing narrow
Ed25519, POST, exact fixed HTTPS URI, access-token hash and 60-second proof window,
with five seconds of allowed future skew. No nonce challenge or general-purpose
authorization-server protocol is introduced. Verified mTLS workload identity
comes from the completed connection, never caller headers.

## Registration

The operator configures 1..256 closed registrations. Each binds an exact
`Subject { iss, sub }`, exact validated SPIFFE workload ID and 1..128 unique
allowed scopes. The subject issuer must equal the authenticator's pinned issuer.
Every token scope must be in the matching registration; missing membership,
workload substitution or scope widening refuses before replay state changes.
Registrations do not replace application role, tenant, resource or signed-record
checks. Authentication is not transaction approval or execution authority.

All replicas of one issuer/audience/external-URI realm MUST use the same etcd
namespace, capacity and canonical registration digest. Configuration differences
refuse against retained state. Static registration/key changes require an
explicit migration/rotation contract; selecting another namespace is a trust
change, not a replay-safe migration. Existing pin-file custody remains assumed.

## Shared state and atomic consumption

The realm is a domain-separated digest of profile, issuer, audience and external
URI. One protected record under `authentication/replay/{realm}` contains the
profile, immutable registration digest, last accepted verifier time and a map
from proof digest to expiry. The proof digest binds the confirmation-key
thumbprint and `jti`; raw access tokens and proof identifiers are not retained.

Capacity is operator-selected in 1..4096 live entries. Parse a closed schema,
validate bindings and refuse oversized/corrupt records. Refuse clock regression
relative to the retained watermark. Remove entries only when their stored expiry
is at or before the trusted verifier time. Expiry is proof `iat + 66` seconds,
covering the full accepted window plus skew and an extra boundary second.
All accepted requests advance the watermark atomically with consumption.

Read and compare the exact prior record; a version-zero or value CAS writes the
new record. Concurrent replicas retry a bounded number of CAS conflicts.
Duplicate proof, saturation, corruption, dependency outage, uncertain transport
result or restore quarantine refuses. There is no local-cache fallback or replay
of an ambiguous mutation. Use a fresh proof on retry; operation/attempt
idempotency remains the separate execution contract. No etcd lease expiry is
used: cleanup is explicit and tied to the trusted monotone verifier watermark.

All transactions use the shared restore gate when enrolled. Before enrollment,
operators must independently qualify replay-store durability and prohibit stale
restore/raw writes. This profile does not establish independent custody or
physical failure-domain coverage. Time trust, shared namespace and complete
writer/replica coverage are deployment requirements.

## Service binding and verification

Gateway, admission/issuance/status, governance administration and collector
DPoP routes use the asynchronous shared path when configured. The old synchronous
conformance helper MUST refuse on a shared authenticator to prevent accidental
local-cache bypass. `--check` validates configuration/material without consuming
a proof or probing remote state. Operator samples show explicit opt-in.

Required cases: concurrent independent authenticators, recreated instance,
lost successful consumption reply, outage, capacity/expiry boundaries, future
proof retention, malformed state, clock regression, registration mismatch,
workload/subject/scope substitution and restore-marker refusal. Native service
tests must demonstrate use of the shared path, rather than only library calls.

## Remaining M5 gate

This is a software prerequisite. Real authorization-server discovery/key rollover,
administered SVID provisioning/rotation, broker-side grant/attempt validation,
least-privilege production RBAC, identity revocation, key custody, protected egress
and deployed bypass qualification remain required for enterprise acceptance.
