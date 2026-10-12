# RFC 0020: Pinned exchange identities and bounded trust refresh

- Status: Draft
- Milestone: M5c verification prerequisite; enterprise acceptance remains open
- Baseline: `8e83aeb`; RFCs 0018 and 0019
- Owners/reviewers: unassigned; authorization-server, workload and security owners
- Profile: `KF-PINNED-EXCHANGE-IDENTITY-0.1-draft`

## Scope and trust boundary

Implement `ExchangeIdentityProvider` with independently verified subject and
actor signatures. The operator supplies a protected trust snapshot; request
headers, embedded keys and network discovery MUST NOT select trust. This is a
library prerequisite, without an AS endpoint, mint service or SPIRE provisioner.

Subject tokens use the existing closed Ed25519 `at+jwt` profile, exact issuer and
admission audience, expiry, issuance time, scope and `cnf.jkt`. Require an explicit
registered `kid`. Reuse admission's canonical delegation construction, including
the original scope order and subject-token digest. Exchange verifies the retained
token; it does not repeat or consume the gateway's DPoP proof. RFC 0019 still binds
the exact subject, agent workload, confirmation key and delegation to a live grant.

Actor tokens implement a narrow subset of the [JWT-SVID specification](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md):
ES256 only, protected header `alg`, required enrolled `kid`, optional `typ` of
`JWT` or `JOSE`. The standard permits other algorithms and optional key IDs;
this profile deliberately requires explicit key selection and supports one
algorithm. EdDSA actor tokens MUST refuse. An actor key is an enrolled P-256
uncompressed SEC1 point, with `use: jwt-svid`, scoped to one exact trust domain.
There is no token `iss` requirement: authority comes from the trust domain in the
signed SPIFFE subject and the independently enrolled domain key.

Closed actor claims are `sub`, `aud`, `exp`, optional `iat` and `nbf`. Audience is
one exact configured value, as a string or single-element array. Reject broader
arrays, unknown/duplicate fields, invalid SPIFFE IDs, wrong domain, malformed
signatures, expiry, future `iat`/`nbf`, unsafe integers and expired signing keys.
Unsupported private claims require a new agreed profile. All JWTs are bounded to
16 KiB. A subject/workload pair and every subject scope MUST be registered.

## Snapshot lifecycle and revocation

A closed snapshot contains profile, monotone epoch, validity interval (at most
five minutes), subject issuer/audience, actor audience, enrolled subject/actor
keys with acceptance intervals, registrations, and SHA-256 digests of withdrawn
subject tokens. Keys and registrations have explicit bounds; key IDs are unique
within each role and actor trust domain. No secrets are part of this structure.

The trusted caller supplies an independently retained minimum epoch at startup;
loading an older snapshot MUST refuse. Replacement is atomic, strictly increases
epoch, preserves issuer and audiences, and cannot move validity start backwards.
The provider shares replacement state across clones. Each verification holds one
snapshot lock through signature and registration checks, so it cannot combine
old keys with new registrations. Missing freshness refuses; refresh failure never
extends trust. Subject and actor validity returned to RFC 0019 is bounded by
both token expiry, the selected key acceptance expiry and snapshot expiry.

Removing a key or registration, or adding a subject-token digest, prevents future
verification after replacement. Explicit withdrawal is bounded by snapshot
freshness and delivery to every replica. It does not invalidate an already
returned permit, revoke a minted token or establish instantaneous AS revocation.
Provider updates MUST arrive from protected operator/provider administration;
this API authenticates neither their source nor a network publication protocol.
Independent epoch custody, cross-replica update ordering, restart/restore fencing,
clock monotonicity, and fresh real-provider revocation delivery remain deployment
requirements. A process-local epoch alone is insufficient after stale restore.

## Compatibility and failures

No frozen wire record changes. Snapshot schema has a new identifier under
`spec/drafts`. Invalid configuration is rejected before publication. Verification
and rotation lock failures refuse; no previous-key fallback, arbitrary JWKS
fetch, algorithm negotiation or unchecked token path exists. A key ID only selects
from an approved role/domain key set. RFC 0019 remains responsible for durable
claim/control/revocation comparisons and one-shot permit CAS; final dispatch and
target guards remain independent.

## Implementation and acceptance

`exchange_identity` supplies configuration validation, atomic replacement and
cryptographic verification. `auth` supplies shared subject-token verification
and canonical identity construction. Tests use generated software signing keys:
canonical equality with admission, ES256 JWT-SVID signatures, exact domain and
single audience, closed objects and algorithm refusal, expiry and snapshot
freshness, overlap then key retirement, withdrawn workloads/tokens, epoch rollback
and rejected updates preserving the previous snapshot. A real-etcd broker test
must compose actual token verification with the original claimed-attempt permit.

This increment does not close M5c. Approved AS/SVID provisioning, protected refresh
and epoch custody, actual minting/target-token enforcement, mTLS custody, RBAC,
bypass tests and owner acceptance still require the inputs in
[enterprise qualification](../ENTERPRISE_QUALIFICATION.md).
