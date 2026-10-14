# RFC 0031: Canonical review assertion and durable consumption

- Status: Draft
- Profile/version: KF-REVIEW-0.1-draft
- Milestone: M7a verifier/state prerequisite; M7 service/hardware acceptance open
- Baseline: frozen ApprovalPayload; RFCs 0005, 0016
- Owners/reviewers: unassigned

## Supported subset

An authority-side library enrolls an externally approved ES256 credential and
binds a server-created challenge to the frozen canonical ApprovalPayload: exact
proposal, parameters, policy epoch, template/rendered digests, reviewer, verdict,
server nonce, RP, issued time and expiry. The challenge is the unprefixed SHA-256
of canonical approval bytes, encoded unpadded base64url. This is not a signature
over arbitrary JSON by the authenticator.

Enrollment pins the credential ID, reviewer, HTTPS origin/RP, SEC1 uncompressed
P-256 public key and user handle. The library does not perform registration,
attestation, rendering or hardware provenance verification. It refuses a requested
hardware-bound profile. The supported subset excludes backup-eligible/backed-up
credentials, zero/nonmonotonic counters, extensions and attested credential data.
These restrictions deliberately exclude otherwise valid WebAuthn variants.

Verification uses the original clientDataJSON bytes and authenticatorData bytes.
Require webauthn.get, exact origin/challenge, absent/false crossOrigin, no topOrigin,
known credential/reviewer and matching optional user handle. Verify RP hash, UP/UV,
the narrow flag set and counter, then ES256 ASN.1 signature over authenticatorData
concatenated with SHA-256(clientDataJSON). Reject malformed/duplicate JSON and
bounded oversized encodings. No parsing/re-encoding of signed client bytes.

## Durable state

Operator enrollment is create-only; revocation is monotone. Challenges reference
the exact enrollment digest and have at most five-minute validity. Verify against
current enrolled state on each completion. In one real-etcd transaction compare
pending challenge and current active credential, mark the challenge consumed,
advance its counter, and retain the assertion digest. Replicas/restarts yield at
most one consumption. Revocation races this same comparison. Lost publication
after consumption never reopens the challenge. Validity exhausted during the
transaction leaves consumption held; a final freshness check refuses publication
of expired facts. No deletion, expiry refund or
in-memory fallback exists; optional existing restore quarantine applies.

The resulting private-construction VerifiedReview supplies evidence facts to a
trusted provider. It is not a grant, allowance, certificate or public HITL witness.
Current admission continues refusing the frozen HITL/lease variants until a
versioned service/evidence integration is qualified. Trusted library ports must
not be exposed as unauthenticated agent enrollment APIs.

## Remaining M7 work

Protected canonical panel and browser ceremony; approved enrollment/attestation
and hardware policy; reviewer authentication, service/RBAC/custody; provider-signed
HITL carriage in native admission; exact-proposal non-authorizing static leases
with membership/policy/descriptor/delegation invalidation and fresh JIT witnesses.
Synthetic authenticator tests cannot close these gates.

Reference: [W3C WebAuthn assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).
