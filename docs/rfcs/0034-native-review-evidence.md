# RFC 0034: Native reviewed evidence and admission comparisons

- Status: Draft
- Profile/version: KF-REVIEW-EVIDENCE-HTTP-0.1-draft
- Milestone: M7b native review/evidence integration; browser/hardware/leases open
- Baseline: a73666a; RFCs 0005–0007, 0016, 0031
- Owners/reviewers: unassigned

## Scope and compatibility

Add a native provider for the narrow ES256 review subset from RFC 0031. Carry its
closed result in the existing signed Evidence envelope, under a dedicated provider
key, question and result-schema pin. Do not change frozen records or interpret a
generic approved boolean as verified review. Opt-in evidence registration includes
a review rule binding approved public credential enrollment and the fixed renderer.
Legacy registrations omit it and retain identical obligation digests. Old consumers
refuse this new registration field. Frozen HitlWitness and lease carriage remain
unsupported by this increment; no hardware or browser ceremony claim is made.

## Server rendering and binding

Verify signed proposal and CTD against protected initiating-subject/workload,
tenant, descriptor, policy and ownership pins. Support the current single-resource
SQL/mock leaf only; validate registered parameters, baseline version/incarnation,
freshness and absence of workflow/dependencies/compensation. The descriptor must
select the fixed JSON renderer, its template digest and text/plain media type. The frozen CTD rendering enum
permits plain text or HTML; canonical JSON is presented as UTF-8 plain text.
No caller supplies rendered text, rendering digest, time or nonce. Return canonical
JSON bytes over the complete signed action, parameters, resources, baseline,
initiator, qid, policy and descriptor context. Template and rendered digests are
unprefixed SHA-256 of those canonical bytes. The ApprovalPayload challenge remains
the unprefixed SHA-256 of canonical approval bytes.

## HTTP contract

One fixed HTTPS /review endpoint accepts POST application/json only, verified
workload mTLS plus current OAuth/DPoP, an exact registered reviewer subject,
reviewer workload and separate review scope. Origin/header aliases, grant metadata,
unknown fields, unsupported profiles and oversized bodies refuse. This is a native
review-client boundary; direct browser fetch and protected UI remain a later profile.

- begin: profile, operation, request_id, credential_id, proposal, descriptor,
  verdict (approve/reject). Issue one server nonce and return approval, challenge,
  rendered JSON string and credential id. Every new begin is a new challenge;
  callers must retain the received approval after a lost reply rather than infer
  transaction approval. An orphan challenge confers no execution permission.
- complete: profile, operation, request_id, proposal, descriptor, approval,
  assertion. Rebuild and match the exact server context, verify/consume the original
  assertion, then durably publish one signed Evidence envelope for that nonce.
  Return operation=evidence, request_id and witness. Another assertion/context or
  publisher registration for the same nonce refuses. A fresh authenticated retry
  returns the original retained envelope while approval/enrollment remain current.

Closed local schema, fixed errors (invalid_record, unauthenticated, forbidden,
authority_unavailable), no-store responses and bounded owned tasks apply. No HTTP
enrollment, revocation, arbitrary signing, issuance or dispatch route exists.

## Durable checks and publication recovery

Compare current policy/ownership and optional installed-control state at challenge
creation, consumption and publication. Consumption atomically retains assertion
digest, counter and verification time; publication compares the consumed challenge
and current active enrollment, and is create-only. If the process dies between the
two transactions, an exact assertion retry resolves the consumed record and signs
the same deterministic envelope; it never consumes again or changes its timestamps.
Existing output is compared to the expected bytes, not blindly returned. Old
consumed library records without completion metadata refuse publication; there is
no implicit migration or counter reset. Revocation,
expiry, policy changes and inconsistent records refuse recovery. A disconnected
HTTP caller cannot cancel an owned consumption/publication operation.

Admission independently verifies provider signature, closed schema, rendered
binding, policy epoch, parameters, reviewer/credential/enrollment and time/counter
facts. In the admission and issuer transactions, compare active enrollment and the
exact consumed challenge/assertion record. Include these checks in duplicate lookup,
fence allocation and issuance reuse. A signed label without corresponding durable
consumption cannot authorize. Enrollment revocation blocks new admission/issuance;
already issued grants retain the normal explicit authority-revocation semantics.

## Custody and qualification

The new launcher requires an explicit protected-file root and builds TLS, signer
and authenticated etcd client from checked descriptor bytes. Offline --check
publishes nothing. Explicit privileged --enroll/--revoke operate only on fixed
configured credentials; neither is exposed to agents. Batch administration may
partially succeed before an error and is not an atomic enrollment transaction. Existing restore quarantine
applies. Same-host software tests do not prove independent custody/physical domains.

Test real mTLS/DPoP/etcd begin/complete, exact lost-reply retry and process restart,
approve/reject, invalid signatures/origin/UV/substitution, wrong subject/workload,
replay, revocation, expiry, policy change and admission/issuer refusal for fabricated
or revoked review facts. Compose positive review plus fresh JIT evidence through
native admission and issuance. Retain new source-pinned evidence separately.

Protected browser rendering/ceremony, physical approved enrollment/attestation,
hardware-bound profiles, credential administration/rotation, static leases and
enterprise owner acceptance remain open.
