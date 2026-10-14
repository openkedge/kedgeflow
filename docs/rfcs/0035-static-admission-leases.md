# RFC 0035: Exact-proposal static admission leases

- Status: Draft
- Profile/version: KF-STATIC-LEASE-HTTP-0.1-draft
- Milestone: M7c bounded native lease integration
- Baseline: 1f9e9c8; RFCs 0003, 0005–0007, 0016, 0018, 0034
- Owners/reviewers: unassigned

## Scope and compatibility

Issue the frozen KF-JSON-0.2 AdmissionLease record from the Admission Controller
for exact signed leaf proposals with both static and JIT obligations. A lease
certifies the verified static discharges under registered rules. It supplies no
certificate, root, execution nonce, resource fence, reservation, credential or
execution authority. Full Cedar authorization runs only at final admission.
Frozen records, schema, fixtures and migrations remain unchanged.

Opt-in registration pins admission-role lease keys, maximum lease lifetime and
JIT freshness. Include that registration in the obligation/policy digest. With
no lease registration, existing obligation hashes and control wire behavior stay
unchanged. One new fixed /leases endpoint and profile carry prevalidate/admit;
ordinary admit continues to reject lease fields. Old issuers refuse certificates
with lease_digest. Only independently verified retained input chains enable it.
Existing v0.1 historical lineage/export schemas cannot carry leased packets and
must refuse them; a separately versioned historical profile is subsequent work.

## Binding and static prevalidation

Verify proposal, CTD and static-only manifest/evidence, current subject/workload /
DPoP delegation, parameter/baseline/version/incarnation, leaf scope, policy and
ownership, provider/schema/predicate pins, evidence freshness and review facts.
Require every registered static obligation exactly once and no JIT witness. The
frozen lease binds proposal/delegation, subject/workload, policy/descriptor /
ownership, exact static discharges and exact pending JIT obligation IDs, ordered by
registered obligation ID.

Bound expiry by original underlying evidence, baseline, proposal, delegation and
configured lifetime. Retain a create-only lease plus original static records and
membership generation under a deterministic input/signer/member cache key. Exact
fresh authenticated retry returns the original signed lease, including after a
lost reply or restart; it cannot renew timestamps or replace an expired cache.
Changed static witness/manifest bytes or membership generation select a different
cache. The lease's signed lid binds its cache key. Recompute that identity from the
retained verified-input binding, original membership snapshot and verified signer
when using the cache; rewriting cached membership cannot reopen an older generation. Public signed bytes alone are
insufficient: use requires the exact original retained record and current member.

## Membership and authority comparisons

An operator enrolls a tenant/subject/workload membership with the current complete
registration binding. It is not inferred from agent metadata or lease presence.
One active registration per tenant/subject/workload matches this single-leaf
service. Create-only initial generation is one. Withdrawal and explicit expected-generation
replacement increment generation atomically. Replacement never silently resets or
reopens an old lease. Configuration/policy/provider/descriptor changes require a
new operator generation before lease-enabled authority can be produced.

Compare the active exact membership, policy/ownership and optional installed-control
state at lease creation/reuse and at final admission, fence allocation and issuance,
including duplicate lookup/reuse. Review challenge/enrollment comparisons remain
independent. Withdrawal also blocks the ordinary full-evidence path when leases
are configured, so omitting a lease cannot bypass membership withdrawal. Retain
old leases and allocations; withdrawal does not retroactively revoke an issued
grant. Normal explicit execution-authority revocation remains required.

## Final admission and issuance

The client keeps the original static evidence and lease, acquires new JIT witnesses
and submits a complete signed manifest plus all raw evidence and the lease. Reverify
raw static records and exact discharges against current rules and compare the
retained lease/member in the authority transaction. Never trust the lease as a
replacement for expired, withdrawn or changed evidence. Require each JIT observation
at or after lease issue and within the stricter configured/registered freshness
limit. Certificate lease_digest equals the verified lease record digest and bounds
certificate expiry. The issuer revalidates the retained leased packet and current
membership/lease/review/control state before allocation and grant creation/reuse.
Legacy context-only issuer ports continue to refuse non-null lease digests.

## HTTP and operator contract

Native verified mTLS plus OAuth/DPoP, exact initiating subject/workload and a separate
lease scope. POST application/json only, exact URL/Host/path, no Origin or grant
metadata; closed schema, bounded records/owned tasks and no-store responses.

- prevalidate: profile, operation, request_id, proposal, descriptor, manifest,
  witnesses. The manifest contains only static evidence. Return lease only.
- admit: the same fields plus lease, with full static + fresh JIT evidence. Return
  the final certificate. Existing native /issuance accepts it only after full
  retained-chain verification.

Privileged CLI enrollment/withdrawal/expected-generation replacement operate only
on configured subjects and the current registration. They have no agent HTTP route.
Batch subject operations may partially succeed before an error; they are not one
atomic transaction. Existing control material loading/custody limitations remain;
this increment adds no new key files or production isolation claim. Shared replay,
restore quarantine and optional managed-control requirements still apply.

## Qualification and open gates

Qualify real mTLS/DPoP/etcd static-only prevalidation, immutable retries/recreated
services, complete final admission/issuance with fresh JIT evidence, one fence/root,
wrong signature/context/subject/workload, closed inputs, expired static/JIT/lease /
delegation, changed membership/policy/descriptor/provider pins and generation,
withdrawal races at all authority transactions, no grant from a lease alone and
legacy issuer refusal. Record source-pinned software evidence separately.

Protected browser display/ceremony, approved physical enrollment/attestation,
hardware-bound review, independently administered membership/providers/custody,
versioned leased lineage export, SDK lease acquisition workflow and enterprise
owner acceptance remain open. This draft makes no latency or cost claim.
