# RFC 0012: Retained leaf admission lineage export and offline verification

- Status: Draft
- Profile: `KF-ADMISSION-LINEAGE-0.1-draft`; signed records retain KF-JSON-0.2
- Milestone: bounded M4b2; full operational/crash/restore gates remain open
- Baseline: `e4a79a0`; RFCs 0003, 0005, 0006, 0010 and 0011
- Owners/reviewers: unassigned; protocol, runtime, resource and security owners

## Problem and scope

The outcome verifier authenticates a signed grant and receipt chain but explicitly
lacks their admission inputs. The authority already retains the exact signed
proposal, CTD, manifest, witnesses, admission certificate and issued grant. This
increment exports those records alongside outcomes and checks the complete signed
authorization chain for the current single-resource, dispatch-bound Cedar profile.

An offline verification result establishes signature, reference, declared identity,
constraint, evidence-rule and policy consistency under separately trusted historical
registration. It performs no admission, issuance, target query, claim or redispatch.
Historical validity checks do not make an expired grant executable. No raw access
token, DPoP proof/private key, target credential or signing seed belongs in the bundle.

## Separate historical trust

The verifier takes an independently approved historical registration: tenant,
proposal workload/keys, registry/manifest/provider keys, evidence schemas/rules,
descriptor, ownership epoch, policy epoch, Cedar source/ABI and obligation pin,
allowed declared subjects, delegation audience and admission/issuer/outcome keys.
Registration is never selected by bundle metadata. Roles must have independent
keys, including across input, admission, issuer and outcome roles. No network
schema/key retrieval, policy supplied by the bundle, or private key is required.

Reconstruct declared subject/workload/delegation/PoP bindings from the signed
proposal, including authorization-server, audience, scopes and expiry. Required
scope must occur in the signed delegation and the subject must be independently
approved. This reconstructs signed assertions; it does not independently validate
the original access token, TLS handshake or request DPoP. Those remain explicit gaps.

The signed proposal/descriptor tenant must match the approved registration. This
provides signed tenancy absent from the frozen grant, binding it transitively via
proposal/certificate digests. It does not qualify mixed-tenant execution namespaces
or silently change RFC 0011's collector registration and storage assumptions.

## Closed export supplement

The [draft schema](../../spec/drafts/admission-lineage-v0.1.schema.json) defines:
profile, admission, packet, issuance and outcomes. Admission/issuance are retained
metadata records; packet contains exact signed proposal/descriptor/manifest and
witness strings. Outcomes use the existing RFC 0010 bundle with signed grant,
execution parameters, ordered receipts, referenced evidence and raw journal.
All record/carriage objects are closed; application evidence/parameter objects
remain governed by their independently pinned schemas.

The protected `EtcdLedger::export_lineage(candidate, operation_key)` reads the
correlated historical admission/chain/issuance snapshot and exports the outcomes.
It works after expiry/current policy changes, without execution authority or
agent-facing disclosure API. The caller must authorize disclosure and supply
the original operation key. A wrong/missing/mismatched operation refuses; legacy
issuance without a retained admission chain cannot manufacture a full bundle.

Admission/issuance metadata are correlated, not signed ledger-state proofs. The
export is a retained receipt-chain prefix, not proof of the latest head or absence
of later reports. Immutable signed links bind the separate reads. No consistent
whole-ledger backup, installation snapshot, authority journal signature or collector
acknowledgement export is supplied by this increment.

## Verification sequence

1. Enforce closed supplement, 16 MiB aggregate bundle bound, 1 MiB per signed
   input and 1–64 witnesses/receipts. Authenticate the certificate and grant with
   independent role keys before taking their signed times as historical clocks.
2. Verify signed proposal/CTD/manifest/witnesses at certificate admitted_at.
   Enforce exact tenant, approved declared subject/workload/delegation, action,
   resources/incarnation, parameter schema/digest, baseline/guard/coverage,
   policy/ownership and complete witness references. Evaluate registered evidence
   predicates, not provider-selected satisfied labels.
3. Re-evaluate the pinned Cedar definition at admitted_at, refusing errors/denial.
   Bound certificate lifetime by input validity and the independently approved
   maximum. Recompute original operation key and retained admission binding.
4. Reverify input freshness at grant issued_at and run certificate/discharge/grant
   constraint validation at that time. Require admission <= issuance and original
   grant validity. Correlate retained admission/issuance keys, binding digests,
   certificate/grant digests, exact canonical issued grant and execution parameters.
5. Verify the RFC 0010 outcome chain, canonical evidence digests, source/fence/root/
   original attempt and monotonic predecessor order. Validate raw journal shapes,
   duplicate phases and correlation; require claimed and reported phases and
   dispatch authorization for possible sends. Raw journal correlation is not
   independently authenticated authority-state proof.

The result identifies signed tenant/operation/proposal/certificate/grant,
historical times, verified witnesses/receipts, reported status and remaining gaps.
No unsigned admitted_at or export-provided clock bypasses freshness. The verifier
exposes no verified inputs or admitted issuance capability to a caller.

## CLI, compatibility and acceptance

`kf-verify-lineage --trust FILE --bundle FILE` consumes public historical trust and
an offline bundle, performs no network access and emits JSON or exits nonzero.
Trust has its own closed public registration, not a service configuration requiring
TLS/secrets. Existing partial outcome verification remains available and frozen
paper/schema/fixtures and runtime fresh-verification behavior remain unchanged.

Test actual retained admission/issuance followed by recorded execution, recovery,
expiry, export and a separate verifier process. Test missing/substituted witnesses,
proposal/descriptor/certificate/grant/parameters/tenant/subject/time/binding/policy,
signer role overlap, missing/reordered receipts and malformed journal/carriage.
Verify expired export is query-only and consumed authority remains held.

## Remaining evidence and release gates

Original authenticated OAuth/DPoP/mTLS transcript; installed control/revocation and
historical key membership; independently authenticated authority journal and fence
allocation; registered tool-name mapping; target-signed commit/no-effect proof and
complete target writer coverage remain explicit gaps. Pinned provider signatures
do not prove factual state or hardware enrollment. Key rotation, authenticated
installation-history export, incidents/automatic delivery, gateway/target crashes,
quiesce/restore fencing and enterprise custody remain later M4/M5/M6 work. A valid
signed chain cannot erase those limitations or qualify independent protocol peers.
