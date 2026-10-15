# RFC 0047: Fresh native compensation authority

- Status: Draft
- Profile: KF-COMPENSATION-LEAF-0.1-draft
- Milestone: M8d2b2
- Baseline: 0cca7ea; RFCs 0044–0046; frozen v0.9
- Owners/reviewers: unassigned

## Contract

Only an explicitly configured RFC 0046 inverse lane can execute the separately
registered RFC 0045 conditional restore action. Classic grants retain null parent
and saga fields. A mandatory separately signed compound binding supplies original
forward identity, contract, exact retained qualification, inverse operation,
certificate/grant/parameters, held compensation cost and deadline. A bare grant
or qualification cannot substitute for that binding.

Protected inverse configuration supplies the complete forward historical trust
and contract. Fresh inverse proposal, registry CTD, manifest, independently signed
evidence and Cedar admission use the existing independently pinned verification
pipeline with an explicit inverse parameter-binding opt-in. Ordinary ports keep
refusing these parameters. The inverse control's scope, policy, tenant, ownership,
trust and signer roles must match the protected pair and contract. Barrier and
applicability signers cannot overlap inverse input/admission/issuer roles.

## Forward to compensation transition

Before inverse admission, the operator atomically enters a permanent compensating
mode for the original immutable saga registration and paired topology. It requires
the selected original committed forward effect, current signed barrier and
applicability, and complete original native proof comparisons. An unknown forward
allocation blocks entry. Mode and the native allocation snapshot share the CAS,
so an in-flight forward claim cannot slip through. Forward admission, issuance /
reuse, claim and dispatch compare absence of mode. No mode reset or timer refund
exists. Query-only original outcome recovery remains available.

Inverses follow reverse dependency order. A committed descendant must have a
committed inverse; unknown descendants refuse. Unclaimed allocated descendants
are held and cannot start after the mode transition. Neither failed nor unknown
compensation satisfies a reverse dependency. The bounded profile holds all costs
after every known outcome; it provides no replacement inverse operation.

## Native authority and spend

Admission, fence allocation, issuance/reuse, claim and dispatch independently
reverify the retained exact qualification against current authority time, original
committed native authorization/outcome and the active original reservation. Every
proof read, compensating mode, original inverse-operation ownership and physical
domain stop joins the actual authority transaction. Missing or changed history
refuses. Fresh admission/grant validity must fit the original accepted deadline.
Refresh cannot silently replace a previously bound qualification.

Issuance atomically retains the signed binding and one spend overlay for the
original forward operation along with its ordinary native issuance/root records.
The overlay spends only from the compensation units already held on the original
forward allocation. It cannot create another capacity root or reduce held costs.
The existing global tenant/resource/incarnation fence allocator supplies the next
fence across both exact action lanes.

Claim changes the original spend from allocated to unknown with one immutable
attempt in the same nonce/root/outbox transaction. Dispatch requires that exact
attempt, original binding, still-current barrier/applicability/deadline and active
controls. The signed native recovery receipt may refine only the original spend
to committed or proven no effect. Failed, partial and unresolved results remain
unknown and held. Historical recovery can continue after expiry or stop; it never
authorizes another send.

## Bounded deployment

One protected inverse service selects one exact contract and operation. Its
contract is included in inverse control trust. This version cannot switch among
multiple contracts in one installed pair; a separately reviewed family profile
is required before claiming a complete multi-node inverse runner.

## Compatibility and qualification

All opt-ins are protected configuration, never request metadata. The frozen schema,
fixtures, prior migrations and previous evidence stay unchanged. Existing profiles
cannot adopt this execution profile by installing an inverse lane or presenting a
grant directly. Native tests must cover fresh admission, mandatory binding,
spend/operation deduplication, common fences, mode/stop/proof/deadline races,
query-only recovery and reverse dependency refusal. Actual inverse target/barrier,
late physical effects and complete independent saga evidence remain M8d3; this
profile alone cannot assert their acceptance.
