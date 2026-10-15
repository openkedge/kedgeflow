# RFC 0045: Protected inverse contracts and compensation proof qualification

- Status: Draft
- Profile: KF-INVERSE-QUALIFICATION-0.1-draft
- Milestone: M8d2b1; fresh authority integration remains M8d2b2
- Baseline: c3f298c; RFCs 0043–0044; frozen v0.9
- Owners/reviewers: unassigned

## Boundary and purpose

RFC 0044 supplies fixed forward DAG authority. Its registered action, descriptor,
installed control and gateway mapping cannot admit an inverse action. M8d2b first
needs an independently approved inverse contract and verifiable applicability /
late-effect-barrier statements. This increment retains and verifies those inputs.
It issues no grant, spends no compensation allowance and dispatches nothing.

A `Qualification` is time-bounded evidence for a future fresh admission. It is
never execution authority, a reusable admission certificate or a statement that a
physical barrier has been deployed. Output always says `execution_authority:false`
and `fresh_admission_required:true`. Existing grants and ports keep refusing wider
compensation/saga fields. Existing observation roots cannot be silently adopted.

## Protected inverse contract

An operator approves one contract before the selected forward operation is issued.
It binds the original RFC 0044 registration, saga/node/operation, exact inverse QID
operation digest and principal, separately signed inverse CTD and enforcement
scope, registered restore-state digest, compensation units, absolute validity and
relative deadline after the original committed receipt. The fixed draft inverse
semantics declare a protected one-version-step forward model and restore the original
signed baseline state only when the original forward attempt is
terminal and the target version still matches. They cannot undo arbitrary
side effects, downstream fulfillment, evictions or other writers.

The closed inverse parameter object contains resource ID, expected target version,
original forward grant/attempt and registered restore-state digest. The restore
digest must match the signed original resource baseline and the barrier version
must equal that baseline plus the protected single forward version step. A changed
intervening writer version refuses. Actual values
are independently certified by the applicability signer; neither an agent nor an
operator's compensation request selects an uncorrelated original effect. CTD
parameter schema, rendering pin, action/version, resource/predicate, adapter contract,
tenant, ownership, audience and registry signature must match approved pins.
The inverse action differs from the forward action but keeps its exact resource /
incarnation and conflict domain. It is not added to the current one-action control
installation or exposed as a working target adapter by this RFC.

Target-barrier and applicability signer sets are nonempty, bounded, separately
pinned and disjoint by public key bytes. Both are disjoint from proposal, registry,
manifest/evidence, admission, issuer, composite delegation, outcome and observer
roles. Their source identities are fixed by protected configuration. Trust is
never inferred from a submitted proof or its exported keys. The native contract
marker pins the complete approved forward trust as well as the inverse contract.

## Signed statements and time

Each statement uses a closed Ed25519 envelope with this profile, `kind`, key ID,
typed payload and base64url signature. The signature domain is
`KedgeFlow:KF-INVERSE-QUALIFICATION-0.1-draft\0` plus canonical unsigned envelope.
Digest labels distinguish inverse contract, signed statement, proof and journal
record. Duplicate fields, unsafe integers, unknown fields and explicit nulls refuse.

Both statements bind one original forward identity: registration/root/saga/node /
operation/grant/attempt/committed receipt/resource. A signed target barrier states
that this original attempt is terminal and cannot later commit again under the
specified target contract, and identifies the observed version. A separately
signed applicability statement binds that barrier digest, inverse operation /
principal, exact parameter digest and approved restore semantics. Both booleans
must affirm the bounded claim. The two independent statements cannot substitute
for each other or for an OutcomeService committed receipt.

The verified original forward history must report committed with its native audited
allocation committed and compensation allowance still held. Unknown, pending,
failed, pre-send no-effect and unsigned success refuse. The barrier follows the
signed committed receipt; applicability follows the barrier. Both validity windows
fit the protected contract and the fixed deadline measured from that receipt;
applicability cannot outlive the barrier. Qualification checks authority time again
at persistence. Expiry never releases capacity, refreshes a statement or permits
resend. Historical verification uses an explicit validation time and confers no
current authority.

## Native retention and races

Contract enrollment is create-only and compares the original forward root, plan,
static skeleton/history, selected unissued allocation and absent native issuance.
A forward operation has one permanent inverse contract/operation ownership marker;
changed IDs, trust, cost or pins cannot re-enroll or adopt an already issued leaf.
Enrollment also compares absent inverse admission/fence/issuance. Ordinary native
admission and fenced issuance/reuse compare absence of the inverse ownership marker,
so the prospective inverse QID cannot be claimed by the existing forward ports.

Qualification independently verifies the supplied complete reserved-lineage bundle
and the original signed forward inputs/admission/grant/binding/outcome chain. It
compares original native plan/budget/history and every referenced history event,
selected original authorization, claim/outbox/context/journal, receipt chain and
evidence/head in the same transaction that retains the qualified proof. Current
native history must equal the submitted history. A concurrent stop, receipt/proof
removal or original-state change refuses the stale write without a budget write.
No target request or outcome query is sent by this component.

At most 32 explicit qualification records per contract are retained in a hash-linked
journal, with immutable proof blobs and a current head. Unchanged duplicate proofs
return the original record through a read CAS; they do not extend validity or append
records. New signed proof statements may append within the original deadline;
there is no automatic renewal or identity replacement. A timestamp earlier than
the latest retained qualification refuses before append, preserving valid history
even if the clock regresses within a statement window. Missing/corrupt head, prior
record or proof refuses without reset. Bounds: 512 KiB per submitted proof, 96
comparisons and 1 MiB transaction, with smaller valid cases allowed to refuse when
combined bounds are exceeded. Historical status/history remain nonauthorizing and
report stale/stopped qualification explicitly.

The shipping operator CLI validates protected configuration locally, enrolls a
contract, qualifies a supplied proof, and reads retained status/history. Offline
verification requires the independently approved contract/trust and explicit time.
There is no listener, signing key, target client, compensation grant or executor.

## Follow-on implementation and acceptance

M8d2b2 must introduce an explicit inverse-capable control/issuer/gateway contract,
fresh independently verified inverse proposal/evidence/Cedar admission, one original
inverse operation and atomic compensation-spend linkage. It must recheck original
forward outcome, exact applicability/barrier, stop, deadline and current target
preconditions inside issuance/reuse/claim/dispatch. A qualified proof alone cannot
satisfy those gates. Multiple action installation and common resource fence/domain
semantics require a new explicit profile rather than weakening current scope checks.

M8d3 must implement and qualify the actual registered inverse target and barrier,
late effects, external writers, partial/failed/unknown compensation, process loss
and complete independent saga evidence. Synthetic target/applicability signatures
qualify verification software only. They prove no physical target behavior,
production signer custody, complete writer coverage or independent acceptance.
M8e governed drain and enterprise/physical/release gates remain open.
