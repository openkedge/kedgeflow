# RFC 0049: Complete bounded saga and compensation lineage

- Status: Draft
- Profile: KF-COMPENSATION-LINEAGE-0.1-draft
- Milestone: M8d3c
- Prerequisites: RFCs 0042–0048
- Owners/reviewers: unassigned

## Scope

A report covers every planned forward node in one fixed registered saga and the
one exact inverse contract selected by its paired services. It is historical
evidence, never admission, execution permission, a refund or a fresh attempt.
Complete evidence does not imply a successful workflow. A committed forward node
without a committed matching inverse is explicitly uncompensated; an unknown
forward or inverse stays unresolved. Multi-contract families, dynamic delegation,
independent implementation acceptance and physical drain remain separate gates.

## Carriage and independent pins

A closed report includes complete current forward budget history, full independently
verified admission/issuance/outcome lineage for every claimed forward node, the
complete qualification chain, and the original inverse authorization, signed
compound binding, held spend and original outcome lineage when claimed. All
forward exports must have exactly the same budget events and all-issued-leaf
authorizations. Their claimed operation set must exactly equal the claimed plan
set; omissions, extras, substituted attempts and histories refuse.

Public verifier configuration independently pins the registration, paired topology,
selected inverse contract, both original lineage trust sets, budget observer and a
separate compound observer. The latter cannot share input, issuer, outcome,
barrier, applicability, composite or budget-observer keys. No key or endpoint in a
report becomes a verifier pin. Draft domain separation signs the complete report
digest, namespace, observer identity and capture time. Historical verification
uses the original recorded instants; later stop or expiry does not erase evidence.

Qualifications must form the original contiguous chain. Each is reverified at its
recorded validation instant and its budget events must be an exact prefix of the
current history. Inverse admission is independently replayed with original inputs,
signatures and Cedar policy. Its scope, principal, parameters, certificate/grant,
original qualification and held units must equal the signed compound binding.
Its common physical-resource fence must exceed every recorded forward fence.
Claimed inverse outcomes must use the one original attempt. Native broker permits,
when required by dispatch, must match protected broker registration, original
grant/root/attempt, workload, scope, audience and time. Observer attestation does
not replace these signature or policy checks.

## Native export

Only the protected operator-side ledger API exports this profile. It uses no
target client, token exchange or execution port. Before signing it compares the
original reservation, complete budget events, original authorizations, all retained
receipts/evidence/journal, qualification records, inverse binding/spend/seal,
mode marker and original broker permit in one bounded read transaction. Missing
or concurrently changed records refuse. A claim without a retained signed receipt
must first undergo existing query-only recovery; export never synthesizes one.
Unissued planned operations remain held and compare absence of issuance. Issued
but unclaimed forward/inverse authority must retain the exact unclaimed native
root/grant and unused nonce; an allocated budget/spend alone cannot hide a claim.

Bound the plan to its existing eight nodes, qualifications to 32, complete report
to 8 MiB and the final native comparison request to 1 MiB / 127 comparisons. Refuse
larger reports; do not silently truncate, paginate or infer missing outcomes.

## Report meaning and limits

Report each node as held, no_effect, unresolved, uncompensated or compensated.
Only permanent compensation mode, a committed selected inverse, no unresolved
nodes and no uncovered committed forward node permit the bounded `compensated`
classification. Otherwise return forward_only, partial or unresolved. Allocated
and unknown costs remain held, including proven no-effect inverse costs.

Observer correctness, clock, ledger consensus/custody, native authentication and
actual target assertions remain explicit trust assumptions. A complete local
report is not independent peer acceptance or a production restore qualification.

## Qualification

Compose real SQL forward/barrier/evaluator, fresh inverse admission and broker,
actual restore and query-only recovery with native export and offline verification.
Cover allocated, unknown, committed and no-effect inverse states, stop/expiry,
omitted forward nodes, old history, substituted qualifications/attempts/roles,
re-signed semantic tampering, missing old receipts, concurrent changes, all bounds
and the shipping offline verifier. Preserve frozen records and prior evidence.

## Implementation and compatibility

`compensation_lineage` supplies closed carriage, public historical trust,
independent replay and protected native export. The shipping offline command is
`kf-verify-compensation-lineage`; no new agent network endpoint is exposed.
`spec/drafts/compensation-lineage-v0.1.schema.json` closes the outer profile;
original nested profile validators and semantic verifiers remain mandatory.
The frozen schema, forward/inverse execution contracts, migrations and retained
results remain unchanged. Unknown fields, wrong profiles, duplicate JSON keys,
missing nullable carriage and oversized reports refuse. The two-node local case
uses one actual SQL forward/inverse and another original pre-send no-effect
node; it is not a multi-contract inverse runner.
