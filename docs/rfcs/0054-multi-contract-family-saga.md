# RFC 0054 — Native multi-contract family saga

- Status: Draft; bounded native multi-contract software qualification (M8d3f)
- Milestone: remaining M8d3 multi-contract runner and complete execution evidence
- Profile: `KF-FAMILY-SAGA-0.1-draft`
- Depends on: RFCs 0042, 0044–0053
- Acceptance: no deployed, independent or physical acceptance is implied

The [implementation boundary](../FAMILY_SAGA_RUNTIME.md) describes the bounded
native implementation and its real two-contract SQL/official SDK inverse
qualification. Native host code performs forwards and owner transitions; shipping
owner-command deployment and SDK forward execution remain unqualified. The
[required record](../../results/verification/rfc-m8-family-saga-native-2026-10-22/README.md) retains the frozen tested source.
This increment does not close whole-saga, physical or enterprise acceptance.

## Problem

RFC 0052 conserves held capacity across cataloged contracts. It does not make
independent local compensation-mode transitions one global transition, enforce
cross-contract dependencies, or prove a whole saga. RFC 0053 completed tasks are
coordination records and cannot supply those missing execution facts.

This profile selects an explicit fresh family registration and one protected DAG
across at most eight cataloged native children in one etcd namespace. Each member
has exactly one planned native forward operation, pinned independent admission /
issuer / outcome / observer trust, and an optional exact registered inverse.
An operation/task/message ID cannot select another resource or create a leaf.
The family owner cannot execute the composite parent or supply target credentials
or alternative trust pins in a command.

## Protected plan and enrollment

The new registration profile explicitly selects a composition plan. Legacy family
registration digests and their history remain unchanged. Omission, explicit null,
unsupported profile, mismatched catalog/namespace/trust, duplicate operations,
missing members, cycles and legacy adoption refuse. Every native service must
select the same protected registration; an older or unselected service refuses
the required marker rather than treating the family as independent roots.

Pin all catalog members, exact forward operation keys, dependency edges, native
forward public trust, optional compound public trust, and separate aggregate
observer identity/keys. Existing native trust validators remain authoritative.
Catalog scope, principals, root IDs, policies, action domains and inverse contracts
must match those pins. All member allowances, including compensation, must fit
and be held before any member receives fresh native admission or authority.
Native child registrations and inverse qualifiers are installed before execution.

Fresh enrollment installs family genesis, all paired topologies, the composition
plan/phase genesis and a mandatory nonrepeating native-write epoch atomically.
There is no adoption or live migration of an occupied namespace.

## Global phases and original identities

The durable phases are forward, quiescing, compensating and terminal observation.
Quiescing permanently closes fresh forward admission, issuance, claim and dispatch,
including fresh controller acceptance/substeps for any separately enabled deferred
physical child. Original operation queries and signed receipt refinement continue.
No transition can reopen forward authority or change an original operation key.

Owner intents are signed, short lived, bound to the registration, current phase
head, permanent command operation key and exact collected-proof digest. An exact
original intent replay is read only; a changed command or new task ID cannot
repeat its transition. Request data cannot introduce a node or select trust.
Retain a bounded hash-linked phase history and complete referenced proof bytes.

Before compensating, collect complete current native state for every planned
forward operation. A missing result is unknown. An unissued/unclaimed member
needs positively qualified inventory and a closed late-authority boundary;
absence of a receipt alone is insufficient. Every committed member needs its
existing independently verified original outcome, fresh registered applicability
and late-effect barrier. Unknown forward effects hold the entire transition.
A committed irreversible child cannot be skipped to enable an ancestor inverse.

The global transition compares the unchanged native snapshot and phase head, sets
all relevant permanent local compensation-mode keys, and enters compensating in
one transaction. Calling a local qualifier alone cannot enable an inverse while
the global phase still forbids it.

Fresh inverse authority requires reverse DAG order: each relevant descendant is
proven no effect/unissued under the closed boundary or has completed its original
registered inverse. At most one inverse attempt is in flight in this bounded
profile. Its original member/grant/attempt identity is reserved in the same CAS
as native claim and held spend. Competing ready claims cannot both win. The same
original attempt can dispatch/reconcile; another member cannot bypass unresolved
in-flight work. Only complete verified original evidence can clear that slot.
A failed or unknown inverse preserves consumption and blocks unsafe ancestors.
A complete original signed `failed` receipt may be classified as `failed` and
clear its observed flight slot while the native dispatched allowance remains
`unknown` and consumed. Retain the original failure receipt digest; do not relabel
it as proven no effect or allow another attempt.

No timer refund, replacement attempt, automatic forward retry, uncordon or capacity
release follows from stop, deadline, failure or successful compensation. Each
inverse still needs fresh independent evidence/admission/issuance/broker controls.

## Consistent multi-member snapshot

Each normal mutating native transaction in this new profile compares and changes
the mandatory nonrepeating write epoch in its final transaction. Read-only exports
do not change it. Enrollment is the only initialization path; missing/corrupt
state cannot initialize a replacement epoch. Shared authentication, control,
claims, outcomes, family commands and local mode changes participate too.

A collector reads the epoch before complete native exports and finishes with a
CAS against that same epoch and phase head. This avoids assembling inconsistent
member histories or exceeding etcd's operation limit with hundreds of repeated
per-member comparisons. It does not establish cross-namespace atomicity or trust
a Byzantine storage administrator. Restore quarantine and its independent witness
remain mandatory where enrolled; raw storage/restore paths cannot bypass them.

New complete proof blobs and the corresponding phase transition are retained in
that same final CAS. Do not prewrite snapshots while assuming the old epoch is
still current. Bound individual proofs, new proof batches, total retained history
and the actual encoded transaction; deduplicate identical comparisons without
removing conflicting comparisons. Refuse before exhausting space required for
permanent stop. A history slot alone does not reserve serialized state or etcd
wire capacity.

## Runner and complete evidence

The closed Rust/JSON carriage uses:

- `Intent`: `profile`, owner `key_id`, `payload`, canonical base64url signature.
  The payload fixes the family digest, permanent operation key, expected phase
  head, issued/expiry milliseconds, action and nullable proof digest.
- `Collected`: complete `snapshot` plus separate `seal`. The snapshot fixes
  profile, registration digest, phase head, write epoch token, capture time and
  exact member map. The seal fixes collector identity/key, namespace and snapshot
  digest under `KedgeFlow:KF-FAMILY-SAGA-0.1-draft:native-capture\0`.
- Owner phase events: `kind: owner`, `at`, original signed `intent` and nullable
  `family_head`. Observe requires null; quiesce/preparation require the exact
  live root family head compared by their original CAS.
- Native claim events: `kind: native_claim`, exact native `at`, child/attempt
  identity and original issuer-signed inverse `binding`. Owner commands cannot
  create these records.
- Supplemental native authority bindings: original control key, phase,
  certificate/grant digest, nullable attempt, checked time and exact global
  family/phase/child/lane/qualification view. They accompany the original native
  control binding in the same authority CAS.
- Aggregate: profile, complete `evidence` and `checkpoint`. Evidence includes
  the separately signed family bundle, phase state, exact referenced sealed
  proof map and current complete sealed capture. The checkpoint covers the
  entire evidence digest under
  `KedgeFlow:KF-FAMILY-SAGA-0.1-draft:aggregate-history\0`.

Signatures cover the existing integer-only canonical JSON with signature omitted
and the literal NUL-terminated domain prefix. Observer trust is supplied outside
the exported payload. Historical proof memoization is keyed by all protected
public registration bytes and every actual stored phase/proof byte; final current
family/phase/epoch comparisons and fresh native admission remain mandatory.

A host-side runner uses protected permanent member/qid bindings and the existing
Node Agent Adapter's fresh native path. It persists original operations before
sending, queries them first after restart, and never generates a replacement ID
or re-signs an ambiguous target request automatically. The native guards enforce
dependencies and phases even when a runner sends requests out of order. The
runner cannot treat an A2A coordination task as an outcome proof.

Aggregate export includes the entire family allocation/delegation proof, phase
history, every referenced proof blob and every cataloged member's complete original
forward/inverse authority and outcomes. Fully unissued members need an explicit
complete planned-operation inventory under the separate observer; they cannot be
omitted from an empty map. Verify all members, exact original operation identities,
namespace/plan pins, DAG ordering, in-flight ownership, budgets and phase transitions
before accepting the aggregate observer checkpoint. A digest without its complete
member evidence is insufficient.

Report forward progress, blocked compensation, partial compensation, compensation
failure, unresolved work and completed compensation distinctly. Even completed
compensation retains the original held costs. Historical verification conveys no
current execution authority and does not prove a whole deployed writer boundary.

## Qualification required before delivery

Use two distinct native real-SQL contracts under one shared family. Demonstrate
fresh independent forward and inverse admission, actual SQL commits, real original
barriers/applicability, reverse-order native refusal, final snapshot races, competing
claimers, lost responses, process recreation, late effects and explicit partial /
failed / unknown composition. Re-signed aggregate omissions and substituted trust,
operation, member or outcome records must refuse. Exercise the shipping runner and
offline verifier against actual retained native evidence.

A separate Kubernetes drain remains a Level C child with its own deferred-effect
contract and actual cluster qualification. SQL reservation commit, accepted API
request and observed physical completion are different facts. Unknown physical
work cannot authorize reservation release; uncordon is not workload restoration.
Physical storage/cutover, complete deployed writer coverage, independent custody
and independent whole-saga acceptance remain external gates.
