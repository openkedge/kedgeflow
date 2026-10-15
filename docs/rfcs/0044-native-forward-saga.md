# RFC 0044: Native forward-saga authority

- Status: Draft
- Profiles: KF-SAGA-FORWARD-0.1-draft; KF-SAGA-FORWARD-LINEAGE-0.1-draft
- Milestone: M8d2a; fresh inverse authority remains M8d2b
- Baseline: 08f96d4; RFCs 0041–0043; frozen v0.9
- Owners/reviewers: unassigned

## Problem and scope

RFC 0043 observes dependency intent but cannot prevent out-of-order execution.
This explicit fresh-root profile enforces a protected forward DAG at native
admission, issuance/reuse, claim and dispatch. It reserves every planned leaf's
forward and compensation allowance during enrollment, before any executable grant
exists. Reserved capacity supplies no execution permission.

The profile supports at most eight fixed operations under one immutable signed
static hierarchy and one exact executable contract. Every leaf still requires
fresh independently verified inputs, policy admission and native issuance. There
is no agent allocation API, dynamic DAG edit, reactivation or cross-root transfer.
Frozen grants retain null saga/parent fields; mandatory signed saga bindings and
native markers form a separately identified compound profile.

## Protected contract and trust

The reservation registration selects `KF-SAGA-FORWARD-0.1-draft`, requires its
existing hierarchy and a `saga` object, and refuses either object's omission.
Other registration profiles refuse a present saga object. The closed local schema
defines saga ID, validity interval, original node/operation identities, exact
subject/workload assignments, unique dependency edges, OutcomeService public pins
and source identity. Refuse cycles, duplicate/dangling edges, duplicate operations,
unassigned principals, unsafe units and hypothetical overdraw. Saga validity must
fit every assigned composite ancestry; a leaf's whole validity must fit the saga.

OutcomeService pins must be separate from input/evidence, admission, leaf issuer
and composite-delegation roles. Native recovery must use the exact approved outcome
key/source. The independent verifier separately approves all registration,
policy/input/admission/issuer/outcome/observer pins; no exported keys create trust.

The signed leaf binding uses `KedgeFlow:KF-SAGA-FORWARD-0.1-draft\0` followed by
canonical unsigned envelope fields. In addition to the hierarchical binding fields,
it requires `saga: {saga_id, node_id, plan_digest}`. The plan digest uses the separate
`saga-forward-plan` digest label. Its operation and complete registration digest
pin the exact preallocated costs, principal, parent and immutable DAG.

## Enrollment and native gates

One create-only transaction retains the original static composites, protected saga
plan, required-profile/domain markers, all planned leaf capacity allocations and
history genesis. Each planned allocation is nonexecutable until the same stable
operation receives its own signed admitted grant/binding. Native gates compare
the original plan and skeleton, required marker, complete snapshot and history
head/latest event. Missing/changed configuration or original records refuses.
An unplanned operation cannot consume the reserved root. Raw coordination and
raw issuance ports cannot bypass this compound profile.

For each direct predecessor, native authority requires its original issued grant,
binding and attempt, a verified complete signed committed receipt chain from the
approved OutcomeService, and matching audited committed budget state. Current
attempt/outbox/context/receipt-head and budget/history/lineage comparisons join
the requesting operation's actual authority transaction. Unknown, pending,
not-found, failed and proven-no-effect predecessors cannot enable a successor.
Unsigned gateway success also cannot satisfy a dependency.

The same dependency and principal checks apply before retaining admission, before
fence/issuance and issuance reuse, and inside claim/dispatch CAS. Admission checks
also bind the exact current descriptor/policy/ownership scope. A long-lived
prepared candidate cannot bypass a later stopped root or missing predecessor
proof. A stale write refuses; trusted callers resolve the original operation
before retrying a confirmed refusal. Ambiguous replies authorize no speculative
issue, claim or resend.

Native permanent stop blocks all further forward authority without releasing
costs. Signed original-outcome refinement and historical export may continue after
stop/expiry. Unissued reservations, known outcomes and unresolved attempts all
keep both allowances held; no timer refund, replacement or generation bump exists.

## History, replay and compatibility

The separate `KF-SAGA-FORWARD-LINEAGE-0.1-draft` wrapper uses RFC 0042's bounded
hash-linked history, complete issued-leaf authorization map and separately pinned
observer checkpoint, with the new profile in each signature/digest contract.
Genesis contains both the exact static skeleton and every protected planned leaf.
Issue records its original positive unique fence and signed saga binding, without
allocating capacity again. Replay requires committed predecessor refinement before
successor issue/claim/dispatch, verifies all issued admissions/inputs/policy /
grants/bindings, and permits unissued held reservations without inventing grants.

The offline history does not attest the live admission CAS or replace its runtime
tests; original authentication, control/key history, clock, observer and ledger
custody/consensus remain explicit trust gaps. It proves no physical target effect.
Existing history bounds remain: 256 events with final stop slot, 256 KiB/event,
128 KiB/snapshot and 64 MiB/bundle. Bound dependency comparison transactions before
writing; combined limits may refuse a larger otherwise well-formed plan.

Fresh roots only. Old static hierarchy and RFC 0043 observer enrollments cannot be
upgraded or adopted. Old binaries refuse the new registration profile; new native
markers prevent omitted-configuration fallback. Frozen grant/fixture/receipt bytes
and all previous profile serialization remain unchanged. The existing control,
recovery and offline reservation/lineage CLIs select the explicit new profile.

## Implementation and acceptance

Add protected forward-plan validation, enrollment/preallocation, mandatory signed
saga bindings, native admission/issuer/claim/dispatch gates, pinned recovery and
separate historical replay/schema. Require native managed etcd/TLS tests for chain
and parallel DAGs, unknown/no-effect refusal, unplanned/identity substitution,
reserved capacity before admission, original operation reuse, omitted config /
changed pins, missing/tampered plan or predecessor records, stop/proof races at
authority boundaries, shipping CLIs and official SDK composition. Retain the full
source-pinned conformance corpus and accurate README/roadmap limits.

## Remaining compensation and deployment work

M8d2b needs a distinct inverse-capable contract: exact original committed forward
correlation, independently accepted inverse CTD/applicability, fresh admission,
validity/deadline, reserved compensation spend and an accepted late-effect barrier
compared at issuance/claim/dispatch. This forward profile cannot issue an inverse
or turn an RFC 0043 compensation request into authority. Unknown forward effects
never enable compensation. M8d3 qualifies an actual inverse, late commits,
partial/failed/unknown compensation, process loss and independent complete saga
evidence. M8e governed drain and enterprise/writer/physical/release gates remain open.
