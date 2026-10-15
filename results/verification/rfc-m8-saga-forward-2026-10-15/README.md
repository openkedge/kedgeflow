# M8d2a native forward-saga authority — 15 October 2026

Baseline: 08f96d4. [RFC 0044](../../../docs/rfcs/0044-native-forward-saga.md)
and the [operator guide](../../../docs/SAGA_FORWARD_AUTHORITY.md) add
`KF-SAGA-FORWARD-0.1-draft` and `KF-SAGA-FORWARD-LINEAGE-0.1-draft`.
The fresh-root profile reserves every planned forward/compensation allowance
before admission and enforces original signed committed predecessor dependencies
inside native authority transactions. Inverse execution remains M8d2b/M8d3 work.

The complete final required run passed **394 Rust tests across 47 binaries**,
**18 SQL storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. There were no
Rust failures, ignored tests or required-mode skips. All **461 source files** stayed
unchanged during the run and afterward. `summary.json` pins tested source, commands,
logs and tools; `final-source.json` pins identical final source and this evidence.
No source edits followed this run. Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3,
etcd 3.6.5, Python 3.13.12, Node 25.2.1 and official MCP client 2.3.0. Shipping binary
count remains 17. Linux account/MSRV execution, physical targets and independent
peer/release acceptance remain unobserved here.

## New observations

Nine new native test groups and two official SDK groups cover:

- Enrollment atomically retains immutable protected plan/static composites, domain
  marker, complete preallocated DAG and history genesis. All planned costs are
  held before any admission or executable grant. Issuance/reuse adds no capacity;
  independent ready branches claim without waiting for sibling outcomes. Unplanned
  operations and re-enrollment refuse; permanent stop preserves all allowances.
- A two-node chain refuses successor admission before an original committed outcome.
  Claimed/dispatched, pending, not-found, unknown and fenced-no-effect observations
  remain blocked. The exact signed original committed chain enables successor
  admission, issuance/reuse, claim and dispatch without releasing either cost.
- Native signed pre-send no-effect cannot enable a successor. Complete offline
  replay permits unissued held nodes without inventing authorizations or grants.
- Closed plan validation refuses cycles, duplicate/dangling edges and operations,
  unassigned principals, incompatible profiles, missing/null/unknown fields,
  overdraw, parent deadline widening and issuer/delegation role overlap. The public
  registration example validates using its original signed static parents;
  independent lineage trust refuses a changed OutcomeService source.
- Mandatory saga binding and original parent/registration/plan identity verify
  under the explicit new signature domain. Omitted saga or parent bindings refuse;
  frozen executable grants still reject non-null saga fields.
- Missing original plan, omitted protected configuration, predecessor issuance,
  admission chain and signed receipt refuse authority without synthesizing proofs.
  Every predecessor proof joins the actual authority CAS, including retained root,
  grant/nonce, attempt/outbox/context, journal, receipt chain/evidence/head and
  native budget/history/plan comparisons. Dependency comparisons are deduplicated
  and bounded before writing.
- Deterministic transaction barriers exercise both permanent stop and predecessor
  receipt deletion at admission, fence allocation, issuance, claim and dispatch.
  Every stale authority write refuses. Reserved costs remain held; failed claim
  cannot manufacture an attempt, and failed dispatch cannot reopen or replace one.
- Complete issued-leaf replay checks original admission/input/policy/issuer pins,
  the preallocated genesis, exact signed bindings and committed predecessor order.
  A correctly rehashed and observer-signed history that moves successor issuance
  before predecessor refinement refuses. Correctly resigned missing-genesis-cost
  and changed-plan substitutions also refuse.
- Separate shipping offline CLIs verify new binding/history profiles without live
  authority claims and refuse changed trust. The existing shipping control CLI
  group additionally exercises the new profile through local check, enrollment,
  permanent stop, duplicate/restart refusal and changed-registration refusal over
  pinned mTLS and fixed etcd credential.
- Official MCP client workflows exercise fresh native admission/issuance, mandatory
  compound binding, one original claim/effect, normal and lost execution replies,
  signed receipt refinement after stop, independent offline replay and a separate
  query-only restart after expiry/revocation. Neither path adds a second target
  effect or query-only recovery dispatch.

The complete earlier corpus remains passing, including query-only RFC 0043 saga
observation and full journal exhaustion, static hierarchy/history, leases/review,
control retention, shipping process kills, native SQL failures/peer transport,
restore quarantine and storage budgets. Frozen fixture/schema/whitepaper bytes,
SQL migration and every earlier verification record remain unchanged.

## Remaining acceptance

This is a bounded software forward-DAG prerequisite: eight fixed operations, one
exact executable contract, static hierarchy and existing bounded history. There
is no autonomous runner or inverse-capable target contract. Offline replay does
not attest the live admission CAS; authentication/control/key history, clock,
observer and ledger custody/consensus trust gaps remain explicit. No result proves
a physical target effect or independent deployment acceptance.

M8d2b next requires separately accepted inverse CTD/adapter semantics, applicability,
fresh compensation admission, deadlines, held compensation spend and late-effect
barriers compared at issuance/claim/dispatch. M8d3 must qualify actual inverse,
late commits, partial/failed/unknown compensation, process loss and complete
independent saga evidence. Dynamic delegation, complete A2A peers, M8e actual
Kubernetes drain and enterprise/writer/physical/release gates remain open.
