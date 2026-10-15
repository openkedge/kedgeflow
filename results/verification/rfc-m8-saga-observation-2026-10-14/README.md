# M8d1 durable query-first saga observation — 14 October 2026

Baseline: 53abc13. [RFC 0043](../../../docs/rfcs/0043-durable-saga-observation.md)
and the [operator guide](../../../docs/SAGA_OBSERVATION.md) add
`KF-SAGA-OBSERVATION-0.1-draft`: a protected DAG, permanent saga/root/operation
identities, durable original authorization/attempt/outcome observations and blocked
inverse intent. This is a query-only prerequisite, not executable saga authority.

The final complete required run passed **383 Rust tests across 47 binaries**,
**18 SQL storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips. All **454 source files** stayed unchanged
during the run and afterward. `summary.json` pins tested source, commands, logs
and tools; `final-source.json` pins the identical final source and this evidence.
There were no post-run source edits. Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3,
etcd 3.6.5, Python 3.13.12, Node 25.2.1, official MCP client 2.3.0. The new
`kf-saga` binary raises the shipping binary count to 17. Linux/minimum-version
execution and independent peer/release acceptance remain unobserved here.

## New observations

Eleven real-etcd test groups cover:

- Protected plan/genesis/head/state, one permanent root owner and original
  operation ownership markers share one enrollment transaction. Exact replay and
  a recreated observer return the original state. Changed plan, changed saga ID,
  previously issued children and reused ownership cannot reset or adopt authority.
  Missing issuance remains planned with no execution permission or capacity write.
- Enrollment pins the complete approved historical trust, including registered
  evidence/review/lease definitions, policy, subject/workload/scope, role keys,
  source and observer identity. Changed outcome pins cannot reuse status or
  compensation intent. This supplies no implicit key/policy migration.
- Query-only reconciliation verifies the original retained admission inputs,
  certificate/policy/issuance, selected parent binding, exact principal and original
  claim/context. A native signed unknown receipt stays unknown; a later original
  committed receipt refines after stop while the second forward node remains
  planned. Compensation intent remains blocked pending fresh admission/barrier;
  no allowance is released and no inverse is dispatched.
- A signed pre-send no-effect receipt stays correlated to the original attempt,
  blocks inverse execution and keeps both fixed costs held, without a target query.
  Neither planned absence nor uncertain query results authorize a resend.
- Dependency edges are diagnostic intent. An observed out-of-order native issuance
  records a sticky violation; later predecessor commit cannot erase it. Output
  always states `dependency_order_enforced: false` and `execution_authority: false`.
- Closed-plan validation refuses cycles, duplicate/dangling edges, duplicate
  operations, unapproved principals, wrong registration, inverse cost/resource /
  action substitutions, impossible hypothetical capacity, unknown fields and
  duplicate JSON fields. The public example's registration digest independently
  matches the signed hierarchical example in Rust.
- Eight concurrent observers append one original observation. Repeated unchanged
  reconciliation or compensation requests do not append duplicate events. Exact
  comparisons are deduplicated even on unchanged-read paths.
- Deterministic native transaction barriers race an observation against a new
  signed unknown receipt and against permanent root stop. The receipt race changes
  no budget snapshot; exact receipt-head comparison still rejects the stale write.
  Fresh reconciliation resolves the same original attempt and current root state.
- Missing original admission chains and unplanned native leaves block
  reconciliation. Corrupt/missing head, latest events, earlier events or referenced
  current/older proof blobs refuse status/history as appropriate, without reset,
  proof synthesis or capacity mutation. Proofs retain original claim context even
  before any signed outcome exists.
- Eight original dispatched operations produce changing signed unknown/pending
  observations until the journal reaches all 128 events. Changed intent then
  refuses, while unchanged reconciliation/status remain readable. All eight
  unknown allowances remain held; complete retained history stays readable.
- Separate shipping `kf-saga` processes use pinned mTLS and a fixed etcd credential
  for local check, enrollment, reconciliation, blocked compensation request,
  status/history and restart. Check makes no remote call. The forwarding fixture
  asserts every write stays within observation records/identity markers; native
  budgets remain byte-for-byte unchanged by these commands. A new saga ID on the
  existing root refuses. There is no target client or credential in this CLI.

The entire preceding corpus remains passing, including old reservation and
hierarchical profiles, native SDK recovery, lease/control/review lineage, signed
outcomes, shipping process kills, SQL peer transport, restore quarantine and
incident delivery. Frozen schema, fixtures, whitepaper, SQL migration, artifacts
and all earlier verification records remain unchanged.

## Limits and next milestone

Plans check hypothetical capacity and reference each forward leaf's held
compensation allowance. They reserve no exclusive whole-DAG capacity and enforce
no native dependency or inverse admission/claim/dispatch gate. Inverse semantic,
applicability and late-effect-barrier digests register intent only. A committed
forward observation still cannot execute an inverse. This run qualifies no actual
inverse, compensation success/failure/partial recovery or complete independent
saga replay. Observation records remain dependent on ledger custody and have no
new observer signature or independent consensus/physical-effect claim.

Fixtures use generated identities/keys/clocks and same-host software mock/SQL
targets. Production custody, writer/predicate coverage, identity/key lifecycle,
physical storage/restore, hardware, independent peers and enterprise owner/release
acceptance remain open. M8d2 next defines explicit native saga/dependency/fresh
compensation authority; M8d3 qualifies an actual inverse, accepted applicability /
late-effect barriers, partial/failed/unknown compensation and independent evidence.
M8e actual governed drain remains open. Unknown forward effects never trigger an
inverse, blind retry or timer refund.
