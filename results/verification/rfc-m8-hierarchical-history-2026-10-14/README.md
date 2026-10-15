# M8c3 audited static hierarchical history — 14 October 2026

Baseline: 6b7a9bf. [RFC 0042](../../../docs/rfcs/0042-hierarchical-history.md)
and the [operator guide](../../../docs/HIERARCHICAL_HISTORY.md) introduce explicit
fresh-root `KF-HIERARCHICAL-LEAF-0.2-draft` enrollment and a separate
`KF-HIERARCHICAL-LINEAGE-0.1-draft` historical wrapper. Static composite and leaf
binding formats remain unchanged. Old hierarchical 0.1 keeps unknown/held budgets.
No existing enrollment can be upgraded, reset, refunded or reactivated.

The final required run passed **372 Rust tests across 46 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. There were no
Rust failures, ignored tests or required-mode skips. All **446 source files**
remained unchanged throughout the complete run and afterward. `summary.json`
pins tested sources, commands, logs and tools; `final-source.json` repeats the
exact final source pins and hashes this evidence. No post-run source edits.
Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5, Python 3.13.12,
Node 25.2.1 and official MCP client 2.3.0. No Linux/minimum-Rust acceptance claim.

## New observations

Fourteen new test groups plus expanded shipping operator lifecycle checks cover:

- Genesis contains the exact independently signed static composite skeleton.
  Child cost, original fence/grant/binding, issuance and its history event share
  one native transaction. Eight contenders produce one last-slot winner and one
  issue event. An earlier retained fence consumes no hierarchical capacity.
- Complete replay checks original ancestry/narrowing, conservation, original
  attempt, active-root dispatch, permanent stop and signed refinement. Every
  issued leaf has a matching original admission/certificate/input/policy/issuance
  proof, including an unclaimed second leaf. Missing retained inputs refuse
  export; no proof is synthesized from another operation.
- Independently approved subject/workload assignments support different workloads
  under the same static root and shared historical role/policy pins. A leaf with
  fence 2 can issue before the leaf with fence 1; complete replay checks unique
  original fences and does not mistake that permitted ordering for a refund.
- Correctly re-signed observer checkpoints cannot validate missing/extra/swapped
  proofs, substituted input/certificate/issuance metadata, changed static cost /
  parent, refund, attempt, dispatch/refinement/stop removal, fence or phase/profile
  substitution, or impossible capture time. Raw duplicate scope entries refuse
  before set decoding. Wrong observer/namespace/profile/role pins refuse.
- Native signed pre-send no-effect and committed receipts refine original leaves
  after expiry/stop without releasing either allowance. Dispatched pending,
  not-found, unknown and no-effect wording remain unknown. Concurrent receipt
  workers retain one original refinement; repeated recovery does not duplicate it.
- Deterministic receipt-CAS barriers race dispatch and stop. A stale no-effect
  transaction refuses. A separately clocked native dispatch replica exercises
  the absent-journal comparison itself; retry preserves unknown after dispatch
  or refines the original pre-send attempt after stop.
- Corrupt/missing head or latest events blocks native authority; a missing older
  event blocks complete export. State-only coordination ports refuse the audited
  marker. Exhaustion at event 255 preserves every unknown allocation and the
  remaining free capacity; only permanent stop may consume event 256.
- The shipping recovery CLI requires the exact audited configuration, retains one
  original pre-send signed refinement and never queries/resends the target. The
  shipping offline CLI uses independently approved hierarchy/observer/role pins.
  Operator lifecycle checks now cover legacy, static 0.1 and audited 0.2 enrollment
  and permanent stop. The signed public demonstration registration verifies.
- Official SDK/native TLS/DPoP/etcd normal and lost-execution-reply cases refine
  the original committed child after stop and independently replay six authority
  events. A separate Node process resolves the same original attempt after expiry
  with query-only delegation, without extra evidence, admission, issuance, target
  credential mint or dispatch.
- The full preceding corpus remains passing, including hierarchical 0.1 unknown
  holding, reserved-leaf 0.1/0.2, lease lineage, control/review/revocation, SQL process
  failures, peer transport, restore quarantine and incident delivery.

## Scope and next milestone

These are same-host software fixtures with generated identities/keys/clocks and
software mock/SQL targets. Observer correctness, ledger consensus/custody, runtime
OAuth/DPoP/mTLS transcripts, historical control/key/lease lifecycle, target-signed
physical effects, writer/predicate coverage and enterprise owner acceptance remain
open. Frozen schema, fixtures, whitepaper, SQL migration, artifacts and earlier
verification records are unchanged. The bounded static hierarchy software
increment is complete; dynamic delegation/full A2A peers need separate profiles.
M8d next defines durable saga identity/state, registered inverse applicability,
fresh compensation admission and late-effect barriers. Unknown forward outcomes
cannot trigger an inverse. M8e actual governed drain and M9 independent release
acceptance remain open.
