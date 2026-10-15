# M8d2b2 fresh inverse authority — 15 October 2026

Baseline: 0cca7ea. [RFC 0047](../../../docs/rfcs/0047-native-compensation-authority.md)
and the [operator guide](../../../docs/NATIVE_COMPENSATION_AUTHORITY.md) add the
explicit `KF-COMPENSATION-LEAF-0.1-draft` opt-in. Fresh independently verified
inverse inputs/evidence/Cedar admission produce a mandatory signed compound
binding and spend only from the original held compensation allowance.

The complete required run passed **422 Rust tests across 49 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, both Node suites, formatting,
Clippy, Ruff, mypy and frozen schema/whitepaper checks. There were no failures,
ignored Rust tests or required-mode skips. All **481 source files** stayed unchanged
through the final run and afterward; no source repairs were needed. `summary.json`
pins commands, source and logs. `final-source.json` pins the same source and evidence.
This local Darwin run uses disposable single-host etcd and PostgreSQL with generated
software identities. Separate-account Linux/MSRV, deployed targets, physical
barriers and independent enterprise acceptance remain unobserved.

## New observations

Eight new native groups establish:

- Fresh inverse proposal/registry CTD/manifest/evidence/Cedar verification under
  separately installed inverse controls, exact operation/principal/parameters,
  mandatory signed compound binding/seal and one retained original held spend.
  Reuse preserves the original issuance. Bare public issuance and an inverse
  lane without the execution profile cannot bypass the compound binding.
- Common resource fencing across forward and inverse actions; inverse issuance
  does not allocate another reservation, reduce the original held allowances,
  reset counters or make another inverse operation available.
- A permanent compensation transition requires a current original committed
  proof. Unknown forward children block mode entry. Mode serializes against an
  actual delayed live forward-child claim; no stale attempt is retained.
- Nine native issuance/claim/dispatch transaction races against root stop,
  physical-domain stop and original prerequisite deletion refuse stale authority.
- Claim atomically marks one original inverse attempt unknown. Missing bindings
  and a refreshed qualification head cannot authorize dispatch using old proof.
- Unknown, pending, not-found, failed, partial and fenced-no-effect observations
  keep compensation held. Query-only recovery after expiry/stop refines only the
  original attempt, with duplicate receipt retention and no replacement claim.
- Pre-send expiry produces original proven-no-effect without querying or sending
  to a target, refunding capacity or allowing later dispatch.

## Remaining M8 gates

The protected inverse service selects one exact contract/operation per pair. A
multi-contract family, complete multi-node inverse runner and independently
verified whole-saga history remain open. Synthetic barrier/applicability statements
qualify verifier and native authority software; no actual inverse target or physical
late-effect barrier is asserted by this record. Actual SQL inverse/barrier and
crash/late-effect/partial-failure composition remain M8d3. Separately accepted
Kubernetes Level C drain remains M8e. Dynamic delegation, full independent A2A
peers and enterprise/writer/release acceptance also remain open. M8 is incomplete.

Earlier committed evidence, migrations, fixtures and frozen records remain
unchanged. No global cross-cluster atomicity, refund or retry claim is introduced.
