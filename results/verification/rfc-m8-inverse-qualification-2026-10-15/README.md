# M8d2b1 protected inverse contracts and proof qualification — 15 October 2026

Baseline: c3f298c. [RFC 0045](../../../docs/rfcs/0045-inverse-contract-qualification.md)
and the [operator guide](../../../docs/INVERSE_QUALIFICATION.md) add the explicit
`KF-INVERSE-QUALIFICATION-0.1-draft` prerequisite. It verifies and retains original
committed forward history, a target-signed late-effect barrier and independently
signed inverse applicability. Qualification remains nonauthorizing evidence:
no inverse admission, grant, compensation spend or dispatch is implemented here.

The complete final required run passed **404 Rust tests across 48 binaries**,
**18 SQL storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips occurred. All **469 source files** stayed
unchanged during the final run and afterward. `summary.json` pins tested source,
commands, logs and tools; `final-source.json` pins identical final source, this
bundle and the separately retained preliminary record. No final-run source edits
were needed. Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5, Python 3.13.12,
Node 25.2.1 and official MCP client 2.3.0. `kf-compensation` raises the shipping
binary count to 18. Linux account/MSRV execution, physical targets/barriers and
independent peer/release acceptance remain unobserved here.

The [preliminary run](../rfc-m8-inverse-qualification-preliminary-2026-10-15/README.md)
stopped at Clippy before runtime testing. Its original source/log hashes and logs
remain unchanged. The owned-string comparison was corrected, and a native
clock-regression case was added before this complete final run.

## New observations

Ten new native groups cover:

- Before selected forward issuance, create-only inverse enrollment binds the
  protected RFC 0044 registration/node/operation, exact inverse identity/policy,
  separately signed inverse CTD, registered restore state, compensation cost and
  deadline. Changed contract or complete forward trust cannot adopt it. Enrollment
  after forward issuance refuses. Ordinary native admission/fenced issuance/reuse
  compares absence of the permanent inverse-operation marker; a reserved inverse
  identity cannot be claimed through ordinary native admission.
- The separately signed CTD's action/version/schema/rendering/resource/predicate /
  adapter/tenant/ownership/audience pins verify. Public example registration and
  signed descriptor digests independently match in Rust. The inverse parameters
  remain unsupported by the existing executable leaf mapping.
- Complete original forward admission/input/policy/issuer/history and signed
  committed outcome verify before a barrier or applicability statement can qualify.
  Signed unknown and pre-send no-effect remain refused even with otherwise valid
  target/applicability signers. Both original costs stay held.
- A target barrier and separate applicability signature bind exact original root,
  saga/node/operation/grant/attempt/receipt/resource and exact inverse operation /
  principal/parameters. Correctly re-signed original-identity, source, applicability,
  terminality, late-commit, version, deadline and parameter substitutions refuse.
  Barrier/applicability roles cannot substitute for each other or for input,
  admission, issuer, registry, outcome, observer or composite roles.
- The protected single-version-step restore model requires the original signed
  baseline state digest and version plus one. An intervening version refuses.
  Barrier time follows committed receipt time, applicability follows the barrier,
  and both expire inside the fixed original deadline. Unknown/extra/null fields,
  duplicate JSON keys, wrong-role signatures and expired/future statements refuse.
- Valid qualification/restart preserves the exact original proof and timestamp,
  emits execution_authority=false/fresh_admission_required=true, creates no inverse
  issuance and writes no native budget/claim/outbox state. Duplicate proofs append
  nothing and do not renew expiry. Root stop blocks new qualification; historical
  status exposes expiry/stop and explicitly requires live revalidation.
- A clock regression within otherwise valid statement windows refuses before
  appending an out-of-order record. Full retained history remains valid and readable;
  no timestamp replacement or capacity change occurs.
- Missing original native receipts/admission chains, retained contract/head or prior
  qualification records refuse without synthesis/reset. Exact selected original
  authorization/lease bindings, budget-history events/head, plan/state, attempt /
  context/journal, receipt chain/evidence/head join the actual retention transaction.
  Deterministic native barriers race qualification against stop, original receipt
  deletion and original history deletion; every stale write refuses without a
  budget write or partial qualification.
- Eight concurrent qualifiers retain one original proof. Explicit distinct signed
  observations eventually hit the 32-record or combined transaction bound; existing
  full history and held allowances survive exhaustion. Proofs are bounded to
  512 KiB, comparisons to 96 and transactions to 1 MiB; combined bounds may refuse
  before the nominal record count.
- Separate shipping `kf-compensation` processes use pinned mTLS and fixed etcd
  credentials for local check, enrollment, qualification, duplicate/restart,
  status/history and stop refusal. Offline verification at explicit time performs
  no remote call. The fixture checks every write remains inside inverse contract /
  operation records. Native budgets stay unchanged; there is no target client,
  admission/issuer client, statement signer or executor in the CLI.

The complete prior corpus remains passing, including the refactored shared original
committed-proof checks used by forward DAG authority, official SDK normal/lost reply /
query-only restart, hierarchy/lease/review/control history, query-only saga journal
exhaustion, native SQL failure/peer transport and restore/storage budgets. Frozen
fixtures/schema/whitepaper, SQL migration, artifacts and all earlier committed
verification records remain unchanged.

## Remaining milestone and acceptance

M8d2b2 remains next: an explicitly versioned inverse-capable multi-action control
installation, fresh independently verified inverse proposal/evidence/Cedar admission,
mandatory signed compound inverse binding and one original inverse operation with
atomic compensation-spend linkage. It must preserve the common physical resource /
conflict domain/fence scope and recheck current original outcome, applicability,
barrier, deadline and stop at issuance/reuse/claim/dispatch. Qualified evidence alone
cannot satisfy those gates or broaden a frozen grant.

M8d3 must implement and qualify the actual inverse target/barrier, late effects,
external writers, partial/failed/unknown compensation, process loss and complete
independent saga evidence. Synthetic signer statements establish verification
software only, not target behavior, physical barriers, production custody or writer
coverage. Existing inner authentication/control/clock/observer/ledger trust gaps
remain explicit. Dynamic delegation, complete A2A peers, M8e actual Kubernetes drain
and enterprise/physical/release acceptance remain open.
