# M8c2 static hierarchical leaf authority — 14 October 2026

Baseline: bcc7ef0. [RFC 0041](../../../docs/rfcs/0041-static-hierarchical-leaf-authority.md)
and the [operator guide](../../../docs/HIERARCHICAL_LEAF_AUTHORITY.md) add an
explicit compound profile: signed nonexecutable composite capacity, protected
subject/workload parent assignments, independently admitted frozen leaf grants,
mandatory issuer-signed parent bindings and atomic child-cost/issuance retention.
The frozen grant still refuses parent/saga execution variants.

The final required run passed **358 Rust tests across 46 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips. All **441 source files** remained unchanged
during the final complete run. summary.json pins tested sources, commands, logs
and tools; final-source.json pins committed sources and the one documentation-only
whitespace adjustment below. Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3,
etcd 3.6.5, Python 3.13.12, Node 25.2.1 and official MCP client 2.3.0.

## New observations

Fifteen new groups plus the expanded shipping control lifecycle exercise:

- Fresh native managed admission/issuance creates an exact signed leaf binding to
  the selected composite parent. Recreated issuers return the same operation,
  grant, parent, costs and fence. Claim binds one original attempt and marks the
  leaf unknown; dispatch compares that lineage. Native stop is permanent and
  idempotent; privileged historical binding verification still works afterward.
- Eight independently admitted contenders compete for one parent's last slot.
  Exactly one child issues. Every retained child allocation has its matching
  signed issuance; composite costs remain conserved. An earlier fence alone
  creates no capacity or executable grant. Raw admitted/allocated/grant issuance
  cannot synthesize the required compound binding.
- Two independently admitted subjects issue under separately narrowed static
  branches. Sibling contention may safely refuse; retries after confirmed refusal
  first resolve the same stable operation. Both parents conserve their own budgets;
  a fresh task/operation cannot spend an already full branch.
- Correctly re-signed wrong tenant/root/generation/ownership/contract, wider scopes
  or principals, overdraw, invalid ancestry/time containment, excessive depth,
  duplicate grants/assignments and unsupported profile combinations refuse.
  A fresh leaf cannot outlive its parent. The signed public demonstration
  registration independently verifies in Rust.
- Composite records and frozen leaf grants with non-null parent fields cannot
  execute. Correct issuer signatures do not bypass wrong parent/operation/cost /
  certificate correlation. Missing/null parent bindings, wrong profile/key pins
  and legacy reinterpretation refuse. Valid legacy serialization omits the new
  optional fields, preserving old registration/binding signature values.
- Omitted configuration, changed parent assignment and unassigned identities
  refuse. State-only coordination allocation/consumption/refinement/stop cannot
  bypass the native hierarchy. Raw generation replacement refuses.
- Missing or substituted original composite records, executable-parent state and
  modified child costs refuse at native issuance/claim/dispatch. Restoring the
  test-owned original bytes permits the original valid transition; nothing is
  synthesized or refunded.
- Deterministic etcd transaction barriers race root stop against early fence,
  atomic child-cost/issuance, claim and dispatch. Stale transactions refuse. A
  stopped issuance leaves no child cost or grant; stopped claim preserves its
  issued allocation; stopped dispatch preserves the original unknown attempt.
- Native recovery after expiry/stop signs one original pre-send no-effect receipt
  without target queries. Repeated recovery retains that receipt. Hierarchical
  budget state/costs remain unknown and held; ordinary complete lineage export and
  state-only refinement refuse. Recovery authorizes no new operation or inverse.
- Composite keys overlapping admission or registered input/evidence roles cannot
  produce a native child. Delegation and leaf issuer keys also require disjoint
  approved public pins.
- The shipping offline CLI recognizes the explicit profile, verifies separately
  pinned static ancestry and exact leaf/parent binding, reports no execution /
  live-budget permission, and refuses wrong delegation keys. It does not
  reconstruct complete admission/role history.
- The shipping control CLI now runs both legacy and hierarchical enrollment /
  permanent-stop cases against actual mTLS forwarding to etcd. Protected checks
  publish nothing, enrollment is create-only, stop persists and configuration
  drift refuses. No agent HTTP parent/cost/enrollment endpoint is added.
- Two official SDK cases traverse actual managed mTLS/DPoP admission/issuance,
  native compound claim/dispatch and a fenced software effect, including a lost
  execution reply. A separate Node process resolves the same consumed grant and
  original attempt after expiry/stop/revocation, with no additional broker mint,
  target call or effect. Composite reservations stay nonexecutable and leaf costs
  stay unknown/held.

## Canonicalization review and provenance

The [preliminary complete run](../rfc-m8-hierarchical-leaf-2026-10-14-precanonical/README.md)
passed before review identified normalization of unordered signed scopes. Its
original logs/summary were preserved byte-for-byte; it is not final parser
acceptance. The corrected receiver requires unique signed scope strings in
ascending UTF-8 byte order and uses strict duplicate-field/safe-integer parsing.
Reordered values and duplicate signed fields now refuse before set decoding.
New regression assertions preserve exact signed JSON semantics without changing
frozen wire records. The complete final corpus then passed against the corrected,
unchanged sources. final-source.json pins both runs' evidence and the six changed
review-fix source hashes. No prior committed evidence was edited.

After the full run, one trailing space in the operator guide was removed to pass
the staged whitespace check. All runtime sources and the other 440 source files
match the full-run hashes exactly. final-source.json separately pins the tested
and committed guide hashes; this one-byte prose cleanup requires no runtime retest.

Disposable package build outputs were cleaned before each complete run to keep
within host disk capacity. No source fix, evidence overwrite or test skip was used
to hide an infrastructure failure; neither complete run had one.

## Limits and next milestone

This is a static, generation-one skeleton of at most 16 composites/assignments,
seven composite levels plus a leaf, 16 KiB per composite and 128 KiB registration.
Snapshot limits remain 128 KiB, 256 allocations and depth eight. Every executable
leaf uses one exact fixed action/resource/incarnation/predicate/adapter/audience
and fixed costs. A fence alone consumes no hierarchical capacity. No dynamic
recursive delegation, branch withdrawal, transfer, replacement, reenrollment,
rotation, generation bump or refund is provided. Stop cannot undo an earlier
send authorization.

The profile does not upgrade reserved v0.2 or inherit its complete history. Native
outcome receipts may refine ordinary effect observations, while hierarchical
budget classification stays unknown/held. Offline verification proves static
signatures and correlation, not complete signed hierarchical history, admission /
role lifecycle, current permission, consensus or actual target effects.

Keys, clocks, OAuth/evidence/broker services, target and TLS forwarder are local
software fixtures. Existing SQL tests pass separately; these new cases do not
accept an enterprise hierarchical SQL deployment, physical durability/custody,
hardware, complete/independent A2A peers or actual Kubernetes drain. Minimum Rust
and Linux separate-account CI execution were not observed locally.

Next is M8c3: complete bounded hierarchical authority/outcome history and independent
replay without refunds. Dynamic delegation/wider executable profiles, M8d durable
saga/compensation, M8e governed drain and enterprise/independent release acceptance
remain open.
