# M8b2 reserved history/refinement — 14 October 2026

Baseline: 0334e9a. [RFC 0039](../../../docs/rfcs/0039-reserved-history-refinement.md)
and the [operator guide](../../../docs/RESERVED_HISTORY.md) deliver explicit
reserved leaf v0.2 enrollment, bounded hash-linked budget history, native signed
receipt refinement and an independently pinned reserved-lineage wrapper/verifier.
Frozen authority/receipt/HTTP records and v0.1 budget holding stay unchanged.

The complete required run passed **331 Rust tests across 46 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips. All **428 source files** remained unchanged
throughout the complete run and match final-source.json. summary.json pins sources,
commands, logs and tools. Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5,
Python 3.13.12, Node 25.2.1 and pinned official MCP client 2.3.0.

## New observations

Eleven new test groups exercise real etcd/native managed authority:

- An original pre-dispatch attempt resolves after expiry/stop to proven no effect
  with a native OutcomeService-signed receipt. Recreated issuers retain original
  allocation/grant/fence; repeated recovery retains one refinement/receipt.
- Dispatched not-found/pending/fenced-no-effect/unknown query reports keep capacity
  unknown. A later correlated original commit refines classification while both
  costs remain held. Resolution after stop creates no new execution permission.
- Eight recovery workers compete; one original refinement is retained. Test-owned
  transaction barriers race recovery's pre-dispatch seal against dispatch and stop.
  The stale receipt/budget transaction fails. Reread preserves unknown after
  dispatch, or seals the original no-effect attempt after stop.
- Two original operations allocate increasing fences and consume an active budget.
  Both proven-no-effect results still hold all forward/compensation units. A third
  operation cannot reuse them. Full history independently verifies either selected
  admission/outcome chain against the shared conserved snapshot.
- Corrupt current head or missing latest event blocks authority. Missing older
  history blocks complete export; no replacement history is synthesized. State-only
  coordination mutation ports refuse v0.2 roots.
- 127 issued allocations fill 255 history events. Another allocation refuses
  without consuming the last free unit or advancing authority. The reserved final
  stop event makes the root inactive; repeated stop appends nothing.
- Closed/duplicate carriage, wrong roots/roles/namespaces/costs/attempts, omitted
  allocation/dispatch/refinement, reordered events, fence substitution, refund and
  capture-time inconsistencies refuse. Correctly re-signed observer checkpoints
  do not bypass semantic replay. Scope arrays are validated before set decoding.
- The shipping offline CLI validates independently approved public pins and reports
  historical classification/held costs with execution authority false. Wrong
  observer/namespace pins refuse.
- The shipping recovery CLI loads generated protected material, validates without
  mutation, refuses missing v0.2 configuration and wrong grant roles, and records
  one original signed pre-dispatch refinement through actual TLS forwarding to
  etcd. Recreated process recovery issues no extra target query/refinement.
- The official SDK workflow traverses native mTLS/DPoP admission/issuance/claim /
  dispatch, then resolves the original committed effect after expiry/stop. Seven
  conserved authority/history events independently verify, with no extra target
  query, broker exchange or effect. A separate Node process resumes status only.

## Retained diagnostic and limits

The [first full attempt](../rfc-m8-reserved-history-2026-10-14-diagnostic/summary.json)
stopped during linking with errno 28 (no disk space), before runtime population
qualification. Its logs/summary were retained byte-for-byte. Cleaning only the
disposable KedgeFlow package build artifacts reclaimed 4.1 GiB; the complete run
then passed against exactly the same source hashes. No functional fix or test skip
was used for that infrastructure failure. Previous evidence is unchanged.

This remains fixed-cost, root-level, single-resource software qualification. The
new SDK provider/broker/effect, keys, query observations and clocks are fixtures.
Existing SQL tests pass separately; these new cases do not accept a reserved SQL
deployment, physical/hardware failures or Kubernetes drain.

History is bounded to 256 events, snapshots to 128 KiB, events to 256 KiB and
bundles to 64 MiB. Exhaustion can block further recorded refinement; held unknown
capacity stays held. No truncation, automatic upgrade, replacement, reactivation,
generation bump or refund is provided. A stop cannot undo a previously authorized
send. The observer attests retained bytes/semantics, not consensus, non-revocation
or an actual target effect. Inner lineage runtime/governance/tool/target gaps and
observer/clock/ledger/custody/restore assumptions remain explicit.

Next M8 work is hierarchical grants and authenticated A2A scope narrowing, followed
by durable saga/compensation and separately governed drain. Accepted writer and
predicate coverage, production custody, hardware and enterprise/independent release
gates remain open. Linux separate-account and minimum Rust CI execution were not
observed locally.
