# Native multi-contract family saga — 22 October 2026

Baseline: 5deefc23410ea821f6cb1b8e483765d0831a31fd. [RFC 0054](../../../docs/rfcs/0054-multi-contract-family-saga.md)
and the [runtime boundary](../../../docs/FAMILY_SAGA_RUNTIME.md) describe M8d3f:
global phase/epoch enforcement, complete signed native capture, reverse original
inverse ordering and complete aggregate replay in one fresh bounded namespace.

The required frozen-source run passed **473 Rust tests across
55 unique binaries** (56 executions across two
required batches), **26 primary SQL storage/peer/restore groups** and
**23 separate family-batch SQL groups**, **34 Python tests**, three
Node vector suites, formatting, Clippy, Ruff, mypy and frozen schema/whitepaper
checks. Runtime failures, ignored and skipped tests: zero. The exact target/case
manifest matches the combined executed population once; zero-test binaries also
execute. All 543 source files remained unchanged from the pre-run archive
through finalization. source.zip, summary.json, source observations and final
source/evidence hashes pin the tested implementation. Earlier committed results,
frozen inputs and SQL migrations remain unchanged.

## Actual execution and evidence

- Two separately cataloged native SQL contracts execute actual forwards and
  conditional original inverses in reverse dependency order. Fresh qualification,
  admission, issuance, native broker permit and original dispatch are retained.
  Both final rows have version 243 and free reservation; both costs stay held.
- The actual official MCP SDK and FamilySagaRunner execute both inverses. One
  actual SQL COMMIT reply is discarded. Query-only native recovery and a fresh
  Node process recover the same original operation after root stop/expiry, with
  one mint/evidence/baseline/dispatch per child and no second mutation.
  Native host code performs forwards and owner transitions; this does not qualify
  SDK forward execution or shipping owner CLI phase submission.
- Final capture and each forward authority boundary lose their CAS after a real
  native write or permanent stop/quiesce. Original inverse issuance also loses
  against a concurrent qualification update. Competing inverse claims retain one
  original unknown flight slot. A warmed proof cache rejects deleted original
  history, and fresh admission refuses exactly at the original proof expiry.
- A real SQL guard failure preserves the intervening writer and blocks the
  ancestor. Its complete original signed failure receipt is observable as failed;
  dispatched native spend stays unknown and consumed. A negative query alone
  still cannot resolve unknown work. No refund or replacement is introduced.
- Required public artifacts retain complete compensated, unknown and failed
  aggregates, pinned public trust, row observations and SDK wire counters.
  Four separate shipping offline CLI invocations replay their serialized bytes
  without protected config, private keys or live etcd. Re-signed omissions and
  substituted original heads/outcomes refuse in the native tests.

## Diagnostics and limits

Focused diagnostic logs are retained as gzip with original-byte hashes. They
are unfrozen development attempts, not final conformance records. They exposed
nested-future stack size, repeated historical verification exceeding the existing
five-second client window, a fixture missing its real broker permit, and the
missing distinction between a known signed inverse failure and consumed unknown
spend. Bounded full-input historical caches, guarded current read-set validation,
request-private issuer comparisons and batched original reads remove redundant
work while preserving current proof checks and final authority CAS. Production
windows and unknown/retry semantics remain unchanged. A diagnostic SDK attempt
crossed host clamshell sleep; the accepted SDK run completed awake. Temporary
stage timing instrumentation was removed before this source freeze.

This is same-host software qualification with generated identities and a trusted
native fixture clock. Native saga service roles are co-located Rust tasks and
share bounded historical caches; SDK clients and the offline verifier run in
separate processes. Cold-cache, separately deployed service timing is unqualified. Observer correctness, storage consensus, protected clocks,
target assertions and key custody remain assumptions. Historical aggregates
convey no execution authority and do not prove present target state. The source
is draft software, not an independently accepted protocol deployment.

Wider crash/partial-failure combinations, shipping owner-command deployment,
SDK forward orchestration, independent authority peers/whole-saga acceptance,
physical SQL restore/cutover, writer/custody coverage and actual separately
governed Level C Kubernetes drain remain open. M8 is incomplete.
