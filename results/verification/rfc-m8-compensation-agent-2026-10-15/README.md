# M8d3b official SDK inverse workflow — 15 October 2026

Baseline: 6ec50a5. The official MCP client now composes fresh inverse evidence,
admission, native issuance/broker/adapter and actual PostgreSQL restoration.
The protected workflow is described in [the guide](../../../docs/COMPENSATION_AGENT_WORKFLOW.md).

The complete required run passed **430 Rust tests across 51 binaries**, **26 SQL
storage/peer/restore groups**, **32 Python tests**, both Node suites, formatting,
Clippy, Ruff, mypy and frozen schema/whitepaper checks. All **497 source files**
stayed unchanged through and after this run. No failures, ignored Rust tests,
required-mode skips or source repairs occurred. `summary.json` pins commands,
source and logs; `final-source.json` pins the same source and new evidence.

Two new native cases run the official SDK through mTLS/DPoP evidence, control,
broker and gateway services against actual SQL forward/barrier/restore state.
Separate role keys sign proposal/registry/manifest/evidence, admission, grant,
barrier, applicability and original recovery. Protected discovery pins the inverse
profile, exact contract and original five-field parameters. Changed arguments refuse.

The ordinary case commits the original inverse once. The lost-target-reply case
actually commits SQL, discards the reply, and keeps the native original held spend
unknown until independent original query recovery confirms the commit after stop
and expiry. A separate Node process using the same durable store and original QID
returns the same grant/attempt with status-only authorization. No fresh evidence,
admission, issuance, mint or dispatch occurs on this recovery path. Observed SQL
ends at version 243 / fence 2 with the captured original value; counters retain
one original mint and, in the lost-reply case, one target apply.

This is local disposable software qualification with one OS UID and generated
fixture identities. Evidence/capacity providers remain software fixtures; their
use does not establish deployed predicate/writer acceptance. The storage restore
rehearsal still covers the original forward profile. One exact inverse contract
is selected per paired service. Multi-contract families, independent whole-saga
verification/acceptance, inverse crash/restore acceptance, dynamic delegation,
complete independent A2A peers and actual Kubernetes drain remain open. M8 is
incomplete. No refund, mutation retry, scope expansion, physical rollback or global
cross-namespace/cluster atomicity is claimed.
