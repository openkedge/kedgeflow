# M3a live client and replay/status verification — 11 October 2026

This increment follows committed control-lifecycle checkpoint `940813d`. It
implements a bounded live Node Agent Adapter and query-only retained status.
The full M3 release gate remains open. Source and log hashes are recorded in
[summary.json](summary.json).

| Check | Result |
| --- | --- |
| Locked Rust workspace, all targets | **101 passed**, zero failed/ignored/skipped |
| Required infrastructure | Three real etcd 3.6.5 members; pinned official MCP client 2.3.0 |
| New acceptance cases | Four gateway replay/status cases, retained grant verifier case, two live official-client cases, Node negative vectors |
| Live Node processes | Four: normal/lost-response first runs and two resumed query-only clients |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema and signed fixtures | 13 envelopes and declared bindings pass |

Logs: [workspace and client wire summaries](rust-tests.log),
[Node validation vectors](node-vectors.log), [clippy](clippy.log),
[white paper](whitepaper.log), [schema](schema.log).
Trailing whitespace and final blank lines are normalized for repository review.
The final full run includes the completed target-derived baseline/witness binding,
expired/revoked status, and bounded client storage/transport checks.

## What this establishes

An unmodified official MCP client discovers the registered consequential tool
and negotiates governed-call/status profiles. The Node adapter checks remediation
against pinned endpoint/action/parameters/expiry, obtains the mock target's current
baseline through a protected software provider, freezes/signs the exact proposal,
and collects a fresh provider-signed witness/manifest bound to its digest and
observed state digest. It holds proposal/PoP keys, not provider, issuer or
administrative keys. Native admission verifies the complete inputs and Cedar;
native issuance produces a fresh grant and resource fence. No fixture grant or
certificate is supplied to these two live-client cases.

Native mTLS enrolls the agent workload. Actual pinned JWT and Ed25519 DPoP
verification bind the same delegated token/audience across admission, issuance
and gateway, with a fresh proof JTI/URL binding for every HTTP request. The broker
and guarded target are explicit software boundaries. Their counters establish
one exchange, one dispatch and one mock effect; baseline and evidence acquisition
also occur once. The software target checks version/fence and changes capacity
and version atomically under its mutex.

The client persists exact proposal/evidence and grant before execution. In one
case the HTTP execution result is discarded after the server has completed it;
the adapter resolves the original committed attempt without another tools/call.
For each case, a new Node process loads the operation after grant expiry and
signed domain revocation. A renewed status-only token resolves the same attempt
and grant digest. Repeated execute/status and changed-parameter refusal add zero
provider collections, exchanges, dispatches or effects.

Gateway tests separately resolve a lost committed claim reply without exchange,
return the original attempt on fresh-RPC-ID nonce replay, and authorize expired
history under a changed current delegation. Missing status permission, changed
subject/PoP, unknown fields, fabricated attempt IDs, unexpected grant headers and
corrupted attempt/outbox correlation refuse. Ledger status uses linearizable
correlated reads and performs zero writes or recovery/target operations. Unknown
or missing records never become no-effect evidence. Execution still requires
current grant validity; retained verification cannot make an expired grant execute.

Node vectors reject duplicate keys, unsafe/noninteger JSON, unpaired surrogates,
wrong signatures/roles, substituted/expired remediation and unapproved transport
routing. Exclusive store ownership, ordinary restart and bounded writes/readback
are checked. The native gateway additionally bounds owned tasks after disconnect.

## Reproduction and limits

```sh
npm ci --prefix tests/sdk
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
node tests/sdk/agent-vectors.mjs
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python scripts/verify-whitepaper.py
python spec/validate.py
```

Host: macOS ARM64, Rust/Cargo 1.98.0 and Node 25.2.1. The declared Rust 1.88 and
Node 20 minimums are not execution-qualified. No dependencies or lockfiles changed.
Cargo used the existing cache/target paths under `/private/tmp`. The verified
official etcd archive SHA-256 is
`14d7743f9ed07950a8e85491646e067e394a09e049e42083e2f6473fefa717a8`;
three disposable loopback members ran in required mode with owned cleanup.
Python freeze/schema commands used the existing environment/cache. The unchanged
Python runtime's prior **32 passing tests** are historical; its suite was not repeated.

Certificates/keys, provider, credential broker and target are software fixtures.
A fixed trusted fixture clock makes validity boundaries deterministic; TLS itself
uses actual certificate validity. The native tests establish cryptographic
transport/permissions, not enterprise enrollment, least-privilege production etcd
RBAC, shared DPoP state, OS isolation or real target writer coverage. A distinct
software test CA subject fixes Node/OpenSSL chain interoperability; verification
was not disabled. The adapter follows the SDK's normalized complete-result shape.

The operation store is checked across ordinary process restart. This does not
qualify power loss, stale backups, partial persistence or automated crash-lock
recovery. A missing local grant remains uncertain: authorized operation lookup
and resolution of ambiguous issuer replies beyond expiry are **M3b**. Historical
key/tool/PoP migrations, wider provider/client fault cases and release owner
acceptance remain open. Status returns retained state, not a reconstructed signed
target receipt. Recovery/outcome evidence is **M4**; enterprise trust and a real
target remain later gates. See [RFC 0008](../../../docs/rfcs/0008-agent-replay-and-status.md),
the [adapter guide](../../../docs/AGENT_ADAPTER.md) and
[plan](../../../docs/IMPLEMENTATION_ROADMAP.md).
