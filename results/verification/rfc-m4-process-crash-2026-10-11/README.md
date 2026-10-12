# M4c1 process termination — 11 October 2026

Based on `26dcebe` plus working-tree source hashes in [summary.json](summary.json).
This qualifies the bounded Unix software matrix in
[RFC 0015](../../../docs/rfcs/0015-process-crash-qualification.md); see
[qualification instructions](../../../docs/PROCESS_CRASH_RECOVERY.md).
Prior verification evidence remains unchanged.

| Check | Result |
| --- | --- |
| Required workspace/native suite | 147 passed; zero failed, ignored or skipped; actual etcd and official SDK required |
| New process matrix | Nine cases run actual `kf-proxy`/`kf-recover`, force SIGKILL, await termination, restart and check original correlation |
| Test-owned barriers | Verified mTLS transport blocks before submitting selected transactions or after successful etcd writes; no production hooks |
| Restarted consumed grant | New RPC ID and DPoP proof resolve original `NONCE_CONSUMED`; no second claim/exchange/dispatch |
| Expired status / worker restart | Repeated current-authenticated status and workers preserve original attempt and receipt identity |
| Authority conservation | Original nonce stays held; replacement/new claims refuse; recovery never dispatches or refunds |
| Offline outcomes | Every claimed case retains one signed receipt with correlated grant/evidence and passes offline verification |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Node vectors | Pass |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema / signed fixtures | 13 signed envelopes and declared bindings pass |

## Reached boundaries and observed counts

Counts below cover the initial execution, all restarts, status queries and refused
retries. `Q` counts target queries; queries can repeat for unresolved outcomes.
Every row has zero additional successful claims, credential exchanges, dispatches
or commits after the killed execution. Before-claim work was never consumed.

| Barrier | Before recovery → after | Claims | Exchanges | Dispatches | Commits | Q | Receipts |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Before claim submission | unclaimed → unclaimed | 0 | 0 | 0 | 0 | 0 | 0 |
| Claim persisted, reply withheld | claimed → not_dispatched | 1 | 0 | 0 | 0 | 0 | 1 |
| Before dispatch authorization | claimed → not_dispatched | 1 | 1 | 0 | 0 | 0 | 1 |
| Dispatch authorization persisted, reply withheld | dispatch_authorized → unknown | 1 | 1 | 0 | 0 | 2 | 1 |
| Target commit, reply withheld | dispatch_authorized → committed | 1 | 1 | 1 | 1 | 1 | 1 |
| Target reply, before terminal write | dispatch_authorized → committed | 1 | 1 | 1 | 1 | 1 | 1 |
| Terminal write persisted, reply withheld | committed → committed | 1 | 1 | 1 | 1 | 0 | 1 |
| Before receipt/head write | committed → committed | 1 | 1 | 1 | 1 | 0 | 1 |
| Receipt/head persisted, reply withheld | committed → committed | 1 | 1 | 1 | 1 | 0 | 1 |

Each `crash matrix:` JSON line in [rust-tests.log](rust-tests.log) records the
asserted boundary, pre/post state, counts, receipt population and SIGKILL/reaping
confirmation. The full suite includes the earlier native query-worker kill case.

## What was exercised

The parent hosts test-owned mTLS ledger, broker, target and query routes. Shipping
gateway and worker binaries use their normal operator configs and HTTPS clients.
The proxy authenticates separate gateway/outcome workload IDs and role tokens,
then forwards actual etcd transactions. Before-submit barriers never forward the
pending request. After-submit barriers notify only after etcd succeeds. Scoped
server cleanup aborts blocked connection tasks; children use kill-on-drop cleanup.
All asserted kills occur while the PID is alive and are reaped with signal 9.

Software JWT/DPoP and mTLS authentication bind the caller and grant. The software
broker checks the signed grant, exact subject/actor data and original claimed
attempt before a short target credential. The mock target validates resource
incarnation, version and monotonic fence, then updates and retains correlated
attempt/grant state atomically under a mutex. Query uses a separately authenticated
recovery workload and token. The target and host remain running.

After a successful claim, immediate retry against the restarted gateway resolves
the original attempt. After expiry, three status queries and two completed worker
process invocations leave effect/exchange/claim counts unchanged. Recovery queries
an unresolved possible send, treats not-found as unknown, and keeps consumption.
Once committed, later workers reuse the terminal receipt without another query.
Receipt/head persistence before a lost response preserves exact stored bytes on
restart. Every claimed case exports and verifies its signed outcome chain.

## Reproduction and qualification limits

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
PYTHONPATH=src python scripts/verify-whitepaper.py
PYTHONPATH=src python spec/validate.py
git diff --check
```

Executed on Darwin ARM64 with Rust 1.98.0, Node 25.2.1 and etcd 3.6.5 across three
single-host loopback members. Rust 1.88 / Node 20 minimums remain execution-unqualified.
The tested etcd release archive SHA-256 is
`14d7743f9ed07950a8e85491646e067e394a09e049e42083e2f6473fefa717a8`.
Logs: [clippy](clippy.log), [format](format.log), [Node vectors](node-vectors.log),
[frozen paper](whitepaper.log), [schema](schema.log). Trailing whitespace and final
blank lines are normalized for repository review.

The matrix uses operator-bootstrapped signed fixture grants and explicit unmanaged
gateway configuration. It does not qualify full admission lineage or managed
installation/renewal across process kills. Existing managed-control and historical
lineage tests pass separately. Software CA/enrollment, role tokens and actor
assertions are fixtures; this does not qualify a production authorization server,
broker, ledger RBAC, shared DPoP replay or credential custody.

The target is an atomic **in-memory software resource**. Its commit/query evidence
is not target-signed or independently durable. These cases qualify forced process
termination while etcd, target and host remain live. Target-process failure,
host/power loss, stale-backup restore quarantine, durable real-resource recovery,
owned incidents and independent-peer enterprise acceptance remain open.

Next is M4c2 restore quarantine with an independently retained authority high-water
mark. No restore activation or automatic authority restoration is introduced here.
