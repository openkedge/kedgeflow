# M4c2 restore quarantine — 11 October 2026

Based on `a12cdab` plus the final working-tree source hashes in
[summary.json](summary.json). This qualifies the bounded draft contract in
[RFC 0016](../../../docs/rfcs/0016-restore-quarantine.md) and the
[operator guide](../../../docs/RESTORE_QUARANTINE.md). Prior evidence is unchanged.

| Check | Result |
| --- | --- |
| Required workspace/native suite | 158 passed; zero failed, ignored or skipped; actual etcd and official SDK required |
| Restore cases | Ten native integration cases; separate witness etcd process/data directory per case |
| Operator CLI | Actual `kf-restore` empty enrollment and status over verified software mTLS and separate role tokens |
| Draft schema | Closed witness/head fields, state names and safe-integer sequence bound checked |
| Existing process crash matrix | All nine shipping gateway/worker SIGKILL cases continue passing |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Node vectors | Pass |
| Frozen white paper | 58 files and 24 pins unchanged |
| Frozen signed fixtures | 13 envelopes and all declared bindings pass |

## Observed cases

The named tests and their results are in [rust-tests.log](rust-tests.log).
Each harness executes the shipping enrollment CLI before its case, using distinct
local/witness HTTPS origins and test-owned proxies that verify workload identity
and separate role tokens. The proxies forward to actual, separate etcd clusters.
The authority fixture has three members; each witness is a separate single member.

| Case | Asserted result |
| --- | --- |
| Stale snapshot after fence allocation and claim | Gate, fresh claim, policy write and fence allocation refuse; witness unchanged; re-enrollment refuses |
| Exact latest snapshot restored | Status succeeds; original nonce stays consumed; retained fence is reused without resetting |
| Empty / pre-enrollment local snapshot | Missing local head refuses despite independently retained ready witness; enrollment cannot overwrite it |
| Omitted gate; foreign or missing witness | Current unconfigured client refuses enrolled marker; pinned client refuses witness mismatch/absence; no local change |
| Reservation persisted, reply lost | Pending witness; local state unchanged; subsequent authority/status refuses |
| Local commit persisted, reply lost | Local head advances to pending witness head; no automatic finalization; subsequent calls refuse |
| Witness process outage | No authority write or successful freshness check; local state unchanged |
| Concurrent mutations and restarted status CLI | At least one write succeeds; heads converge exactly; read-only status does not advance sequence |
| Nonempty enrollment through fresh witness | Local range comparison refuses; no local change; repeated enrollment cannot clear pending state |
| Finalization persisted, reply lost | Ready equal heads permit checks; original attempt stays consumed and retry returns nonce-consumed |
| Local head changed during reserved write | Outer local CAS refuses application policy/ownership writes; witness stays pending and calls refuse |

The stale-snapshot test also verifies certificate-constrained input validation and
uses the actual issuer-owned fence allocator. It does not run full native admission
or managed governance through the restore: those paths are separate earlier tests.

## Conservation and limits

Every runtime ledger transaction goes through the shared gate when configured.
A mutation reserves the independent next head, then an outer local CAS runs the
original nested transaction and stamps that head atomically. This protects both
original branches. A validated response is returned only after witness finalization.
A failed original comparison can consume a sequence without conferring authority.
No sequence/nonce refund, automatic pending repair, force override or fence reset
exists. Missing/foreign/pending state and unavailable dependencies fail closed.

The unsigned witness is an authenticated store assertion from trusted writers;
the digest chain is correlation, not a signed proof. Exclusive guarded-writer
coverage, independently retained deployment pins and witness survival are required.
A local marker cannot detect its own absence in a pre-enrollment backup without
the independent configuration. Older binaries, raw writers, changed trusted pins
or restoring both stores are outside this claim.

The tests copy a stopped authority prefix and retain the witness process/data,
then restore local records under test-owned privileged credentials. They do not
exercise production etcd snapshot tools, target effects under restore, hardware
failure, separate physical failure domains, production RBAC or key custody.
Earlier process-crash tests remain explicitly unmanaged and do not establish
combined managed-service kill behavior with the new gate. Namespace-wide write
serialization and fail-closed ambiguous reservations favor conservation over
availability; pending repair, live migration, scalability and owner acceptance
remain open. M4c3 owned incidents and bounded automatic delivery is next.

## Reproduction

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
PYTHONPATH=src python scripts/verify-whitepaper.py
PYTHONPATH=src python spec/validate.py
```

Executed on Darwin ARM64, Rust 1.98.0, Node 25.2.1, etcd 3.6.5, using the archive
pin recorded in the summary. Declared Rust 1.88 and Node 20 minimum runtimes remain
execution-unqualified. The required wrapper sets `ETCD_ENDPOINT` and prohibits
skips. The restore tests additionally use `ETCD_BINARY` to start disposable witness
processes and reap them on cleanup. All clusters remain on the same host.
