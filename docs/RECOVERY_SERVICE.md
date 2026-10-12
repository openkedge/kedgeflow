# Run query-only recovery and verify retained outcomes

[RFC 0010](rfcs/0010-outcome-recovery.md) implements bounded M4a for recorded
single-resource attempts. The gateway retains execution context and transition
history automatically. A separate worker inspects expired claimed work and unknown
attempts, records signed KF-JSON receipts and preserves consumed authority.

Start from [recovery.example.json](../config/recovery.example.json). Provision
trusted issuer keys, an independent OutcomeService signing seed, protected etcd
mTLS/token material and a fixed target query service with query-only credentials.
The sample has public placeholders and private-material paths, not deployment
credentials. Grant/receipt signer overlap refuses. Keys and configuration must
be administered independently of the agent.

```sh
cargo run --locked --bin kf-recover -- --config /etc/kedgeflow/recovery.json --check
cargo run --locked --bin kf-recover -- --config /etc/kedgeflow/recovery.json --once
cargo run --locked --bin kf-recover -- --config /etc/kedgeflow/recovery.json
```

`--check` validates material without remote queries/writes. `--once` processes
one page, not the whole namespace. Normal mode advances pages, wraps at the end,
backs off under the configured interval and stops on Ctrl-C; use a process
supervisor for deployment. Stats report examined/reported/deferred/unavailable
entries. A reported unknown receipt keeps the attempt unresolved and consumed.

The configured query URL accepts only RFC 0010's closed POST request and returns
authenticated original AttemptID/RootID/GrantDigest/Status/TargetReference. The
worker never calls an execution endpoint, exchanges credentials, retries an effect
or restores allowance. Target state retention and authoritative-query semantics
must be qualified by the target owner. HTTP success alone cannot prove commit.

Active claimed work is deferred until its signed dispatch budget expires. A CAS
seal can prevent dispatch only when the durable outbox is still pre-dispatch.
After dispatch authorization, absent/pending/unavailable status remains unknown;
only a correlated authoritative commit resolves it. Revocation/expiry cannot
prove no effect. Concurrent workers can repeat queries, and only one snapshot
records a report. A killed worker needs no lock expiry or authority restoration.

The library's protected `EtcdLedger::export_outcomes(candidate)` exports a bounded
bundle of exact grant/parameters, receipts, evidence and journal. Feed it to the
separate verifier with trusted public keys/source obtained through your approved
registration, never from the bundle:

```sh
cargo run --locked --bin kf-verify-outcomes -- \
  --trust /protected/audit/outcome-trust.json --bundle /protected/audit/bundle.json
```

Trust fields are gateway_audience, grant_keys, outcome_keys and source_id; key
maps use base64 Ed25519 public bytes. The bundle contains the RFC 0010 profile,
execution, attempt_id, receipts, evidence and journal. The command verifies the
grant/receipt chain and reports missing full-lineage links explicitly. Artifacts
can contain sensitive parameters/evidence and require authorized storage/disclosure.
Exports are limited to 64 receipts; the CLI input ceiling is 4 MiB. No network or
private key is needed by the offline verifier.

Source role OutcomeService attests the worker's retained observation. It is not
a target signature. The receipt retains the frozen fixture's parameters_digest
as effect_digest; resolution_evidence references the actual canonical observation.
Standalone legacy claims without exact signed context are excluded from discovery.
No automatic migration, pruning, refund, compensation or restore is implemented.

See [fresh verification](../results/verification/rfc-m4-recovery-2026-10-11/README.md).
Full M4 remains open for complete admission lineage, authenticated external reports,
incident deadlines, key history, gateway/target hard-crash coverage and stale-backup
restore fencing. Software target/identity/etcd-role fixtures do not establish an
enterprise deployment or real-target writer coverage.
