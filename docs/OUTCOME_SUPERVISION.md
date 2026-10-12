# Run owned outcome supervision

[RFC 0017](rfcs/0017-outcome-supervision.md) composes query-only recovery, durable
unknown incidents and ordered automatic retained delivery. The shipping
`kf-supervise` process discovers recorded attempts, signs observations using the
existing recovery contract and delivers them to the separately authenticated
collector. It never dispatches an effect, releases a consumed root or clears
restore quarantine. The new profile covers internal incident/progress records;
frozen grants, receipts and RFC 0011 delivery carriage remain unchanged.

Start with [supervision.example.json](../config/supervision.example.json).
`recovery` contains the full existing [recovery configuration](RECOVERY_SERVICE.md).
`delivery` pins the collector URL/CA, enrolled reporter certificate/key, access-token
and DPoP seed files, dedicated tenant/conflict domain, reporter subject/scope,
OutcomeService public keys and independent collector acknowledgement keys.
All public key maps and private Ed25519 seed files use standard base64. Replace
public placeholders and provision approved credentials; the example is not live
enrollment. The actually loaded recovery signer/source/grant pins must match the
reporter registration. Out-of-domain discovery refuses before recovery or incident
creation. Tokens, keys, clocks, writer coverage and deployment pins remain trusted.

`incident_policy.owner_id` is a protected operator-enrolled team/service ID.
`unknown_after_ms` ranges from 1 to 604800000; the sample sets 15 minutes. The
first retained unknown journal event fixes the origin and deadline. Restart,
repeated unknown receipts and collector failure cannot reset it. Owner/duration
changes that conflict with an existing incident refuse; transfer/migration is not
implemented. Clock regression also refuses advancement. An incident records
`open`, then `escalated` at its deadline, then `resolved` when a retained committed
outcome is available. Late discovery can retain open/resolved history together.
Resolution preserves execution consumption.

The head and up to three immutable linked events live under the original attempt.
Protected operator library `EtcdLedger::supervision_incident(candidate)` checks the
retained chain and returns current owner/deadline/state. The records are unsigned
operator state, with CAS comparisons against the original execution and current
receipt/attempt; they are not target proof, an external alert or a response from a
human owner. Wire/API routing, paging/ticket integration and ownership handoff
remain enterprise work.

```sh
cargo run --locked --bin kf-supervise -- --config /etc/kedgeflow/supervision.json --check
cargo run --locked --bin kf-supervise -- --config /etc/kedgeflow/supervision.json --once
cargo run --locked --bin kf-supervise -- --config /etc/kedgeflow/supervision.json
```

`--check` validates material/registration without remote queries, writes or reports.
`--once` handles one bounded page and returns nonzero for unavailable entries.
Continuous mode advances recovery-index pages, wraps at the end and polls at the
existing recovery interval; use a process supervisor for deployment. Its cursor
is process-local. Restart safely rescans verified durable progress. A page has
1..64 attempts; `receipt_budget` permits 1..64 previously unrecorded receipts per
attempt per pass. Receipt export is capped at 64 records and 16 MiB. Incident
advancement verifies the current signed head and retained evidence independently;
export capacity refusal cannot suppress an owned deadline. This polling
contract establishes bounded work, not a hard escalation latency SLO.

For each attempt, incident ownership is retained before collector contact. Verify
the full signed receipt/evidence chain, walk oldest first and skip only a valid
local progress record with an exactly correlated signed acknowledgement. Every
missing receipt first queries the collector; an explicit missing acknowledgement
permits reporting that same receipt. Unavailable/invalid lookup stops the attempt.
A lost accepted reply or failed local progress write is resolved by lookup on the
next pass. Local progress is immutable and compares retained receipt/evidence,
original consumption and verified predecessor progress for the same collector.
Concurrent workers can repeat a report; collector idempotency preserves one
acknowledgement. No exclusive network-delivery lease is claimed.

Stats include recovered/deferred/unavailable, incident transitions, delivered
receipts and attempts deferred by receipt budget. `delivered` counts receipts
processed into local verified acceptance progress in that pass, including a
concurrent peer's matching record. A partial pass retains successful progress
and counts it even if a later receipt becomes unavailable. Unknown target queries
can repeat; terminal retained outcomes do not require another target query.

If the namespace is restore-enrolled, add the same independent `restore_gate`
configuration inside `recovery`. All supervisor state uses the shared gate.
Quarantined/unavailable freshness reads prevent resumed cached delivery. The gate
does not cancel network requests already in flight. No pending-witness repair,
allowance refund or stale-state migration is introduced.

[Native tests](../crates/kedgeflow/tests/supervision.rs) qualify deadlines,
concurrent/recreated workers, ordered budgets, collector outage/restart, lost
acknowledgement, failed local progress, invalid progress, scope/signer refusal and
restore-required refusal. Two shipping-binary cases kill/restart after acceptance
and verify continuous polling of a later commit. See [fresh evidence](../results/verification/rfc-m4-supervision-2026-10-12/README.md).
The software query target, JWT/DPoP and mTLS enrollments are explicit fixtures.
Production incident routing, identity/token rotation, managed execution with an
independent restore witness, latency/scale and independent peers remain open.
M5a shared replay and subject-to-workload authorization prerequisites are next.
