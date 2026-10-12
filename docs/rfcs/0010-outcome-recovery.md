# RFC 0010: Retained execution journal, query-only recovery and signed outcomes

- Status: Draft
- Profile/version: `KF-OUTCOME-RECOVERY-0.1-draft`; receipts retain KF-JSON-0.2
- Milestone: bounded M4a; reporting/full lineage/restore qualification remains M4b
- Baseline: `c312711`, RFCs 0004, 0008 and 0009
- Owners/reviewers: unassigned; runtime, resource, security and SRE owners

## Problem and scope

A process can stop after claim, dispatch authorization or target commit, before
recording a terminal result. The overwritten outbox alone loses transition history.
The existing explicit reconciliation helper handles only already-unknown attempts
and supplies no signed outcome chain. This increment adds durable execution context,
append-only transition/report records, an indexed polling worker and an offline
receipt-chain verifier for the current one-resource, dispatch-bound profile.

Recovery performs queries and authority-preserving state recording. It has no
credential exchange, target dispatch, compensation, allowance refund or root
replacement operation. Active claimed work is deferred until its signed dispatch
budget expires. Expiry makes work eligible for inspection; durable facts and CAS
establish whether dispatch was prevented. Age alone cannot prove no effect.

## Authority and trust

The gateway verifies the signed grant and exact caller/action/parameters before
claiming. Its recorded-claim API atomically retains the signed grant, tool name,
exact parameters, consumed root/nonce, attempt, claim journal and recovery index.
It retains no raw subject access token, DPoP private key or target credential.
Custom ledgers must explicitly implement recorded claims/outcomes; unsupported
implementations refuse instead of silently losing required evidence.

The worker is a protected operator-side process with configured etcd credentials,
pinned issuer keys/audience, fixed target query URL, separately provisioned query
mTLS/read credential and a distinct OutcomeService signing key. It has no listener
or agent-callable administrative interface. Its signing key cannot overlap the
configured grant keys. Production workload/key custody and least-privilege etcd
roles remain M5 qualification; software role fixtures do not establish deployment
isolation. The worker does not require current execution authority to inspect
expired/revoked history.

Native query transport uses explicit CA/client certificates, verified TLS 1.3,
HTTP/1.1, exact HTTPS URL, redirect rejection, five-second deadline and 64 KiB
response bound. The target authenticates the worker and restricts its credential
to query access. A channel-authenticated response is an observation, not a target
signature. Actual target retention/linearizability/restore semantics require the
resource owner's adapter contract and M6 qualification.

## Retention and atomic boundaries

The compatible root/grant/nonce/attempt/outbox layout remains. New records retain
claim, dispatch_authorized and terminal transitions under the attempt's journal.
Claim/dispatch/terminal updates and their journal records share the authority
transaction; existing journal entries cannot be overwritten by those transitions.
A known adapter terminal result is retained as canonical JSON in the terminal
transaction, before the gateway returns success. Recovery retains distinct queried
observations and immutable signed receipt envelopes by digest, with a mutable
receipt-head pointer updated in the same transaction.
The existing explicit reconciliation helper retains its commit observation in
that transaction too, so a later outcome receipt does not inherit pending evidence.

The index contains only recorded claims. Legacy claims lacking exact signed
execution context are excluded; no automatic context fabrication or migration
occurs. A bounded page scans 1–64 entries and advances a namespace-bound opaque
cursor. Terminal entries remain retained and are cheap to revisit. Malformed
index pages fail closed and require operator investigation. No queue deletion,
retention pruning or safe stale-backup restoration is supplied by this profile.

## Recovery transitions

| Durable state | Recovery action | Result |
| --- | --- | --- |
| claimed; signed dispatch budget active | Defer without target query or mutation | claimed |
| claimed + claimed_not_dispatched; budget expired | CAS against exact attempt/outbox/context/root/grant/nonce/index/head | not_dispatched, consumed |
| claimed + dispatch_authorized; budget expired | Query exact original attempt; CAS result | committed if correlated authoritative commit; otherwise unknown, consumed |
| unknown | Bounded authoritative query | committed if correlated commit; otherwise unknown, consumed |
| terminal | Retain/report original terminal evidence; reuse matching receipt head | Same terminal state, consumed |

A pre-dispatch seal and dispatch authorization compare the same outbox. Exactly
one can win. If dispatch authorization won, recovery cannot produce an undispatched
seal. A delayed gateway loses its dispatch CAS after a seal. Missing status,
not_found, pending, query errors, uncorrelated observations and even an unsupported
target no-effect label remain unknown after a possible send. This increment does
not implement target-specific no-effect barriers.

Multiple workers may query concurrently because queries confer no effect. They
compare the complete attempt/outbox/context/root/grant/nonce/index and previous
receipt head before recording results. One snapshot wins; stale workers defer
and reread on the next sweep. There is no expiring lock or takeover that reopens
authority. A killed worker can leave an ambiguous ledger reply; a restart reads
retained state/head. Terminal state never regresses and a committed result is
not replaced by a later missing-status observation.

## Query and signed outcome contract

The [closed draft schema](../../spec/drafts/outcome-recovery-v0.1.schema.json)
defines query, observation, transition, execution-context and receipt-head shapes.
The worker POSTs:

```json
{"profile":"KF-OUTCOME-RECOVERY-0.1-draft","operation":"query","attempt_id":"original-attempt"}
```

The response contains exactly AttemptID, RootID, GrantDigest, Status and
TargetReference. Correlation must match retained authority. Supported observation
labels are committed, pending, unknown, not_found, not_dispatched and
fenced_no_effect. Only correlated committed resolves a possible send in M4a.
Invalid/missing status and query outages preserve consumed unknown.

Receipts use the existing frozen Receipt envelope/schema and Ed25519/JCS rules.
They bind proposal/certificate/grant digests, root/generation, original attempt,
fence, configured source_id and source_role OutcomeService. Status maps directly
for committed/not_dispatched/unknown; state_guard_violation maps to failed with
STATE_GUARD_VIOLATION. It does not claim fenced_no_effect or restore allowance.
Event time is trusted worker UTC milliseconds. Missing observed version remains
null; an uncorrelated target reference cannot become a resource operation ID.

The frozen fixture's effect binding is preserved: effect_digest equals the grant's
parameters_digest. It identifies the intended action rather than authenticating a
physical effect. Actual canonical adapter/query evidence is separately retained
and referenced by digest in resolution_evidence using
urn:kedgeflow:draft:recovery:evidence:0.1. Gateway/OutcomeService signatures attest
their report and correlation; they do not become target-signed commit proof.

Reports have deterministic identity over grant/attempt, state, evidence digest and
previous receipt digest. The durable winning envelope includes its event time.
Duplicate workers or lost recording replies reread/reuse that envelope; they do
not return a fresh signed candidate as a durable result. Different observations
while unknown produce linked receipts retaining earlier evidence, including
uncorrelated/contradictory observations. Authenticated external outcome-report
submission/acknowledgement and incidents remain M4b.

## Worker and offline verifier

`kf-recover --config FILE --check` validates local material without remote access.
`--once` processes one bounded page; unavailable entries give a nonzero exit.
Normal mode polls under configured page/rate bounds, retries authority outages,
defers active/stale snapshots and stops on Ctrl-C. Stats distinguish reported,
deferred and unavailable entries; reporting unknown does not claim resolution.
Deploy it under the operator's process supervisor. This repository does not
start a background worker automatically.

A protected library export returns the retained signed grant, parameters,
ordered receipt chain, referenced evidence and journal. `kf-verify-outcomes`
accepts an offline bundle and a separate trusted key/source configuration. It
validates signatures, distinct signer roles, exact grant/parameter/attempt/root/
fence/source bindings, predecessor ordering, evidence digests and monotonic
receipt transitions. Substitution, missing predecessors/evidence and contradictory
terminal transitions fail.

The verifier explicitly reports missing proposal/certificate/manifest/witness,
installed control/key history, independently authenticated journal and target-signed
proof links. This is grant/receipt-chain verification, not complete independent
reconstruction of admission and a target effect. Key history and complete lineage
export/verification remain M4b. A valid receipt cannot erase those missing links.

## Compatibility and implementation evidence

Frozen artifacts and public MCP/status carriage remain unchanged. New fields are
internal retained records and a separate worker query profile. Current gateways
require recorded ledger support; existing operator configurations need no worker
settings until recovery is separately enabled. Rollback preserves all consumed
roots, context, index and receipt/history records.

Implemented in recovery.rs, recovery_ledger.rs, recovery_config.rs, the gateway/
ledger and two new binaries. See [the fresh evidence](../../results/verification/rfc-m4-recovery-2026-10-11/README.md)
for real-etcd races, duplicate workers, native mTLS, actual killed recovery process,
expired-history recovery, preserved target evidence and offline negative checks.

## Remaining M4 release gates

Full gateway/target process-kill matrix; signed external outcome report/ack API;
complete authorization-lineage export and verification; key history; incident
ownership/deadlines; larger chain retention; delayed contradictory terminal reports;
quiesce, restore quarantine and stale-writer fencing. Real target guarantees,
enterprise identities and least-privilege deployment remain M5/M6. These gates
stay open even when all bounded software tests pass.
