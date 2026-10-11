# RFC 0004: Execution, credentials, status and recovery

- Status: **Draft**, 10 October 2026
- Profiles: KF-MCP-0.1 and KF-JSON-0.2; draft leaf-control supplement
- Milestone: M1 → M3/M4; enterprise credential lifecycle M5
- Owners/reviewers: unassigned

## Execution contract

An authenticated Agent Adapter discovers supported profiles and action scope,
freezes a proposal, resolves trusted admission remediation, obtains a certificate
and grant, then sends the unchanged call with fresh DPoP. Parameters, workload,
subject, delegation, descriptor/incarnation and adapter contract must match.
No transport request ID is an authority or target idempotency key.

The gateway validates the grant and call, then atomically claims the persisted
allowance. That claim assigns a durable AttemptID and retains the grant/root
correlation. Only after claim may the gateway exchange credentials. Persist
dispatch intent and atomically authorize dispatch under current policy/ownership/
revocation state. The adapter applies the declared fence/version guard and retains
AttemptID, RootID and GrantDigest at its commit boundary. Guard guarantees cover
only the declared writer set and target transaction.

Credential Exchange is a separate authorized interface. The broker authenticates
the gateway, validates its signed grant and durable claimed attempt, checks target
audience/scope/lifetime and issues only the required target credential. The subject
credential is not forwarded to the target. Expired, overbroad or unverified broker
outputs refuse dispatch. Existing tests exercise pinned exchange mechanics;
provider lifecycle and cross-replica replay state remain M5.

## Status and replay

Status accepts stable operation, grant or attempt identity and authenticates
current subject/workload authorization separately from execution validity.
An expired grant may identify retained history; it cannot authorize disclosure.
Status never claims, exchanges credentials, dispatches or refunds allowance.
Return the actual persisted AttemptID. `NonceConsumed` must resolve the original
attempt instead of returning a new randomly generated ID. An ambiguous claim reply
uses the same resolution path, with uncertainty explicit when the ledger is down.

States distinguish unissued, unclaimed, claimed, dispatch-authorized, committed,
proven-not-dispatched, guard violation and consumed-unknown. Public mappings must
not claim `no_effect` merely from a timeout, error, cancellation or missing record.
The draft schema enumerates initial status carriage; fine-grained internal states
and adapters require explicit compatible mapping before publication.

## Outcome and recovery contract

Persist signed authorization links, adapter/version, authenticated identity,
dispatch transition and target references before relying on them for recovery.
Outcome reports have stable report identity and attempt/grant/root correlation;
duplicate matching reports are idempotent and conflicting evidence is retained.
Gateway-signed receipts attest gateway observations, not target-signed completion.
Generic MCP success/accepted/job ID does not prove the declared commit point.

A supervised worker discovers stranded claimed/unknown attempts and obtains
multi-worker ownership atomically. It queries independently authenticated target
status and checks all correlation fields. Definitive target evidence may refine
consumed-unknown to committed. Insufficient evidence remains unknown and consumed.
No implicit retry, refund, compensation or root replacement follows process death,
elapsed time, missing status or cancellation. A proven pre-send state can be
reported without restoring authority. Restoration requires a separately proven
no-effect/late-effect barrier and a new protocol transition.

Retention covers signed records, verification key history, issuance deduplication,
claims, dispatch facts and authoritative observations through the replay/audit
horizon. Polling has bounded rate and a deployment-owned escalation deadline.
An offline verifier reports missing links explicitly. Quiesce/restore preserves
consumption and prevents stale writers or backups from reopening authority.

## Binding and acceptance

MCP uses the negotiated existing extension and the pinned
[2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28).
Draft status/control operations are not silently added to `tools/call` or advertised
as supported. Concrete URLs, response codes and signed outcome acknowledgement
schemas remain review decisions. Optional grant-reference carriage must retain
immutable-envelope digest binding and authorized retrieval.

M3 acceptance: live admission and client workflow; lost-reply/replay resolves the
same attempt; status after expiry or repeated calls adds zero claims/exchanges/
effects. M4 acceptance: crash before/after claim, dispatch, commit and receipt;
duplicate workers, missing/contradictory observations and stale restoration preserve
consumption. Independent reconstruction verifies complete retained lineage.

References: [RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693),
[RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449).

## Open decisions

- Status authorization/retention and whether operation lookups are enumerable.
- Signed outcome report/ack schema, observation ordering and incident ownership.
- Target-specific proof required for no-effect and restoration, if supported.
