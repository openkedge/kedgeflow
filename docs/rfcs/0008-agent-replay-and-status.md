# RFC 0008: Leaf Agent Adapter and query-only execution status

- Status: **Draft**, 11 October 2026
- Profiles: unchanged KF-JSON-0.2 / KF-MCP-0.1; new `KF-EXECUTION-STATUS-0.1-draft`
- Milestone: bounded M3a; operation lookup and wider fault qualification remain M3b
- Owners/reviewers: unassigned

## Scope and compatibility

This supplement implements a real Node Agent Adapter with the pinned official
MCP client 2.3.0, native verified mTLS, fresh DPoP, live evidence collection,
admission and issuance, and durable original-attempt resolution. The first action
remains the single-resource mock leaf profile. Evidence integration is a locally
configured callback contract; the HTTPS software provider in acceptance tests is
a test fixture, not a released Evidence service.

Frozen paper/record bytes and the existing leaf-control draft schema are unchanged.
The new [status schema](../../spec/drafts/execution-status-v0.1.schema.json) is a
separate negotiated MCP extension, not an executable tool or an implemented status
operation on the admission/issuer listener. Those draft operation/grant/attempt
lookup routes remain future work. Existing clients can continue using governed
calls without negotiating status. Status is disabled for a tool with empty
`status_scope` and is advertised only to callers holding its configured scope.

## Identity, discovery and exact retries

Control and gateway must use the same operator-approved delegation audience,
authorization issuer and PoP key. Gateway `delegation_audience` config supplies
that audience; omission/empty retains its existing external-URL audience.
Execution grants still bind the exact gateway URL independently. DPoP proofs have
a fresh JTI per request and the actual endpoint as `htu`. The same access token
and scope ordering preserve the original delegation digest across proposal,
admission, issuance and execution. Refreshing it does not refresh execution
authority for an existing operation.

The adapter pins MCP revision 2026-07-28 and negotiates governed-call and status
profiles. It validates the advertised consequential tool and verifies the pinned
registry-signed CTD. Remediation must match the configured admission URL, action,
parameter digest, carriage, profile and exclusive expiry. Remediation hints never
select evidence URLs or replace independently approved policy requirements.

The application supplies an operation identity and exact call. A configured
evidence source obtains baseline state and prepares an unsigned proposal; the
adapter checks its identity/action/parameter/delegation bindings, freezes its
bytes, and signs with its enrolled proposal key. Evidence collection receives
that exact signed proposal and digest. The adapter verifies provider/manifest
roles, proposal binding and witness expiry; the Admission Controller independently
performs the full schema, discharge and Cedar checks from RFCs 0003/0005.

Admission and issuance use RFC 0006 with fresh proofs and request IDs. Returned
certificates/grants require the configured role signatures and exact retained
proposal/manifest/delegation/identity/call bindings. The native gateway performs
full executable-grant validation and current installed-control checks. Oversized
inline grants refuse; this adapter has no reference publication/retrieval path.

## Client persistence and uncertainty

The reference `FileOperationStore` uses a protected directory, hashed operation
filenames, private temporary files, fsync and atomic rename. It retains the exact
proposal/evidence packet before admission and the exact certificate/grant before
`tools/call`. One exclusive per-operation lock prevents overlapping store owners.
The adapter also permits only one active execution per instance. A crashed
owner's lock remains for explicit operational recovery; time does not expire it.
Query-only status does not require that lock. Deployments must protect the store
and qualify filesystem durability; the test establishes ordinary process restart,
not power-loss durability or safe automated lock recovery.

The operation fingerprint binds qid, exact tool/parameters, descriptor, subject,
workload and PoP key. Changing the action under that identity refuses. Retrying a
retained packet preserves its original evidence and delegation; it does not
invent fresh inputs under an already admitted qid. A stored grant causes a repeat
`execute` call to query status, including when still unclaimed. Automatic execution
resume for that state is deliberately absent from this slice.

After a possible execution send, the adapter queries the retained grant. It does
not obtain a new grant, call the tool again, compensate or refund consumption.
A missing local grant or unavailable lookup returns uncertainty; it never asserts
`unissued` or `no_effect`. An unchanged admission/issue retry can use the original
packet while valid, but resolving lost issuer replies after its validity ends
requires M3b's authorized operation lookup. No receipt body is reconstructed from
a committed state alone; signed outcome/receipt retention belongs to M4.

## Status wire contract and permissions

Discovery advertises `io.kedgeflow/execution-status` with profile
`KF-EXECUTION-STATUS-0.1-draft` and method `kedgeflow/status`. Each request must
negotiate that profile in the normal MCP capability metadata. JSON-RPC uses the
same protected POST URL/transport and normal version metadata. Params contain
`name` (registered tool), `arguments` and `_meta`. Arguments contain exactly:

```json
{"profile":"KF-EXECUTION-STATUS-0.1-draft","grant":"<exact signed envelope>","attempt_id":"<optional expected original ID>"}
```

The optional attempt ID only constrains correlation. It cannot select another
attempt or create one. Inline/reference grant headers on status requests refuse;
lookup uses the bounded body and performs no grant-reference fetch.

Status requires a current access token/DPoP and verified enrolled workload,
plus the tool's distinct `status_scope`. Grant signatures, closed executable
record shape, audience and temporal interval syntax remain checked, while the
historical grant's current execution validity is not required. Current subject,
workload and PoP key must match; action/resource/incarnation/domain/predicate and
adapter must match the registered tool. A renewed status-only token may disclose
history without matching the expired execution delegation. Key rotation/history
and future tool migrations require a separately accepted retention policy.

A success is `resultType: "complete"`, `profile`, `state`, nullable `attempt_id`
and `grant_digest`. `unclaimed` requires null attempt ID; all other states require
the actual persisted ID. States are `claimed`, `dispatch_authorized`, `committed`,
`not_dispatched`, `state_guard_violation` and consumed `unknown`. A not-dispatched
state grants no retry/refund authority. The official SDK validates and removes
wire `resultType` before calling the adapter's closed extension result validator.

Errors use existing MCP failures: -32602 `INVALID_STATUS_PARAMS` or
`UNEXPECTED_GRANT_HEADER`; -32002 `KF_STATUS_NOT_NEGOTIATED`; -32003
`INSUFFICIENT_STATUS_SCOPE`/`STATUS_FORBIDDEN`; -32009 `STATUS_UNAVAILABLE`.
TLS/current authentication/transport refusals retain the gateway's existing
behavior. Unknown, damaged, mismatched or inaccessible records do not become a
claim of no effect. Application responses are `no-store`.

## Durable resolution and replay

The ledger reads root, exact persisted grant digest and nonce in one linearizable
snapshot. An unclaimed result requires the exact unclaimed root and absent nonce.
A consumed nonce supplies the original ID. A second transaction compares that
root/grant/nonce while reading the correlated attempt and outbox. Missing or
inconsistent records refuse. Pending attempt plus `dispatch_authorized` outbox
maps to that distinct state; terminal state must agree in both retained records.
Queries require quorum and have no cached authority fallback.

Status requires no live policy/installation acknowledgement or revocation absence:
revocation and expiry stop execution, while current disclosure authorization
controls history. It performs no ledger writes, claim, credential exchange,
adapter dispatch, target query, reconciliation or refund.

On `NonceConsumed`, the gateway resolves this durable status and returns its
original attempt ID/state/grant digest in error data. Ambiguous failed/timed-out
claim replies use the same bounded lookup. Unavailable resolution returns null
attempt ID with explicit `unavailable`; it never returns the random losing
candidate. A concurrent query can observe unclaimed before an in-flight claim
commits; that snapshot does not prove no dispatch or authorize a new allowance.
Owned gateway tasks keep a separate 64-operation limit after HTTP disconnect.

## Acceptance and remaining gates

Real-etcd tests cover original ID replay, lost committed claim reply, expired
status under renewed permissions, missing scope, changed subject/PoP, unknown
fields, false attempt IDs and corrupted attempt/outbox correlation. The official
SDK follows discovery → remediation → fresh software evidence → native
admission/issuance → exact guarded mock effect. Lost execution replies resolve
without another effect; a new Node process resolves the same attempt after
grant expiry and domain revocation with a renewed status-only token. Counters
prove one evidence collection, exchange, dispatch and mock effect per operation.

M3b must provide authorized operation/grant/attempt lookup without a locally
retained executable grant, resolve ambiguous issuer replies beyond expiry, and
qualify wider client/provider outages and interrupted persistence. Minimum
Node/Rust execution, production identity/key custody and shared DPoP replay,
power-loss/restore and real target guarantees remain separate deployment gates.
This bounded client increment is delivered; the full M3 release gate remains open.

## M3b checkpoint — 11 October 2026

[RFC 0009](0009-operation-status.md) now implements a separate signed-proposal
query for missing local grants, ambiguous issuer replies and failed grant
persistence, including expiry/revocation and process restart. The client now
resolves every retained operation query-only; it does not retry issuance on
an unissued snapshot. Wider provider/deployment and persistence gates remain open.
