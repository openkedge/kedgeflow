# RFC 0009: Proposal-addressed historical operation status

- Status: Draft
- Profile/version: `KF-OPERATION-STATUS-0.1-draft`
- Milestone: bounded M3b software increment
- Baseline: M3a commit `cc6d7b7`, frozen KF-JSON-0.2 / KF-MCP-0.1
- Owners/reviewers: unassigned; security, identity, resource and runtime owners

## Problem and scope

An issuer can commit a grant while its HTTP reply is lost. The agent retains the
signed proposal but cannot query RFC 0008's grant-addressed endpoint. Retrying
issuance after the original certificate or delegation expires cannot resolve
that ambiguity. This supplement queries historical state using the exact signed
proposal, including after expiry and control-domain revocation.

This bounded profile supports one registered tenant, proposal workload and
current CTD pin per service. It returns state and correlation identifiers. It
does not return a grant or receipt body, renew authority, recover attempts, query
the target or initiate execution. Key/PoP/descriptor migration and arbitrary
grant/attempt-ID searches require a separate reviewed history policy.

## Authority and trust

The operator configures an optional exact HTTPS status URL and a distinct status
scope. Its origin must match the admission/issuer service; paths must differ.
The status authenticator pins the same authorization issuer and delegation
audience, validates the current token and fresh URL-bound Ed25519 DPoP proof,
and obtains the workload from verified native mTLS. The subject must belong to
the service allowlist and the workload must match its installed registration.
The scope differs from admission, issuance and consequential-action permissions.

The request proposal is verified under the pinned proposal role keys and frozen
closed schema. Its tenant, subject, workload, PoP key and CTD digest must match
the service and caller. The historical execution delegation digest, action scope
and time validity are not used to authorize disclosure. A renewed status-only
token can query history; the original token cannot authorize new execution after
expiry. Revoking current identity/disclosure permission can prevent queries.

No request can select an authority namespace, ledger URL, tenant, target,
operation-key digest, grant or attempt ID. Only the signed proposal identifies
the operation within the configured namespace.

## Contract

See [the separate closed schema](../../spec/drafts/operation-status-v0.1.schema.json).
POST application/json to the configured URL:

```json
{"profile":"KF-OPERATION-STATUS-0.1-draft","operation":"status","request_id":"query-1","proposal":"<exact signed proposal JSON>"}
```

`request_id` is a correlation string, not the operation identity. The server
derives the existing issuance-key digest from trusted tenant, authenticated
subject/workload and signed qid. Requests use the existing bounded strict JSON
parser, 1 MiB body ceiling, native Host/Origin checks and fresh DPoP proof.
Queries have a five-second service deadline and share the 64-operation bound.
Replies use Cache-Control: no-store and the same profile/request ID.

The authority reads the global issuance record and retained admission/chain in
a linearizable etcd transaction. If issuance exists, it checks retained record
keys/certificate correlation, authenticates the original proposal and issuer
signature, requires the requested proposal digest to equal the retained proposal,
and checks grant/proposal/certificate/caller bindings. Historical grant validation
checks executable shape and audience while permitting expired validity intervals.
It then uses RFC 0008's correlated root/grant/nonce/attempt/outbox lookup.

Result fields are `profile`, `operation: status_result`, `request_id`, `state`,
`attempt_id` and `grant_digest`. States are `unissued`, `unclaimed`, `claimed`,
`dispatch_authorized`, `committed`, `not_dispatched`, `state_guard_violation` and
`unknown`. `unissued` has null attempt and grant digest. `unclaimed` has null
attempt and the original signed-grant digest. Other states carry the original
attempt ID and grant digest. No candidate ID is fabricated.

## Failure and retry

`unissued` means no issuance record exists in the configured live namespace at
that read's linearization point. A disconnected issuer task can commit later.
It is neither cancellation nor a no-effect certificate and does not authorize a
retry. The authority must retain issuance records without deletion/reuse for the
supported history horizon. A restored/stale namespace invalidates this absence
claim until its authority restoration is independently qualified.

Unavailable authority, missing/corrupt retained records, inconsistent correlation
and timed-out reads fail closed. They never become `unissued`, `unclaimed` or
`not_dispatched`. Closed failures are invalid_record, unauthenticated, forbidden,
unsupported_profile or authority_unavailable. Malformed or untrusted requests
can fail before a request ID is authenticated/parsed, using `unavailable`.

The Node adapter durably saves the signed proposal before provider/admission
requests. A saved operation is query-only on subsequent execute/status calls,
even without a grant or after an `unissued` snapshot. After an ambiguous control
or provider failure it clears the execution-token pin and queries using a fresh
current token. It performs no recollection, second issuance or dispatch. The
operation remains unresolved if query authorization/authority is unavailable.
The caller deliberately creates a fresh qid only for separately intended work.

A failed grant-store write after issuance also resolves query-only; persistence
is required before dispatch. Existing crash-owner locks remain retained. Status
reads do not take an execution lock or reclaim it. Power loss, stale backups and
operator lock recovery remain deployment qualification gates.

## Compatibility and rollout

RFC 0008's negotiated MCP retained-grant endpoint is unchanged. The earlier
KF-LEAF-CONTROL-0.1-draft generic operation/grant/attempt lookup remains a proposal;
this new profile explicitly implements a narrower signed-proposal lookup with
its own identifier and schema. Frozen profiles, signatures and fixtures remain
unchanged. Existing service configurations omit both status_url and status_scope
and retain two routes. Enable both together; the client additionally pins statusUrl
and explicitly permits it in its mTLS transport URL allowlist. No discovery or
remediation hint can select this endpoint.

## Implementation and acceptance

Implemented in operation_status.rs, control.rs, admission.rs, ledger.rs and the
Node Agent Adapter. The service shares existing TLS, request and operation
bounds. Config validation requires paired URL/scope and distinct permissions.

The [fresh verification record](../../results/verification/rfc-m3-operation-2026-10-11/README.md)
records native authorization/substitution/corruption tests and official-client
fault cases. Lost committed issuer replies and failed grant persistence resolve
`unclaimed` without any exchange, dispatch or effect. A lost provider reply
resolves `unissued` without recollection. Separate Node processes resolve the
same state/digest after certificate, grant and original delegation expiry and
signed domain revocation with status-only
tokens. Existing committed/lost-execution cases still resolve original attempts.

## Open decisions

Owner acceptance, enterprise identity/role lifecycle, shared DPoP replay state,
key/descriptor history, retention/restore, power-loss persistence, real provider
integration and complete target writer coverage remain open. Full M3 deployment
qualification is not established by these bounded software tests. M4 next adds
signed outcome evidence and a recovery worker that distinguishes pre-dispatch
from possible-send states without replaying side effects.
