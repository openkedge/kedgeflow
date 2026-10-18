# RFC 0053: A2A family coordination tasks

- Status: implementation draft; [local qualification record](../../results/verification/rfc-m8-family-tasks-2026-10-17/README.md)
- Profile: `KF-A2A-FAMILY-TASKS-0.1-draft`
- Required extension: `https://kedgeflow.dev/extensions/family-tasks/v0.1`
- Depends on: RFC 0052 shared family authority and the native child profiles

## Purpose and authority

Expose actual A2A v1 JSON-RPC coordination tasks for signed family delegation,
child attachment and permanent stop. A completed task means its coordination
command is retained. It does not attest a target effect or confer execution
permission. A cataloged native child still requires independent evidence,
admission, issuance, original-attempt claim and dispatch controls. Family budget
and ancestor checks remain in the native final authority transaction.

This profile implements core task exchange in the shipping Rust peer and uses
the official A2A JavaScript SDK as a separate client. It does not establish an
independently implemented authority server, cross-cluster capacity, enterprise
custody, full workflow execution, streaming or push delivery.

## Transport and discovery

The protected configuration fixes one HTTPS JSON-RPC endpoint and one immutable
family registration/namespace. `GET /.well-known/agent-card.json` requires verified
workload mTLS. The card advertises the exact endpoint, JSONRPC binding, protocol
version `1.0`, required extension, JSON input/output, disabled streaming/push and
extended card, and separate mTLS/DPoP subject requirements. The card contains no
target credentials, private signing keys or executable grants.

RPC requests require verified SPIFFE workload mTLS, an OIDC subject token bound
to a fresh endpoint/method/access-token DPoP proof, `kf.family.coordinate`, and a
principal pinned in the family registration. A signer principal must match both
the authenticated subject and workload. The extension is activated with
`A2A-Extensions` and `A2A-Version: 1.0`; each send also names the extension in its
message. Duplicate/unsupported headers, endpoint aliases, origins, compression,
external references, batch requests and notifications refuse.

Requests are bounded at 32 KiB; there are 32 concurrent RPC slots and a 15-second
RPC deadline. The shared listener separately bounds connections, TLS handshakes,
headers and connection duration. An interrupted response never authorizes a
replacement operation. Optional shared DPoP replay uses the selected protected
native ledger and fails closed; otherwise replay protection is process-local.
Those deployments must declare their single-process replay boundary.

## Identity and persistence

The peer generates one context ID from the protected family registration digest
and namespace. A caller may omit it or select that exact context. A different
context refuses. The peer generates task IDs from that context and the stable
signed family operation key. Message IDs and JSON-RPC IDs are correlation only.
Incoming task IDs can select an already retained identical original command;
they cannot create authority or override operation identity.

The retained, verified RFC 0052 signed event is the task record. No separate
in-memory task store can allocate capacity or lose its identity on restart.
Exact original signed-command replay returns the same immutable task even after
family stop or command expiration. Changed transport IDs cannot allocate again.
Changed operation keys for an attached child refuse under the native family CAS.
The original signed command is checked before returning an existing task.

## Core methods

`SendMessage` accepts a user message with exactly one JSON DataPart. The first
alternative is an RFC 0052 signed command. It authenticates the command signer,
checks the full narrowed live authority and expected state head, and retains the
command using the family CAS. Its result is the standard SendMessageResponse
`{task: ...}` wrapper. The task is completed immediately and contains one
coordination receipt artifact: original command/operation, applied time and
family digest, with `executionAuthority: false` and `targetEffectVerified: false`.
It carries no target credential or native child grant.

The second DataPart alternative is the closed query
`{profile: "KF-A2A-FAMILY-TASKS-0.1-draft", operation: "status"}`. It returns a
standard agent Message with the selected family digest/head, root active flag
and `executionAuthority: false`. This query supplies the expected head for a
subsequently signed command. It does not disclose budgets, child execution
history or other delegates' commands, mutate the family, or create a task.
The head is a concurrency token, not authorization.

`GetTask` returns an original retained task. `ListTasks` reads the bounded event
history, with context/status/time filters, optional artifacts and stable-head
pagination. Only the original command signer, protected family owner or owner of
a newly delegated branch may read that task. Unauthorized reads behave as task
not found; listing filters unauthorized records. Historical reads continue after
stop/expiry. Task history may be reduced to zero, as permitted by A2A; the signed
coordination artifact is the original immutable result.

`CancelTask` on a visible completed coordination task returns TaskNotCancelable
(`-32002`). It cannot undo delegation, release capacity, stop a branch implicitly
or reinterpret task cancellation as compensation. Permanent stop is a separately
signed RFC 0052 command. Streaming/subscription, push notification methods and
extended card return their standard unsupported/not-configured errors. The peer
does not advertise these capabilities.

## Client recovery

The Node FamilyTaskAdapter takes an approved registration and an injected actual
A2A client. Its signing helper uses the RFC 0052 canonical domain separation and
explicit caller-selected stable operation key, expected head, narrowed action,
signer and validity window. Key material stays in the host adapter.

On a lost mutation reply, retain the signed command and query its original
server-derived task ID. Exact command retry is permitted as read-only replay;
this helper never chooses a new operation key, widens scope, re-signs a command
or retries a target effect automatically. An absent/unknown reply does not prove
no coordination effect. The transport fixes card/RPC URLs, supplies mTLS and a
fresh DPoP proof, bounds response bytes and refuses redirects/proxies/other URLs.

## Qualification and limits

Require real etcd, native mTLS/DPoP, narrowed owner/delegate identities, native
child grant/claim/dispatch after coordination, last-slot/reissue refusal, exact
reply-loss replay, listener/process recreation, historical queries after stop,
ACL/pagination and malformed/version/activation/URL/batch negatives. Run actual
official SDK card discovery, SendMessage/GetTask/ListTasks/CancelTask. Preserve
frozen final-source evidence before claiming the implementation qualified.

Task artifacts prove only the selected retained coordination operation. Family
audit separately proves complete signed delegation/allocation history; native
child lineage separately proves that child's authority and original effects.
Neither replaces complete multi-contract saga evidence or physical drain proof.

## References

- [A2A v1.0.1 specification](https://a2a-protocol.org/v1.0.1/specification/)
- [Official A2A JavaScript SDK](https://github.com/a2aproject/a2a-js), pinned
  `@a2a-js/sdk` 1.0.1 in the interoperability test package
- [RFC 0052](0052-family-authority.md)
