# RFC 0048: Conditional PostgreSQL compensation target

- Status: Draft
- Profiles: KF-POSTGRES-COMPENSATION-0.1-draft; KF-POSTGRES-COMPENSATION-HTTP-0.1-draft
- Milestone: M8d3a; complete saga qualification remains M8d3
- Prerequisites: RFCs 0023–0025 and 0044–0047
- Owners/reviewers: unassigned

## Registered effect

The inverse restores only the original reservation string on one resource row.
It never reverses downstream activity, physical effects or other writers. It keeps
the original resource incarnation, increments its version and uses the common
forward/inverse resource fence. It requires a protected immutable snapshot captured
before the forward operation, the exact original committed forward SQL attempt,
and a current version exactly one greater than the captured baseline. No request
supplies a restore value. An intervening writer refuses without another attempt.

Install migration 0002 separately as the protected owner; migration 0001 remains
unchanged. Snapshot capture is an owner-only provisioning function. Executor and
query roles receive only their fixed functions, with no table/column writes,
role membership, ownership, schema creation or PUBLIC access. The snapshot binds
the approved contract digest, resource/incarnation/domain, baseline version and
canonical original restore digest. Capture checks that no original target attempt
for that version has already been retained. Native contract enrollment separately
requires an unissued planned operation.

## Barrier and applicability

The target barrier function reads the exact retained committed forward attempt
and locks the resource. A committed retained record is terminal under RFC 0023:
exact replay returns the same result, and conflicting original attempt/root/grant
bindings cannot execute. The current incarnation/version and registered snapshot
must still match. Absent, unknown, in-flight, guard-rejected, stale or out-of-scope
forward results cannot yield an affirmative barrier. Native target code checks the
complete independently pinned forward proof and signs the exact RFC 0045 identity,
contract, target and bounded validity window only after this database observation.
A separately pinned evaluator verifies that statement and the fixed restore
semantics before signing applicability; it cannot reuse the barrier role.

The observation is not a lock held until dispatch. An external writer can advance
the version after it; the inverse transaction must test it again under row lock.
Authority expiry stops new sends. A target commit already in flight is resolved
only by querying the original retained attempt.

## Dispatch and retention

The target independently verifies the exact inverse grant, original qualification,
mandatory RFC 0047 compound binding and broker credential. Pins come from protected
configuration. The broker credential must bind the original inverse grant/root /
attempt/gateway/audience/scope and fit the original accepted deadline. Only the
native authority path can obtain it after winning the claim/permit transaction.
The target must reject a pre-CAS binding presented without that credential.

A separate closed dispatch record carries the original forward grant/attempt,
contract and restore digest along with bound inverse root/grant/attempt, current
expected version, common fence and deadline. SQL atomically reserves the inverse
identity, checks all original records and current guards, restores the captured
value, advances version/fence and retains its original result. Exact concurrent
replay returns that original result. A contract, root or grant cannot acquire a
second inverse attempt. Caller rollback undoes both effect and result. Neither
HTTP success nor a returned function row establishes a commit until COMMIT is
acknowledged; loss leaves the original attempt unknown until fixed query resolves.
Query uses a separate role/workload and never invokes mutation functions.

## Qualification

Required real PostgreSQL tests cover snapshot custody, positive forward/restore,
concurrent original replay, response loss/query, rollback, stale version/fence,
expiry during lock wait, recreated resource, missing/noncommitted original,
changed bindings and denied direct table/function privileges. Native HTTP/SDK and
complete independent saga evidence must compose this target with actual paired
controls, compensation spending and recovery before claiming M8d3 complete.
Kubernetes drain and its Level C physical limits remain a separate M8e profile.

## Client and implementation mapping

`compensation_target`, `compensation_target_http`, `compensation_target_config`,
`compensation_adapter` and `postgres_compensation` implement the separately opted-in
path. Shipping commands are `kf-compensation-target` and
`kf-compensation-evaluate`. The forward target/profile and frozen records retain
their original semantics. The operator must enroll the exact inverse adapter;
request metadata cannot select target URLs, keys, SQL or snapshots.

The inverse MCP client explicitly negotiates `io.kedgeflow/compensation-leaf`
with profile `KF-COMPENSATION-LEAF-0.1-draft`. Tool discovery carries that profile
and the approved contract digest in `_meta`. Protected client configuration pins
the digest and exact original five-field parameters. Omitted/mismatched profile,
schema, contract or parameter substitutions refuse before fresh authority work.
Client discovery is not an admission decision or target authorization.

This bounded implementation selects one exact inverse contract per paired service.
It does not establish a multi-contract family, complete multi-node inverse runner,
independent whole-saga verification, enterprise acceptance. M8d3b adds the bounded official-SDK inverse workflow
and query-only restart described in [the workflow guide](../COMPENSATION_AGENT_WORKFLOW.md). Those remain explicit M8 gates.
