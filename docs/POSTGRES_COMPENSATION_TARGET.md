# Conditional PostgreSQL compensation target — M8d3a

[RFC 0048](rfcs/0048-postgres-compensation-target.md) supplies the actual registered
one-row SQL inverse, target barrier and separate applicability evaluator for
[RFC 0047 native compensation authority](NATIVE_COMPENSATION_AUTHORITY.md).
It restores only the original reservation string. It advances the current version
and common resource fence; it does not restore an old version or undo downstream
work, evictions, external fulfillment or other writers.

## Provision the protected snapshot and roles

Apply `migrations/postgres/0002-compensation.sql` separately as the protected schema
owner after migration 0001. The original migration and forward action remain
unchanged. Before forward execution, call the owner-only
`kf_compensation.capture(jsonb)` with exactly `tenant`, `conflict_domain`,
`resource`, `baseline_version`, `contract_digest` and `restore_state_digest`.
The actual stored reservation and resource identity must hash to that digest using
`digest("postgres-restore-state", {"reservation": original, "resource": resource})`.
These values must match the independently approved inverse contract and original
signed forward baseline. A request never supplies the value to restore.

Capture locks the current row, refuses inactive/recreated/moved resources or an
already retained attempt for the baseline version, and retains one immutable
snapshot per tenant/contract. Exact recapture returns the original registration;
changed material refuses. Native contract enrollment separately checks that the
planned forward operation has not been issued. The owner must follow this ordering;
there is no cross-database/etcd transaction.

Enroll three distinct standalone database logins. Each needs schema `USAGE` on
`kf_reservation` and `kf_compensation` for catalog observations, and exactly one
fixed function:

| Role | Function |
| --- | --- |
| Inverse executor | `kf_compensation.apply(jsonb)` |
| Inverse reader | `kf_compensation.lookup(text,text)` |
| Target barrier | `kf_compensation.barrier(text,text,text,text,text)` |

Grant no table/column rights, function grant options, schema creation, database
creation/ownership, administrative privileges or role memberships. No runtime
role receives `capture`, forward `apply`, or another role's function. PUBLIC has
no access to the new schema, tables or functions. Every native connection checks
these effective privileges. Protected schema/function owners and future ACL
changes remain trusted; this observation does not lock later administrative changes.

## Configure and run the target

The protected target JSON has:

- `profile`: `KF-POSTGRES-COMPENSATION-HTTP-0.1-draft`;
- `listen`, fixed distinct same-origin `dispatch_url`, `query_url`, `barrier_url`,
  and the TLS `certificate`, `private_key`, `workload_ca` files;
- `database.connection`: the existing Unix database shape with inverse
  `executor_user` and `query_user`; `database.barrier_user`: the third login;
- `trust.inverse_execution`: the complete RFC 0047 protected execution object;
  `trust.topology`: the approved complete paired topology;
  `trust.registration`: the fixed target registration shape from RFC 0024,
  selecting the contract's exact inverse scope and independent gateway/query
  workloads, target audience and scope; `trust.forward_gateway_workload`: the
  approved original forward target caller;
- `gateway_audience`, `grant_keys`, `token_issuer`, `target_keys`: independently
  approved native inverse issuer and broker credential pins;
- `query_token_file`, `barrier_token_file`: separate protected bearer-token files;
- `barrier_workload`, `barrier_key_id`, `barrier_signing_key_file` and
  `barrier_lifetime_ms` (1–60000): the distinct target-barrier role, RFC 0045 key
  and maximum statement lifetime. Keys use standard base64 in configuration/files.

```sh
kf-compensation-target --config /etc/kedgeflow/inverse-target.json --check
kf-compensation-target --config /etc/kedgeflow/inverse-target.json \
  --check-database --postgres-peer-uid 1001
kf-compensation-target --config /etc/kedgeflow/inverse-target.json \
  --postgres-peer-uid 1001
```

Replace the illustrative UID with the approved PostgreSQL server kernel UID.
`--check` validates local material without contacting SQL. `--check-database`
observes all three role catalogs without executing an effect or opening a listener.
The peer option requires an approved absolute socket path without symlink
components and checks the Unix server identity before authentication bytes.
This new loader does not claim the existing forward target's optional descriptor /
file-custody profile; approve file ownership and credential custody separately.

The barrier endpoint accepts a closed `profile`, `operation:"barrier"`, `forward`
request under its own mTLS workload and bearer token. `forward` is the complete
original RFC 0044 lineage bundle. It independently verifies all historical signed
inputs, admission, grant, attempt, receipt, budget and observer pins, then checks
the exact committed SQL attempt and current locked resource against the captured
snapshot. Absent, in-flight, guard-rejected, recreated or advanced state cannot
produce an affirmative statement. Exact original forward replay returns the
retained result and cannot commit again under migration 0001's contract.

The response is an RFC 0045 signed barrier bounded by the original receipt's
compensation deadline. It is an observation, not a lock extending to dispatch.
Any later writer is checked again by the inverse SQL transaction.

## Evaluate, admit and dispatch

The separate evaluator configuration contains exactly `contract`, `forward`
(the complete historical trust shape), `key_id` and `signing_key_file`.
Its key must be the independently approved applicability role, not the target's
barrier key. It verifies the original proof and signed barrier before returning
the complete nonauthorizing qualification proof:

```sh
kf-compensation-evaluate --config /etc/kedgeflow/inverse-evaluator.json \
  --forward /protected/forward.json --barrier /protected/barrier.json
```

Retain that proof through `kf-compensation --qualify`, enter permanent compensation
mode and request fresh inverse admission. Configure the inverse gateway's
`compensation_adapter` with `profile`, `registration`, `forward_gateway_workload`,
`token_issuer` and `target_keys`. It requires the matching `inverse_execution`,
paired inverse lane, managed controls and one exact inverse tool. It cannot use
another reservation or silently fall back to the generic HTTP adapter.

The native adapter reads the original signed compound binding and exact
qualification through a read CAS after native dispatch authorization. Agent
metadata cannot substitute either. The target independently verifies that binding,
complete original proof, frozen inverse grant and original broker credential,
including the pinned inverse outcome role/source. SQL then atomically checks
snapshot, exact original forward result, current incarnation/version/value/fence
and deadline under row lock; it retains one inverse attempt, restores the captured
value and advances version/fence. Another contract/root/grant/attempt cannot replace
the retained identity. A function result is not returned as terminal before COMMIT
acknowledgement. Expiry is checked after lock contention. Caller rollback undoes
both effect and retained result.

The Node client requires the explicit `io.kedgeflow/compensation-leaf` discovery
profile, exact five-field schema and protected `config.compensation` containing
`profile`, `contractDigest` and the exact original `parameters`. It checks the
selected tool's advertised contract digest and refuses changed original parameters.
These client checks confer no authority; independent native admission and target
checks remain mandatory.

## Unknown outcomes and qualification boundary

A lost reply, process failure or timeout stays tied to the original attempt.
The separate authenticated query returns only that retained inverse result.
Native recovery can refine its signed committed result after expiry or stop.
A target guard rejection remains distinct from committed; it cannot authorize a
new inverse operation or refund the held allowance. No automatic mutation retry,
snapshot replacement, force restore or version rewind exists.

[The required-mode verification](../results/verification/rfc-m8-sql-compensation-2026-10-15/README.md)
retains 428 Rust tests across 51 binaries, 26 SQL groups, 32 Python tests and both
Node suites. Six new native groups compose real PostgreSQL effects/barriers with paired native
controls, fresh inverse admission/spending, cryptographic broker identities,
original permit minting, mTLS role separation, reply loss/service restart and
shipping evaluator/target commands. SQL tests also cover rollback, concurrent
replay, expiry after lock contention and bypass refusals. Client vectors cover
explicit inverse schema/contract/parameter binding. Full official-SDK inverse
orchestration, multi-contract inverse families, independently verified complete
multi-node saga history and deployed writer/custody acceptance remain open.
M8e's actual Kubernetes drain and Level C physical limits are separate.
