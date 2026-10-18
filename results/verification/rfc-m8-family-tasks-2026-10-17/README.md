# M8c5 core A2A family tasks — 17 October 2026

Baseline: d55b2c2. [RFC 0053](../../../docs/rfcs/0053-family-coordination-tasks.md)
and the [operator guide](../../../docs/A2A_FAMILY_TASKS.md) describe the new shipping
kf-family-peer and host-side Node family command/task adapter.

The complete required frozen-source run passed **454 Rust tests across
54 binaries**, **26 SQL storage/peer/restore groups**,
**32 Python tests**, both existing Node vector suites, formatting, Clippy, Ruff,
mypy and frozen schema/whitepaper checks. Required-mode ignored/skipped tests and
failures: zero. All **523 source files** stayed unchanged during and after
this run. There are now **24 shipping commands**. Source archive, hashes,
observations, tool/command/log pins and final-source.json retain the exact source
and evidence. Earlier committed results, fixtures, schema, paper and both SQL
migrations remain unchanged.

## Qualification

Three new native cases use real etcd, verified mTLS, OIDC/DPoP and independently
signed narrowed family commands:

- Owner/delegate signing and read ACLs; distinct message/RPC IDs retain the same
  task and original held allocation. Reissuing the child with another stable
  operation key refuses. Canceling completed coordination cannot release it.
  A task ID presented as a native grant digest refuses; independently fresh
  native admission/issuance/claim/dispatch still works under the attached child.
  Listener restart reconstructs original tasks from retained signed events;
  historical reads survive family stop while fresh authority refuses.
- Required version/extension activation; closed JSON, integer-only bodies, fixed
  context, URL/reference refusal, subject/scope separation, scoped pagination,
  descending update times, inclusive timestamp boundary, omitted unrequested
  artifacts, stale cursor refusal, UTF-8 JSON and honest unsupported capability
  errors. No rejected message allocates capacity.
- Actual official **@a2a-js/sdk 1.0.1**, pinned by lockfile integrity, discovers the
  card and performs SendMessage/GetTask/ListTasks/CancelTask against the shipping
  peer. A deliberately lost committed SendMessage reply is resolved under the
  original task ID and exact signed-command replay. After SIGKILL and permanent
  family stop, a fresh native peer and separate Node process query the same task.
  Shared durable DPoP replay is selected in the shipping configuration. Reusing
  the OIDC verification key as a family signer refuses local preflight.

The two early focused SDK fixture failures are retained: the SDK error exposes
reason/envelopeCode, and its typed ListTasksRequest.fromJSON supplies required
proto defaults. Correcting those fixture API uses did not relax production
parsing, authentication, validity, budget or replay guards. The subsequent focused
run passed all three cases before this full source freeze. The final full run
also covers the added float/charset checks.

## Meaning and remaining work

A completed task attests retained coordination, never a physical target effect,
child execution grant or whole-saga success. Artifacts explicitly report
executionAuthority=false and targetEffectVerified=false. Each native child keeps
its independent admission, original execution identity and outcome lineage.
Read-only family status supplies a concurrency head, never authority. The helper
never automatically changes an operation key, widens scope or re-signs ambiguous
commands. Streaming, push, arbitrary contexts, batch/notifications and external
references remain disabled and are not advertised.

This is bounded software interoperability between the shipping Rust peer and
actual official JavaScript client under generated same-host identities. It does
not prove an independently implemented authority server, enterprise identity/key
custody, complete cross-contract saga, cross-cluster atomicity or physical drain.
M8 remains incomplete pending multi-contract real-SQL inverse runner/aggregate
execution evidence, broader failure composition, physical restore/cutover,
independent/deployed acceptance and actual separately governed Kubernetes drain.
The user has no supplied cluster; portable local test tools are being prepared,
and no existing cluster was used or changed in this qualification.
