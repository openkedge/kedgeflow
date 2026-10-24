# Named Kubernetes drain Agent Adapter

[RFC 0055](rfcs/0055-governed-kubernetes-drain.md) selects
`kubernetes.node.drain` version `1.0` under `KF-KUBE-DRAIN-0.1-draft`.
The Node Agent Adapter requires this explicit binding. Generic mock, SQL and
inverse configurations cannot inherit Level C semantics or SQL fencing for it.
The [controller guide](KUBERNETES_DRAIN.md) describes the native authority and
physical evidence boundary.

## Protected client binding and discovery

In addition to the ordinary [Agent Adapter configuration](AGENT_ADAPTER.md),
provide a protected `config.drain` object with exactly these fields:

```js
{
  profile: 'KF-KUBE-DRAIN-0.1-draft',
  contractDigest: '<64 lowercase hexadecimal characters>',
  node: '<protected node name>',
  generation: 1,
  resource: { id: '<same node name>', incarnation: '<protected resource digest>' }
}
```

Use the actual enrolled generation and resource identity. The helper
`drainRegistration(contract)` in `sdk/node/kube-drain.mjs` projects these pins
from an already trusted full controller contract. It does not authenticate,
enroll or approve that contract. The resource incarnation binds the protected
realm UID and node UID; it is not a caller-selected node identifier.

The adapter verifies the registry-signed CTD, exact contract digest annotation,
parameter schema/digest, resource, generation, coverage inventory and exact
`Level_C` / `None` / empty guard scope. Parameters contain only `node` and
`expected_version`. The latter is the controller contract generation, not an
opaque Kubernetes resourceVersion or availability/SLO version. A caller fence,
API endpoint, credential or attempt/idempotency key is refused.

The selected gateway advertises `io.kedgeflow/kubernetes-drain` with the profile,
`commit_point: controller_acceptance` and
`physical_completion: separate_observation`. Its tool catalog carries the exact
protected schema, contract digest and these completion semantics. Discovery
comes from the selected physical adapter; naming a physical tool on a generic
adapter is insufficient. The Node client checks these pins before execution and
checks the extension again on query-only connection.

`FamilySagaRunner` also compares the member's client binding to the complete
protected family catalog. It still uses the native phase and original-operation
checks. Task IDs, local state hints and catalog metadata supply no execution
authority.

## Native acceptance and independent physical completion

Fresh execution still performs original proposal preparation, independently
signed evidence, admission, issuance, durable grant persistence, gateway claim,
one-shot broker exchange and target acceptance. The original grant and target
transport deadlines remain five seconds in the qualification fixture. Ordinary
installation acknowledgement renewal happens before grant issuance; polling,
restart and recovery cannot extend that grant.

A committed native result is returned locally as:

```js
{
  state: 'accepted',
  native_state: 'committed',
  commit_point: 'controller_acceptance',
  physical_status: 'unresolved',
  attempt_id: '<original attempt>',
  grant_digest: '<original grant digest>'
}
```

An ambiguous original send remains `state: unknown`, with the corresponding
native state and unresolved physical status. Querying a committed native receipt
continues to return `accepted`, even if a separate observer has since recorded
physical completion. The SDK correlates the enrolled gateway's verified
controller acceptance; it does not independently verify a whole physical bundle
or report completed drain from a native receipt.

Use the complete signed physical family evidence and separately pinned
`kf-family-saga verify --bundle FILE --trust FILE` result for observed completion
or positive closed no-effect. Unknown, partial and failed physical work keeps
both original costs held and cannot authorize a SQL inverse. The SDK neither
redispatches an ambiguous operation nor remints its grant.

## Query-only recovery configuration

Use the protected `RecoveryConfig` with the same family registration and selected
physical child, fixed query URL, outcome-role mTLS identity and query token file.
That registered physical member selects `ControllerQuery` and its closed
`{"attempt_id":"original"}` request. Other target query bindings retain their
existing wire shape. There is no request-controlled physical-profile switch.

The controller query response is the existing closed authoritative observation
with `AttemptID`, `RootID`, `GrantDigest`, `Status` and `TargetReference`. Only a
correlated committed controller-acceptance reference qualifies native commit;
the recovery worker separately checks the original root/grant/attempt binding.
404, malformed replies, substituted attempts and other statuses remain unknown.
They never supply physical no-effect. A child-scoped recovery sweep filters the
shared namespace to that protected member's exact scope; paired inverse scopes
take precedence when configured. It cannot query another child's target merely
because both children share a namespace.

`kf-recover --config FILE --once` retains the original query result and signed
receipt without dispatching, minting, releasing costs or creating a new attempt.
After controller Pending, root stop and a new controller/SDK process, recovery
can resolve native acceptance while the independent physical state remains
unknown.

## Bounded qualification and remaining work

The [frozen-source record](../results/verification/rfc-m8-kubernetes-sdk-2026-10-23/README.md)
adds two required isolated real-cluster cases using official MCP client 2.3.0,
native mTLS control/gateway/broker services and the shipping controller/recovery
commands. The evidence provider uses a read-only service account to validate the
actual pinned inventory and availability before signing the exact proposal.
Its question/result schema explicitly describes available workload replicas and
controller generation; it does not reuse a SQL slot witness.

The positive path reports SDK acceptance while the independent aggregate reports
observed completion. The negative path discards the actual accepted target reply
at the adapter boundary, kills the controller after durable Pending, stops the
root and restarts. Shipping recovery retains native acceptance, and a new SDK
process only queries the original operation. One original admission, issuance,
broker mint and adapter dispatch are retained; the physical aggregate stays
unknown with both costs held. This adapter-boundary fault is distinct from the
M8e2a actual Kubernetes API effect/reply-loss transport qualification.

SQL predecessor execution and owner commands remain host fixture orchestration.
Control/gateway/broker services run native library servers on the same host;
the controller and recovery worker are shipping child processes. Generated
identities and colocated administration do not establish production custody.
Fixture readiness is not a workload SLO. Physical HITL/static-lease combinations,
wider evidence attacks and independent whole-saga acceptance remain unqualified.

[RFC 0056](rfcs/0056-physical-operating-records.md) specifies the remaining
M8e2b work: a protected Level C owner/on-call and incident operating
record and protected current SQL reservation/fence evidence under the declared
writer/storage boundary. Native committed acceptance must not resolve an incident
about unknown physical work. Historical SQL commit and fresh availability
observations alone do not establish a current exclusive reservation or an atomic
cross-resource guard. Independently administered writers/custody, production
maintenance, physical node failure and accepted SLO evidence remain M8e3 gates.
**M8 and the current development phase remain incomplete.**
