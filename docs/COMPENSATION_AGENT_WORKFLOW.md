# Official SDK inverse workflow — M8d3b

The existing Node [Agent Adapter](AGENT_ADAPTER.md) now has a qualified bounded
inverse path using the official MCP client, [RFC 0047 native authority](NATIVE_COMPENSATION_AUTHORITY.md)
and the [RFC 0048 SQL target/barrier](POSTGRES_COMPENSATION_TARGET.md). It uses
existing wire profiles. A client request never creates a contract, barrier,
applicability decision, held allowance or restore value.

## Prepare the exact original operation

Approve the paired controls, original forward plan, inverse contract, stable inverse
QID and signer roles before forward issuance. Retain the approved QID alongside
the contract: its `inverse_operation_key` is a digest, not a recoverable QID.
Provision the protected SQL snapshot before executing the forward action.

After the original forward effect is independently known committed, obtain the
actual target barrier and the separate evaluator's applicability proof. Retain that
exact qualification, then enter permanent compensation mode. Unknown forward
allocations block this transition. The native inverse service selects one exact
contract; the client cannot substitute another operation or obtain another allowance.

Use the ordinary Agent Adapter configuration with independently approved fixed
endpoints, signed inverse CTD, role public keys, subject/workload, token issuer,
DPoP key, proposal signer and durable store. Add the explicit protected registration:

```js
const config = {
  ...approvedCommonConfig,
  compensation: {
    profile: 'KF-COMPENSATION-LEAF-0.1-draft',
    contractDigest: approvedContractDigest,
    parameters: approvedQualification.proof.parameters
  }
};
```

The referenced values must come from independently approved and verified material,
not a discovery response, remediation hint or agent-supplied keys. Parameters are
exactly resource ID, expected version, original forward grant/attempt and registered
restore-state digest. They contain no restore value, URL, fence or target credential.

The client verifies the registry-signed inverse CTD and exact closed schema,
negotiates `io.kedgeflow/compensation-leaf`, and checks the selected tool's advertised
contract digest against the protected pin. Changed original parameters, unsupported
profile/schema or a different contract refuse before fresh authority work.

## Execute once and preserve ambiguity

With an `AgentAdapter` constructed using that protected configuration:

```js
await agent.connect();
const result = await agent.execute({
  qid: approvedInverseQid,
  arguments: config.compensation.parameters
});
```

Its independently authenticated evidence source supplies the fresh current baseline,
signed manifest and evidence. Native admission and issuance independently verify
those records and Cedar policy under the inverse control. Qualification alone is
not admission. The native issuer retains the mandatory compound binding and original
held spend in the same issuance transaction. The client persists its original
proposal/certificate/grant before the governed call.

The gateway claims once. The native broker rechecks original inverse authority in
its credential-permit transaction; it verifies the real subject and actor tokens
before minting one narrow target credential. The adapter reads the original bound
qualification from the ledger after dispatch authorization. The independent target
checks the proof, binding, grant and credential, then performs the conditional SQL
restore with its original attempt/version/fence guards.

Do not repeat admission, minting or `tools/call` after an ambiguous request, allocate
a replacement QID, renew the original grant or release held capacity on a timer.
The durable store makes a restarted operation query-only. If its original grant
was not retained locally, the signed-proposal operation-status path remains the
existing recovery route. Storage loss or inconsistent records require investigation;
they do not authorize reconstruction of a new inverse operation.

A lost target reply can leave the native attempt unknown after SQL COMMIT. The
separate query role resolves the exact original target attempt. Signed native
outcome recovery refines that original held spend after expiry or stop. A later
client process uses the same QID/store and a current status-only delegation; it
returns the same original attempt and grant without collecting evidence, admitting,
issuing, minting or dispatching again. Allowances remain held after success.

## Qualification boundary

[The required-mode record](../results/verification/rfc-m8-compensation-agent-2026-10-15/README.md)
retains **430 Rust tests across 51 binaries**, **26 SQL groups**, **32 Python tests**
and both Node suites. Two new official-client cases cover positive actual SQL
restoration and a lost target reply, with separate Node-process restart after
stop/expiry. Both retain one original credential mint and SQL effect. The evidence
fixture reads the actual SQL version/state, while its capacity labels and signer
custody remain generated software fixtures. They establish no deployed business
predicate or independent enterprise acceptance.

This delivers one contract's SDK composition. Multi-contract inverse families,
independently verified complete multi-node saga history, inverse storage restore /
wider crash qualification and deployment acceptance remain open. Kubernetes drain
and its Level C physical limits remain separate M8e work. M8 is incomplete.
