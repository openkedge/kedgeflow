# Terraform gateway and Agent Adapter (N2c)

The explicit `KF-TERRAFORM-GATEWAY-0.1-draft` selection connects the
[native runner](TERRAFORM_APPLY.md) to shipping `kf-proxy`, `kf-broker` and the
Node Agent Adapter. It supports the same existing ConfigMap annotation update
and v0.2 local saved-plan capsule. Discovery and SDK results declare **Level C**
and `target_atomic: false`. [RFC 0061](rfcs/0061-terraform-gateway-sdk.md) defines
the binding.

## Setup

Start from [terraform-gateway.example.json](../config/terraform-gateway.example.json).
Replace all placeholders with approved planner, registry and identity material;
the template intentionally refuses startup. Use `kf-proxy --custody-root ROOT
--config FILE`. The certificate must identify the pinned gateway workload. The
plan, backend and secret roots retain descriptor-relative custody; shared UID
fixtures do not establish service isolation.

The `terraform_adapter` subtree pins native `Pins`, broker issuer and independent
target verification keys. Its sole tool must exactly match `pins.tool` and the
signed CTD's schema, action, parameters and writer inventory. `expected_version: 1`
identifies the capsule, not a Kubernetes version or atomic fence. Existing policy,
descriptor, installation and gateway acknowledgement enrollment still apply.
Use mutation scope `terraform:apply` and a distinct disclosure scope (`kf.status`).

The broker issues the original-claim-bound reference token for the exact target,
scope, grant/root/attempt and gateway. The actor assertion identifies the agent;
the outgoing gateway certificate identifies the gateway. Kubernetes writer and
observer credentials remain in the protected secret root. The writer is read
only after the original native intent CAS and never reaches the SDK. External
credential provisioning/rotation remains operator work.

`target_url` equals the target audience for configuration consistency; the local
adapter does not send Terraform to that URL. Kubernetes host/CA and backend path
come from the approved capsule. Mixed tools/adapters, read tokens and reservation,
family or inverse selections refuse. Omitting explicit selection still refuses
the Terraform action. `--check` reads local material and snapshots without native
authority use, token exchange or writer access.

Add this independently pinned SDK registration alongside the signed CTD and role
keys; request arguments cannot supply it:

```js
terraform: {
  profile: 'KF-TERRAFORM-GATEWAY-0.1-draft',
  manifestDigest: approvedManifestDigest,
  effectDigest: approvedEffectDigest,
  inspectionSha256: approvedInspectionSha256,
  resource: approvedResource
}
```

## Execution and recovery

The SDK requires exact capabilities, tool schema and plan metadata. It checks
the signed descriptor, arguments and grant, then correlates the first result's
original intent with the grant/root/attempt, plan/effect and backend/observation
hashes. Receipt fence equality supplies correlation; the contract declares no
fence enforcement. This is local historical evidence, not a portable signed
target proof.

The gateway owns claim, broker exchange, dispatch authorization and ordinary
outcome publication. The runner rechecks original authority/current control and
owns its permanent one-shot intent. Its internal gateway entry point leaves
ordinary publication to the gateway; the public CLI retains its own publication
behavior. The subprocess limit is 20 seconds; the selected gateway budget is
30 seconds, further clipped by grant expiry. Cancellation/ambiguity can leave
started/unknown and never releases an execution opportunity.

The SDK persists the grant before its single governed call. Lost replies,
repeated execution and restart use existing query-only `kedgeflow/status` under
current disclosure credentials. Cold query works after execution-grant expiry
and revocation with broker stopped and writer absent. It reads native historical
status, not current Kubernetes state. Unknown stays unknown; target coincidence
cannot establish historical success.

## Qualification

The [9 November record](../results/verification/terraform-gateway-2026-11-09/README.md)
records real saved-plan effects, shipping gateway/broker processes and official
SDK 2.3.0 completion, lost reply, unknown and cold query cases. It includes native
CLI/legacy SDK compatibility, adversarial vectors and owned-resource cleanup.

The separate [failure-boundary qualification](TERRAFORM_FAILURE_QUALIFICATION.md)
adds certified SIGKILL, revocation, target drift and SIGSTOP/expiry cases. It
preserves unresolved native phases and adds no automatic publication repair.

Level C races and protected-producer/backend assumptions still apply. Generated
same-host roles do not qualify independent custody or external providers. Linux,
HCP/remote backends, multi-resource partial apply, active-child crash handling,
automatic unknown/publication repair and portable signed outcome evidence remain
separate work. The complete N2 exit remains open.
