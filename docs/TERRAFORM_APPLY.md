# Protected Terraform execution (N2b)

`kf-terraform-apply` executes one admitted saved plan through a protected local
runner. The supported effect is the existing ConfigMap annotation update from
[saved-plan inspection](TERRAFORM_PLAN.md). This is an experimental native CLI
binding. The separately selected [gateway/SDK binding](TERRAFORM_GATEWAY.md)
now connects it to the shipping gateway and broker; generic configuration still
refuses this action. [RFC 0060](rfcs/0060-terraform-original-apply.md) defines
the separate draft profiles and authority boundary.

```sh
kf-terraform-apply --material-root /protected/runner \
  --config /protected/runner/config.json \
  execute --request /protected/runner/request.json
kf-terraform-apply --material-root /protected/runner \
  --config /protected/runner/config.json query --attempt-id ORIGINAL_ATTEMPT
```

Configuration pins the protected plan capsule, live local-backend root, separate
secret root, approved inspection/effect/manifest hashes, exact tool/schema,
gateway identity, token audience/scope, grant and target-token verification keys,
and authenticated native ledger. Configuration, request and credential files
use descriptor-relative custody. Administration must provision these pins from
approved artifacts; accepting agent-supplied pins would defeat the boundary.

The execution capsule uses `KF-TERRAFORM-PLAN-0.2-draft`, keeping v0.1 inspection
artifacts compatible. Its provider configuration contains only the fixed HTTPS
host and CA. Planner credentials are supplied through `KUBE_TOKEN`, and the live
fixture checks that they are absent from every saved-plan ZIP member. The
capsule additionally pins `backend.json`, the initialized local-backend metadata,
and one absolute `terraform.tfstate` path. The runner stages the metadata and
uses that live backend with Terraform's native locking, rather than applying
against the copied inspection state. Only the default workspace is supported.
Backend metadata and the plan's creation context are trusted planner inputs;
this is not independent attestation of an arbitrary submitted plan's backend.

The runner verifies the exact signed grant, original claim and retained request,
broker permit, dispatch record, current policy/ownership and installed control
state. It checks the original live backend bytes and independently reads the
target UID/resourceVersion and content with a get-only credential. An etcd CAS
retains a permanent per-manifest intent in the configured authority namespace,
comparing that original authority and an absent intent. Only its winning process
may read the writer credential and invoke the fixed saved-plan apply command.
Grant and target-token expiry are checked again before launching Terraform.

Successful apply requires a successful Terraform exit, unchanged backend lineage
with serial strictly advanced, and a separate target GET showing the exact
annotation effect with unchanged UID, data, labels and other annotations. The
real fixture advances serial 1 to 3 during one apply; an increment of exactly
one is not required. The retained native intent controls execution attempts.
The runner retains this result and the ordinary native attempt outcome. CLI reply
loss is recovered by querying the original intent. Repeated execution of that
same request performs a query; a different grant, attempt or effect refuses.

Any failure after intent retention yields `unknown`; retries never launch apply,
even after credentials or backend locks become available. Process loss can leave
`started`, also reported as unknown. A matching current target alone cannot
resolve that historical uncertainty. Query may disclose a historical committed
result alongside a now-false current postcondition. The report is a protected
local observation, not a portable signed outcome certificate.
Intent retention and ordinary native outcome publication are separate writes.
If publication fails, the intent still prevents apply and remains queryable;
automatic repair of that publication is not implemented here.

The [local-backend qualification](TERRAFORM_BACKEND_QUALIFICATION.md) exercises
actual state-lock contention, pre-check backend drift and Terraform's stale
saved-plan serial/lineage checks. Recognized apply failures retain a fixed
diagnostic category; raw tool/provider stderr is not disclosed. Diagnostics do
not resolve unknown effects or authorize another apply. Existing deadlines and
native locking are unchanged.

This is **Level C**. The pre-apply target read, native authority checkpoint and
Kubernetes effect are separate operations. A Terraform state lock coordinates
users of that backend; it does not atomically enforce target resourceVersion,
availability, policy changes or every external writer. Revocation after the
checkpoint cannot roll back an effect. The protected runner, approved binaries,
backend directory, authority namespace and writer credential must remain outside
agent control. Same-UID isolation, privileged administrator mediation, cluster
identity attestation and production credential delivery remain deployment gates.

The [verification record](../results/verification/terraform-apply-2026-11-08/README.md)
describes actual results and reproduction. HCP remote state/runs, multi-resource
or partial apply, autonomous retries, crash-after-effect reconciliation, Linux
custody qualification remain open. The explicit gateway/SDK binding has a separate
qualification record. N2 is not complete.
