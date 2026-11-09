# RFC 0060: Original-attempt Terraform apply

- Status: Draft; native protected runner implementation
- Profiles: `KF-TERRAFORM-PLAN-0.2-draft`, `KF-TERRAFORM-APPLY-0.1-draft`
- Named action: `terraform.configmap.annotation.apply`, version `1.0`
- Milestone: N2b; generic gateway/SDK integration remains open

## Contract and authority

Extend RFC 0059 with an explicit absolute local backend, pinned initialized
backend metadata and credential-free literal provider configuration. The saved
binary plan and all code/configuration/state/lock inputs are still snapshotted
and hashed through protected custody. Old v0.1 artifacts remain inspection-only.

Admission recognizes only the exact Level C adapter contract, closed constant
manifest/effect/resource parameters and explicit coordinated/uncoordinated writer
inventory. The synthetic predicate version `1` identifies the enrolled capsule;
it is not a Kubernetes resourceVersion or an atomic target guard. The resource
incarnation is the original target UID. The signed action/descriptor and grant
bind these values with existing admission and issuance records.

The runner requires the original native claim, retained execution request,
one-shot broker permit and dispatch authorization. An intent CAS compares the
original root/generation, nonce, grant, attempt, context, policy, ownership,
permit and current control state. Optional enrolled restore gates still govern
ledger transactions. The intent key is scoped by the configured authority
namespace and manifest digest. It has no lease or deletion/retry API. Re-enrolling
the same plan in another namespace or restoring the authority behind its retained
head is outside the once-only guarantee and requires administrative controls.

Only the winning process reads the protected writer credential. It launches
the pinned Terraform binary with a cleared environment, fixed provider layout,
`KUBE_TOKEN`, native locking and exactly:

```text
apply -input=false -lock=true -lock-timeout=1s -no-color plan.bin
```

Subprocess duration/output are bounded; the process group is cleaned up. The
writer credential and raw provider diagnostics are never emitted in reports.

## Outcome and recovery

Intent states are `started`, `unknown`, `applied`. Apply exit success alone is
insufficient: native backend lineage/serial and independent target postcondition
must also pass. A CAS replaces only the original retained intent, then records
the ordinary native outcome. Any ambiguous retention or process failure stops
execution. Exact retries query the original intent, including after grant expiry;
they do not need or read a writer credential. Other bindings refuse.

An applied intent is historical local evidence. A started/unknown intent cannot
be promoted from target coincidence. No refunds, replacement grants, automatic
reapply, inverse operation or partial-apply resolution are introduced.

## Limits and qualification

See the [execution guide](../TERRAFORM_APPLY.md) and its linked verification
record for the qualified native fixture and remaining limits. The authority
checkpoint is before target execution; this is not target-atomic authorization.
Trusted planner/runner code and administrative provisioning are assumptions.
The local CLI is an administrative surface without a network listener. Generic
MCP tools cannot select this action in this increment. Complete portable outcome
evidence, independent providers, external identity/Vault integration and deployed
writer coverage require separate work.
