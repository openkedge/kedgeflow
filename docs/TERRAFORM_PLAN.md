# Terraform saved-plan inspection (N2a)

`kf-terraform-plan` snapshots protected planner inputs and derives an inspection
from their saved binary plan. The current supported change is one existing
ConfigMap's `kedgeflow.dev/revision` annotation, using Terraform 1.17.1 and
Kubernetes provider 2.38.0. [RFC 0059](rfcs/0059-terraform-saved-plan.md) defines
the draft artifact contract and trust boundary.
The separate [two-resource candidate inspector](TERRAFORM_PAIR_PLAN.md) is a
read-only partial-apply prerequisite; it does not broaden this profile or the
single-resource execution action.

```sh
cargo build --locked --bin kf-terraform-plan
kf-terraform-plan --material-root /protected/planner/capsule \
  --manifest /protected/planner/capsule/manifest.json
```

The root contains six private non-executable files (`terraform.bin`,
`kubernetes.bin`, `plan.bin`, `state.json`, `lock.hcl`, `configuration.json`) plus
the private manifest. Use canonical absolute paths. The manifest's approved
hashes, versions, target and revision constraints are provisioned by trusted
planner administration. The source tool blobs are copied into private executable
snapshots; executable source files and ambient credential/helper configuration
are refused. Raw plans, inspection JSON and configuration may contain secrets.
The CLI emits only a candidate summary with hashes and declared target identity.

An `inspection_passed` result has `execution_enabled: false`. It proves the
implemented snapshot/inspection checks under the protected-planner assumptions;
it does not grant permission, attest current state or implement Terraform apply.
No gateway execution profile or MLP service package is enabled by this command.

## Insertion-point decision — 2 November 2026

The table is an engineering assessment of the documented interfaces. Only the
local inspection path is implemented and qualified here.

| Surface | Admission insertion point | Decision and required enforcement |
| --- | --- | --- |
| CLI saved plan | Protected runner immediately before `apply <saved-plan>` | Selected first: snapshot exact inputs, keep credentials outside the agent, preserve native locking and original-attempt status; this increment implements inspection only |
| HCP runs API | Protected caller of the run-specific apply action | Later binding: keep apply permission away from the agent, bind run/plan/configuration/workspace IDs, control auto-apply and preserve native queue/status semantics; queued apply is not completed target effect |
| HCP mandatory pre-apply task / policy | Existing governed gate before native apply | Potential additional admission hook; deployment must cover override/admin/direct API paths and independently enforce mutation authority |
| Remote Terraform MCP | Agent access to governed workflow tools | Agent Adapter entry point; disabling a tool alone does not remove equivalent API/CLI authority or supply target atomicity |

HashiCorp documents [saved-plan apply](https://developer.hashicorp.com/terraform/cli/commands/apply)
and [backend locking](https://developer.hashicorp.com/terraform/language/state/locking).
The [runs API](https://developer.hashicorp.com/terraform/cloud-docs/api-docs/run)
provides run-specific apply/retained state; apply queues execution.
[Run tasks](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/settings/run-tasks)
can be mandatory at pre-apply, and the
[MCP reference](https://developer.hashicorp.com/terraform/mcp-server/reference)
lists workflow toolsets. None of these documents establishes KedgeFlow
interoperability or target-atomic safety; those require separate qualification.

## Qualified behavior

The [verification record](../results/verification/terraform-plan-2026-11-02/README.md)
retains source/tool pins, adversarial Rust tests, custody regressions and an
actual provider saved-plan inspection on the owned kind fixture. The planner
token can get only its ConfigMap; patch authorization refuses. Independent reads
show identical target state before and after planning/inspection. No Terraform
apply was executed. The fixture namespace and private artifacts are removed.

The semantic fixtures in [fixtures/terraform-plan](../fixtures/terraform-plan/)
are redacted real output for offline tests. Their placeholder token and raw JSON
do not reproduce the original binary plan or its hashes. The real fixture
generator reproduces the private binary-plan-to-inspection binding.

The schema is [terraform-plan-v0.1.schema.json](../spec/drafts/terraform-plan-v0.1.schema.json).
The protected manifest and tool code are trusted inputs; source state is a
snapshot, and the supplied workspace/backend/cluster labels are assertions by
that producer. Live freshness, native backend/workspace identity and a complete
production writer/credential boundary remain unqualified.

## Next execution increment

The separately versioned [native apply runner](TERRAFORM_APPLY.md) now adds
exact-action authority, claim-before-credential custody, a live local backend,
retained intent and query-only recovery. Its v0.2 capsule excludes provider
credentials and additionally pins initialized backend metadata. This v0.1
inspector remains read-only. SDK/MCP integration, dependency/suspension races,
partial apply and production deployment qualification remain open.
