# Redacted Terraform plan inspection fixture

Generated with Terraform 1.17.1 and Kubernetes provider 2.38.0 from an actual
ConfigMap in the explicitly owned kind test cluster. A get-only planner token
imports the baseline and produces a refreshed saved plan for one annotation
update. No Terraform apply occurs; the target stays unchanged and the owned
namespace is removed.

The token is replaced by `fixture-readonly-token`. The configuration, state and
inspection files support offline semantic tests only. The manifest's SHA-256
values identify original private inputs; they deliberately do not authenticate
these redacted JSON files or supply an executable plan. No binary plan or tool
blob is included here. Reproduce the protected CLI path with
`scripts/test-terraform-plan.py` and the pinned tools; see
[the integration guide](../../docs/TERRAFORM_PLAN.md).
