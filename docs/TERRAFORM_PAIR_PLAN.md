# Protected two-resource Terraform inspection (N2f1)

`kf-terraform-pair-plan` derives candidate evidence from one protected saved plan
containing exactly two existing ConfigMap annotation updates. This is the
read-only prerequisite for the separately admitted partial-apply fixture in the
[N2 plan](IMPLEMENTATION_UPDATE_2026_11_02.md#n2-terraform-integration-contract-and-demonstration).
It does not implement pair admission, execution, compensation or partial outcomes.

```sh
kf-terraform-pair-plan --material-root /protected/pair \
  --manifest /protected/pair/manifest.json
```

[RFC 0064](rfcs/0064-terraform-pair-plan.md) and the
[draft schema](../spec/drafts/terraform-pair-plan-v0.1.schema.json) define the
separate `KF-TERRAFORM-PAIR-PLAN-0.1-draft` candidate profile. The single-resource
profiles, apply action, gateway discovery and SDK runtime remain unchanged.
The original inspector/runner rejects the new profile. A pair report cannot be
used as a single-resource apply capsule.

The manifest binds fixed members `first` and `second` in that order, with distinct
ConfigMap names and UIDs in one cluster/namespace, exact before/after revisions,
one local backend path and shared state lineage/serial. It pins Terraform 1.17.1,
Kubernetes provider 2.38.0, platform, binary plan, configuration, dependency lock,
state snapshot, initialized backend metadata and both executables. Provider
configuration contains only the HTTPS endpoint and CA; the read-only planner
uses an environment credential that must not occur in the saved plan ZIP.

Protected HCL JSON and the binary-derived embedded configuration must declare
`second` depends on `kubernetes_config_map_v1.first`. There are no other resource
types, module calls, dynamic inputs, hooks, provisioners or external dependency
reads. Every change, prior/planned value, embedded configuration and stored-state
view must contain the same exact two members. Every effect must be one annotation
update, preserving resource identity, data, labels and other annotations.
Only the original validator's permitted provider-computed fields may be unknown.

The implementation validates the complete two-member set and dependency before
projecting each member into the existing closed single-resource semantic
validator. Projection changes only the fixed logical address/name and removes
the already-checked dependency. Both per-member effect digests, actual addresses,
target identities and declared order enter a separate aggregate effect digest.
The manifest and complete original JSON inspection have their own bindings.
Neither projection nor these digests grants execution authority.

The protected reader reuses descriptor-relative custody, private staging,
fixed executable paths, cleared environment, input/output limits, subprocess
deadline and process-group cleanup. It validates protected configuration before
spawning even version/show commands. It exposes no apply flag or command.

The [verification record](../results/verification/terraform-pair-plan-2026-11-09/README.md)
retains a real two-resource saved plan inspection, get-only planner RBAC, unchanged
independent target observations, negative custody/input/hook checks and original
single-resource compatibility. The declared dependency is verified in planning;
physical execution order and partial application have not been qualified.

Next, N2f2 needs its own exact two-resource admission/authority binding, protected
apply path, per-effect independent observations and partial/unknown aggregate
retention. It must demonstrate one effect completing before the other fails and
original-attempt recovery without reapply. Compensation requires separate fresh
authority and a valid applicability/barrier proof. Active-child termination,
Linux custody, HCP, target-atomic invariants and independent production acceptance
remain open; N2 is incomplete.
