# RFC 0064: Protected two-resource Terraform candidate inspection

- Status: Draft; N2f1 prerequisite for partial-apply qualification
- Profile: `KF-TERRAFORM-PAIR-PLAN-0.1-draft`
- Authority/execution: none

Add a separate protected read-only inspector for exactly two existing ConfigMap
annotation updates. Fixed members first/second have distinct UIDs and names in
one cluster/namespace. Bind exact before/after effects, workspace, local backend,
state lineage/serial, initialized backend metadata, full immutable plan/config/
lock/state inputs and pinned Terraform/provider executable versions/checksums.

Require one explicit forward dependency in both protected configuration and
binary-derived embedded configuration: second depends on first. Require exact
two-member correspondence across every state/change/configuration view. Reject
additional resources, dynamic inputs, unsupported unknowns, external dependency
reads, executable hooks, providers, modules, replacement and effects beyond the
two declared annotations.

Validate the complete member set/dependency, then reuse the existing closed
single-resource semantic checks per member. Bind both original addresses,
incarnations, per-member effect digests and declared order into a separately
domain-separated aggregate effect digest. Retain the original complete JSON
inspection hash and pair-manifest digest. Reports contain candidate evidence,
Level C and execution_enabled:false; no current-authority or effect claim.

Reuse protected snapshot/staging and fixed read-only Terraform version/show
commands. Credentials stay outside the saved plan. The new CLI cannot apply;
old single-resource inspectors/runners reject the pair profile. Released/frozen
profiles, existing apply action, gateway tools and SDK wire behavior do not change.

See [the guide](../TERRAFORM_PAIR_PLAN.md), draft schema and verification record.
A subsequent pair execution contract must obtain separate admission, preserve
original authority, classify each observed effect and retain partial/unknown
aggregate outcomes without reapply. Planning dependency order is not evidence
of physical execution or a target-atomic invariant. This RFC closes neither
partial-apply demonstration nor production acceptance.
