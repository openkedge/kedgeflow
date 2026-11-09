# RFC 0059: Protected Terraform saved-plan inspection

- Status: Draft; bounded inspection prerequisite implemented
- Profile/version: `KF-TERRAFORM-PLAN-0.1-draft` (local artifacts, no execution wire)
- Milestone: N2a, from the 2 November implementation update
- Baseline: `92169c5` plus the separately pinned N2a source changes
- Owners/reviewers: resource, policy and gateway owners; individual reviews open

## Problem and scope

An agent-supplied plan hash or independently supplied JSON is insufficient to
bind an infrastructure proposal to executable plan bytes. A protected planner
must pin the inputs and derive the inspection from the saved plan it actually
holds. This increment implements that read-only prerequisite for Terraform
1.17.1 and Kubernetes provider 2.38.0, one root-module ConfigMap update, and one
existing `kedgeflow.dev/revision` annotation changing between known values.

It does not implement Terraform dispatch, target guards, admission, credential
exchange or outcome recovery. Existing gateway acceptance remains unchanged.
Inspection output is unsigned candidate evidence, not a certificate or grant.

## Authority and trust

The caller is protected planner administration. Its material root and manifest
must be inaccessible to the agent and descendants. The manifest pins six
private, non-executable source blobs: Terraform and provider binaries, binary
plan, raw state, dependency lock and literal JSON configuration. Operator-approved
hashes establish the allowed code; computing new hashes from agent-controlled
code is not approval. Both binaries are trusted execution dependencies.

Descriptor-relative reads reject links, unsafe ownership/modes and concurrent
file metadata changes. Each snapshot must match its manifest SHA-256. Existing
configuration/key readers retain their 2 MiB bound; a separate opt-in private
snapshot method caps binaries at 128 MiB, plans at 16 MiB and other inputs at
2 MiB. Sources must remain non-executable private files, including tool blobs.

The inspector copies these exact bytes into a new private directory with
validated ancestor custody, fixed file names and the pinned provider layout.
It runs only the copied Terraform binary, first `version -json`, then
`show -json plan.bin`. No shell, init, refresh, plan or apply command exists in
the inspector. Child environment is empty except fixed Terraform inspection
settings. The process group is killed on completion/error; output and duration
are bounded. Raw plan/provider output is never printed in diagnostics.

This does not sandbox trusted tool code or protect a shared UID against itself.
Deployment requires an independent service account or enforced equivalent.

## Contract

[The draft schema](../../spec/drafts/terraform-plan-v0.1.schema.json) defines
closed Manifest and Inspection objects. Semantics additionally require distinct
before/after revisions (each at most 256 UTF-8 bytes), exact supported versions,
safe target names and the exact file set. The manifest digest is the existing
domain-separated KedgeFlow digest over its serialized value. Inspection also
binds raw inspection SHA-256, all input SHA-256 values, state lineage/serial,
workspace/backend labels, target cluster/UID/resourceVersion and the canonical
before/after effect digest.

Semantic validation requires a complete, applyable, non-errored JSON format 1.2
plan with exactly one managed update. No create/delete/replace/import/move,
extra resources, modules, outputs, drift, deferred work, actions, variables,
executable hooks or provider authentication helpers are supported. Authorized
fields must be known. Only computed metadata generation/resourceVersion may be
unknown. Before/after comparisons permit precisely the one annotation change.
Provider resource ID, UID, name and namespace must remain bound. Source state,
prior-state view, planned-values view and both embedded provider/resource
configuration expressions must agree with protected inputs.

The candidate classification is Level C with `execution_enabled: false`.
Terraform locking and a saved-plan digest do not establish atomic target
predicates. Workspace/backend/cluster labels are protected producer assertions;
the inspector does not attest a live target or independently decode the opaque
plan's backend settings. The snapshot pins the supplied state bytes and their
consistency with the plan, not the current backend head. Native backend/workspace
verification, current target evidence and dispatch authorization belong to N2b.

## Failure and retry

Read, hash, version, shape, semantic, timeout and subprocess failures refuse
inspection. The 20-second per-command bound, 2 MiB stdout and 64 KiB stderr caps
are local profile limits. Cleanup removes private snapshots and kills the owned
process group. No mutation is dispatched and no allowance is claimed, so a new
inspection does not retry an infrastructure mutation.

The CLI has no apply or general command option. Future execution must use fresh
authority and the existing original-attempt lifecycle; a successful inspection
cannot bypass those checks or reopen an uncertain effect.

## Compatibility and rollout

The artifact profile is separately named and is not a new kind in frozen
KF-JSON-0.2. It is not advertised through MCP or accepted by the existing
gateway/broker. Do not reinterpret a Level A grant or the named drain contract
as Terraform authority. Other versions, providers, backends, resources and
partial/multi-resource plans remain unsupported in this increment.

## Implementation and acceptance

- `terraform_plan.rs` implements protected inspection and semantic validation;
  `kf-terraform-plan` is the local administrative CLI.
- Unit/adversarial cases use redacted output from a real saved provider plan.
  They cover extra effects, unknowns, hooks, state/config substitution, closed
  parsing, custody and swapped input bytes, plus existing custody regressions.
- `scripts/test-terraform-plan.py` creates an owned disposable kind ConfigMap,
  gives Terraform a get-only token, imports its baseline and produces a real
  refreshed saved plan. It verifies patch denial and unchanged target state,
  invokes the protected CLI and exercises negative calls before cleanup.
- Qualification and remaining limits are recorded in
  [the integration guide](../TERRAFORM_PLAN.md) and its verification bundle.

## Open decisions

Resource/gateway owners must define a separate exact-action grant binding,
non-bypassable runner, target credential scope, native workspace/backend checks,
live dependency evidence and guard strength. Policy/outcome owners must define
freshness/revocation check points, partial/unknown apply evidence and retained
original-run query semantics. A saved-plan apply may have multiple provider
effects, and must not inherit SQL Level A or blind retry semantics.
