# Native two-resource Terraform apply (N2f2)

`kf-terraform-pair-apply` executes one separately admitted compound action from
the [protected two-resource plan](TERRAFORM_PAIR_PLAN.md). It reuses the existing
native authority/credential/dispatch implementation and subprocess boundary.
[RFC 0065](rfcs/0065-terraform-pair-original-apply.md) and the
[draft schema](../spec/drafts/terraform-pair-apply-v0.1.schema.json) define the
separate `KF-TERRAFORM-PAIR-APPLY-0.1-draft` profile.

```sh
kf-terraform-pair-apply --material-root /protected/pair \
  --config /protected/pair/config.json execute --request /protected/pair/request.json
kf-terraform-pair-apply --material-root /protected/pair \
  --config /protected/pair/config.json query --attempt-id ORIGINAL_ATTEMPT
```

The action is `terraform.configmap.annotation.pair.apply` v1.0, with scope
`terraform:pair-apply`. One logical resource, `terraform-pair:<manifest_digest>`,
represents the immutable compound operation; its incarnation binds both member
identities/revisions, workspace and backend. The four application parameters
bind that resource, logical version 1, manifest and aggregate effect digests.
This profile accepts one resource and dispatch-bound completion without parent
grant or saga budget. It does not create two independently reusable grants.

Protected configuration pins the original capsule, exact tool/schema and
manifest/inspection/effect hashes, live backend, separate writer/observer files,
gateway identity, grant/target-token keys and authenticated native ledger.
The runner verifies current original grant, claim/context, broker permit,
dispatch, policy, ownership and installed control, original backend bytes and
both targets' exact UID/version/content. A successful native CAS retains the
per-plan intent before writer credential access. Expiry/token checks run again
before one fixed saved-plan apply. Native locking and existing timeouts remain.

Both profiles share this authority implementation; the existing single-resource
CLI still rejects pair configuration. Pair intents use a separate namespace.
Generic HTTP fallback still refuses the pair action. The separate
[N2f3 gateway/SDK binding](TERRAFORM_PAIR_GATEWAY.md) explicitly selects this
protected runner and preserves the same ordinary unknown semantics.

After the tool returns, separate get-only reads retain each member's target UID,
observation digest/time and state: `desired`, `original_observed` or `unresolved`.
Successful tool exit, backend lineage/serial progress and both exact desired
targets are required for `applied` and ordinary native `committed`. A completed
failed tool with backend progress, first desired and second original observed
retains `partial_observed` and ordinary native `unknown`. Other outcomes remain
unknown, including matching targets without successful tool completion.

`original_observed` is a snapshot, not proof that an effect never occurred or
that no late effect can occur. The original allowance remains held. There is no
automatic authority release, replan, reapply, force-unlock, inverse or refund.
An exact repeated request queries retained history, including after permissions
are restored or authority/writer access disappears. Conflicting requests refuse.
Current target coincidence cannot rewrite a historical partial/unknown outcome.

The [verification record](../results/verification/terraform-pair-apply-2026-11-09/README.md)
contains normal, partial and actual lost-reply cases. Kubernetes metadata audit
records establish that the first write completed before the second request,
which was denied with 403 in partial cases. The fixture restores and confirms
the second permission, then cold-queries after expiry/revocation with writer
absent and broker unavailable. Native write counts, backend bytes, history and
target-write audit events remain unchanged.

The failed resource's Terraform state can already contain its desired annotation
while the Kubernetes target retains the original value. Backend state therefore
does not establish the target result. The independent read-only verifier checks
actual target observations and audit events separately from provider state:

```sh
node scripts/verify-terraform-pair.mjs results/verification/terraform-pair-apply-2026-11-09
```

This is local software evidence with generated same-host identity/evidence/
policy/relay roles and a fixture-administered cluster. It is not independently
administered attestation or production custody. Level C races, trusted producer/
provider assumptions, active-child termination, Linux service isolation, wider
dependency/provider graphs, HCP/remote backends and automatic outcome repair
remain open. The complete N2 deployment exit is not met.
