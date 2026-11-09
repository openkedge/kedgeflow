# RFC 0065: Original-attempt two-resource Terraform apply

- Status: Draft; native runner implemented; real-target qualification in progress
- Milestone: N2f2
- Runner profile: `KF-TERRAFORM-PAIR-APPLY-0.1-draft`
- Action: `terraform.configmap.annotation.pair.apply`, version 1.0

Register one immutable compound action covering exactly the two ordered targets
in RFC 0064. Its logical resource is `terraform-pair:<manifest_digest>`; its
incarnation binds both member identities, revisions, workspace and backend.
Parameters bind that resource, logical plan version 1, pair-manifest digest and
aggregate effect digest. This is one admitted compound operation, not two
independently reusable grants. Existing budget/claim semantics hold its original
allowance after uncertainty or a partial observed result.

Use the existing proposal/certificate/grant, current control, original claim,
broker permit and dispatch authority. The protected runner must compare this
complete original chain and retain one permanent per-plan intent before reading
the writer credential. Keep native local-state locking, saved-plan-only apply,
bounded process execution and independent read-only target verification. Do not
replan, force-unlock, reapply, renew authority or compensate automatically.

Retain each member's correlated target UID, observation digest/time and observed
state: desired, original_observed or unresolved. Original observed state is not
an authoritative no-effect barrier. A completed successful tool, backend lineage/
serial advance and both exact desired targets are required for applied/committed.
A completed failed tool with backend progress and one exact desired member and
one exact original member may retain partial_observed. Every other result remains
unknown. Partial observed results publish ordinary native unknown and keep the
original allowance held. Current target coincidence cannot rewrite history.

Pair admission uses the separate Level C adapter contract. Single-resource
profiles and released wire records remain unchanged. Generic gateway discovery
and execution refuse the pair action; shipping pair gateway/SDK integration
requires a separate qualified binding. The native CLI is the initial insertion
point, as for RFC 0060.

Required qualification: normal ordered apply; first write success followed by
an independently recorded second-write denial; lost reply; exact replay/cold
query after expiry/revocation with writer absent; conflicting request refusal;
unchanged single-resource behavior. Retain Kubernetes metadata audit events and
separate target/backend observations. Generated same-host roles are software
evidence, not independent production custody or target-atomic safety.
