# RFC 0063: Terraform local-backend qualification

- Status: Draft; bounded supplement to RFC 0060/0061/0062
- Milestone: N2e
- Wire/profile change: none

Qualify native state locking and saved-plan refusal through the existing
protected runner, shipping gateway/broker and official SDK. A fresh real plan,
original native authority and independent target/backend observations are
required per case.

Hold an exclusive OS lock on the actual live backend after durable intent, and
verify contention through an independent descriptor and Terraform's bounded
lock refusal. Hold it until refusal, then release it without retry. Inject
serial drift before the runner's state check and serial/lineage drift after
intent. Prove that only live backend metadata changes and that target state and
the immutable plan capsule remain fixed. Require original grant validity through
the refusal; incidental expiry cannot certify backend enforcement.

Retain only a fixed diagnostic category for recognized Terraform apply stderr.
Unknown/ambiguous diagnostics remain generic. Never echo raw provider output or
interpret a diagnostic as an authoritative no-effect barrier. Every failed
apply retains unknown; pre-intent backend mismatch leaves no runner intent.
This changes no admission, grant, dispatch, outcome or SDK wire shape.

Cold gateway/SDK recovery after expiry/revocation, broker shutdown and writer
removal must preserve the original attempt, intent, backend bytes and native
counters. Repeated SDK execution performs status queries only. Preserve native
locking, existing deadlines and the prohibition on force-unlock, automatic
replanning, reapplication and authority release.

See [the guide](../TERRAFORM_BACKEND_QUALIFICATION.md) for evidence and limits.
Controlled state-file edits are not a second successful Terraform run or a
multi-resource partial-apply experiment. Level C, deployment, active-child and
independent acceptance gates remain open.
