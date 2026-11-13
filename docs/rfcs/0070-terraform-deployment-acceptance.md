# RFC 0070: Exact deployed Terraform owner acceptance

Status: draft; read-only administrative records and pipeline preflight. No
runtime gateway, grant, SDK or existing action profile change.

Turn the N2 owner handoff into a closed, replayable check. Bind one deployment
ID, exact source/archive/configuration/writer inventory, the existing single or
pair Level C scope and a validity window. Require externally pinned deployment
and trust digests; records cannot supply their own trust. Distinct registered
owner keys accept seven complete sets of deployed observations. Storage, audit,
independent reproduction and deployment declare distinct administration domains.
Actual independence remains an externally accepted trust assumption.

Each owner approval uses a separate Ed25519 signature domain and binds the exact
gate, deployment, canonical observation hash, decision, validity and monotonic
sequence floor. Evidence is local, bounded and content-addressed. Missing,
unknown, failed, expired, future, substituted or fixture observations cannot pass.
Rejection and current key/floor withdrawal remain closed. The operator supplies
current approved trust; the offline tool cannot discover a newer snapshot.

Preparation creates unknown requests and empty approval lists. Neither command
generates authority, credentials, owner sign-offs or deployed measurements. The
verification report never marks an archive production-qualified and is not an
execution permit. A running gateway's query-only recovery remains unchanged.

See the [operator guide](../TERRAFORM_DEPLOYMENT_ACCEPTANCE.md),
[draft schema](../../spec/drafts/terraform-deployment-acceptance-v0.1.schema.json)
and [N2 handoff](../TERRAFORM_N2_COMPLETION.md). Synthetic crypto/record tests
qualify the checker; actual deployed inputs and owner acceptance remain required.
