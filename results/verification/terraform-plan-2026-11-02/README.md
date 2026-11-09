# N2a protected Terraform plan inspection — 2 November 2026

Baseline `92169c5eef910fe5c1808b9b9bff5f6f00c477d0` plus
[the source patch](source.patch); [source hashes](source-hashes.json) pin the
eleven changed/added implementation, schema and semantic-fixture files.
The [summary](summary.json) records tool pins, measured checks and remaining
limits. This evidence qualifies inspection only. No Terraform apply or new
gateway execution profile is implemented by this increment.

## Observed results

- [Rust tests](rust-tests.log): **10 new Terraform adversarial cases and five
  existing custody regressions pass**, zero failures, ignored cases or skips.
- [Clippy](clippy.log): the CLI and relevant test targets pass with warnings
  denied. Formatting, Ruff, draft-schema validation and whitespace checks pass.
- [Live fixture](live.log), [step results](steps.json) and [actual CLI report](report.json):
  **20 steps pass** on Darwin ARM64 against the explicitly owned kind cluster.
  The planner token has get permission for one ConfigMap and patch authorization
  refuses. Terraform imports its baseline and creates a real refreshed saved
  plan; the protected Rust CLI derives JSON from the exact private snapshots.
- The CLI succeeds despite invalid ambient Terraform argument/data-directory
  overrides. Swapped plan bytes and a pinned executable provider hook refuse;
  an apply flag is unsupported. Independent target reads remain identical.
- The owned namespace and private artifacts are removed, and the test VM started
  for this run is stopped. Generated credentials and raw binary plans are absent
  from the retained evidence.

The result is candidate evidence with `execution_enabled: false` and Level C
classification. Source state, target UID/resourceVersion and declared context
are bound; this is not a fresh target attestation or an admitted mutation.

The [partial preliminary fixture log](preliminary-failed-steps.json) is retained
separately and is not counted as qualification. The fixture was corrected to
use canonical absolute custody paths before the successful final run. No runtime
custody restriction was relaxed.

## Reproduction and tool pins

Rust/Cargo 1.98.0; Python 3.13.9; Terraform 1.17.1; Kubernetes provider 2.38.0;
the existing kind Kubernetes 1.37.0 fixture. Terraform and provider release
packages were downloaded over HTTPS and checked against the
[Terraform SHA-256 list](https://releases.hashicorp.com/terraform/1.17.1/terraform_1.17.1_SHA256SUMS)
and [provider SHA-256 list](https://releases.hashicorp.com/terraform-provider-kubernetes/2.38.0/terraform-provider-kubernetes_2.38.0_SHA256SUMS).
The manifest and summary also retain the extracted executable SHA-256 values.
This is checksum pinning, not a separate vendor-signature attestation.

```sh
cargo test --locked --offline --test terraform_plan --test custody
cargo clippy --locked --offline --bin kf-terraform-plan \
  --test terraform_plan --test custody -- -D warnings
cargo fmt --all -- --check
ruff check scripts/test-terraform-plan.py
python3 scripts/test-terraform-plan.py \
  --terraform /approved/terraform --provider /approved/terraform-provider-kubernetes \
  --kubectl /approved/kubectl --kubeconfig /private/owned-kind-kubeconfig \
  --context kind-kf8-owned-fixture --inspector /build/debug/kf-terraform-plan \
  --output /fresh/public/qualification-output
```

The script uses an explicitly selected loopback kind context, offline provider
installation, a fresh owned namespace and a get-only planner service account.
The provider binary must match the Terraform platform. It never runs apply.
Build the inspector first if the test command did not build its binary target.

The [redacted semantic corpus](../../../fixtures/terraform-plan/) contains
placeholder credentials and no executable plan. Its JSON is suitable for
offline validation tests, not for reconstructing original private input bytes.
Reproducing the script creates fresh private artifacts and different identities.

## Scope and remaining work

The protected planner and pinned Terraform/provider code are trusted; a shared
UID is not isolated. Workspace/backend/cluster labels are producer assertions,
not independent native-backend or live-cluster attestation. The inspector checks
supplied state consistency, not the current backend head. Physical custody,
complete writer/credential coverage, live freshness, independently administered
evidence and Linux/HCP/MCP deployment acceptance remain open.

N2b must add exact-action admission/grant/claim binding, credential custody,
the protected apply runner and original-run outcome/recovery semantics. Plan
hashes and Terraform locks do not establish target-atomic invariants. Lost
responses, partial apply and dependency/revocation races still need the separate
execution qualification described in [the integration guide](../../../docs/TERRAFORM_PLAN.md).
