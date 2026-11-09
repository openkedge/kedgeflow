# N2b native Terraform apply — 8 November 2026

The protected runner now executes one admitted saved plan and recovers its
original result without another apply. This is a narrow **Level C native CLI**
increment. Generic gateway configuration and discovery refuse this action; SDK,
MCP, external identity/Vault and production deployment qualification remain open.
See the [guide](../../../docs/TERRAFORM_APPLY.md) and
[RFC 0060](../../../docs/rfcs/0060-terraform-original-apply.md).

Baseline `92169c5eef910fe5c1808b9b9bff5f6f00c477d0` plus
[source.patch](source.patch); [source-hashes.json](source-hashes.json) pins the
current implementation and its N1/N2a prerequisites in the shared working tree.
The previous N2a inspection evidence is retained unchanged and pinned in
[prior-inspection-evidence-hashes.json](prior-inspection-evidence-hashes.json).

## Results

| Actual owned-kind case | Observed result |
| --- | --- |
| [Discarded CLI reply](cases/lost-reply/execution-diagnostic.log) | Actual annotation effect; fresh process query reports the retained original committed intent; exact retry after revocation and writer removal leaves backend unchanged |
| [Revocation](cases/revoked/execution-diagnostic.log) | Refuses before intent; backend and target unchanged |
| [Backend drift](cases/backend-drift/execution-diagnostic.log) | An independently advanced backend serial refuses before intent; no additional backend or target effect |
| [Missing writer](cases/missing-writer/execution-diagnostic.log) | Retained unknown; restoring the writer permits only query, followed by query after revocation and writer removal; backend and target unchanged |
| [Backend lock](cases/backend-locked/execution-diagnostic.log) | Actual held native backend lock prevents apply; retained unknown stays query-only after lock release and after revocation/writer removal; backend and target unchanged |

Every case starts with a new real provider saved plan, fresh Cedar admission and
native issuance/claim, original broker authorization/target reference token and
dispatch record. The shipping CLI uses a gateway-mTLS relay to actual three-member
loopback etcd and the real Kubernetes target. Independent administrative target
reads and backend observations are retained with each case. The two unknown
cases have an additional confirmation run that explicitly retries with the
original obstacle removed and writer access available. Earlier successful
versions of those cases are retained under `initial-cases/`.

The [regression log](regressions.log) records **66 passing tests**: admission 20,
configuration 5, contracts 11, custody 5, gateway 13 and Terraform inspection/action
binding 12. Required etcd is present; there are no skips or ignored cases. The
[backend regression](backend-tests.log) adds one passing test for multiple state
checkpoints, rollback, malformed serials and lineage substitution. Seven live
executions cover five distinct cases. [Clippy](clippy.log) passes with warnings
denied; formatting, Ruff, draft schemas, source pins and whitespace checks pass.

The actual apply advances the original lineage from serial **1 to 3**. A state
serial counts persisted checkpoints rather than apply opportunities; the runner
requires strict advancement, successful Terraform exit and the separate exact
target postcondition. Its retained native intent enforces once-only dispatch.

## Trust and limits

These are same-host Darwin ARM64 software fixtures with generated administrative,
workload, grant and evidence identities and an allow policy. The relay checks the
gateway certificate role and fixture ledger token; it is not production etcd
RBAC or independently administered custody. The broker authorization library and
reference minter are real, while the identity provider is a generated fixture.
No shipping SDK/MCP or external AS/Vault integration is claimed.

Planner/code/manifest approval, initialized backend metadata and the declared
cluster/workspace context are trusted inputs. Pre-apply target reads, native
authority checks and the Kubernetes effect are separate operations. A backend
lock does not guard every target writer, and revocation after the checkpoint
cannot roll back an effect. An applied intent is local historical evidence,
not a portable signed outcome proof. Process loss after effect but before result
retention remains unknown; matching target state alone cannot resolve it.
Intent/outcome publication repair, partial/multi-resource apply, Linux/HCP
qualification and production service/credential boundaries remain open.

Public output contains no writer/planner tokens or raw executable plans. Each
fixture verifies namespace UID/ownership before deleting it and removes private
artifacts. [cleanup.log](cleanup.log) records final owned-cluster cleanup and VM
shutdown. The test environment had survived temporary-file cleanup with running
VM sockets but missing metadata; that infrastructure issue is recorded separately.

## Reproduction

Use Terraform **1.17.1**, Kubernetes provider **2.38.0**, matching platform binaries,
and the explicitly owned loopback kind context. Release/archive and executable
SHA-256 values are in [summary.json](summary.json); they match the previously
checked N2a official release checksums. This is checksum pinning, not a new vendor
signature attestation. Kubernetes client/server versions are retained in
[kubernetes-version.json](kubernetes-version.json).

```sh
cargo build --locked --bin kf-terraform-plan --bin kf-terraform-apply
ETCD_BINARY=/approved/etcd scripts/start-etcd.sh -- \
  python3 scripts/test-terraform-plan.py \
  --terraform /approved/terraform --provider /approved/kubernetes-provider \
  --kubectl /approved/kubectl --kubeconfig /private/owned-kind-kubeconfig \
  --context kind-kf8-owned-fixture --inspector /build/debug/kf-terraform-plan \
  --expect-effect --output /fresh/public/output \
  --execution-command cargo test --locked --test governance \
  terraform_apply::native_real_plan_original_apply_and_lost_reply \
  -- --exact --nocapture --test-threads=1
```

Select the other exact test names from `crates/kedgeflow/tests/support/terraform_apply.rs`
and omit `--expect-effect` for refusal/unknown cases. Never share a live capsule
between these destructive disposable-fixture tests. The retained driver scripts
show the exact qualification sequence; their local tool paths require adjustment.

Preliminary 2 November failures are retained separately, including the initial
overly strict serial-1-to-2 expectation. That attempt stayed unknown despite its
target effect. Qualification uses fresh original plans and intents after the
correction; no historical unknown was reinterpreted or retried.
