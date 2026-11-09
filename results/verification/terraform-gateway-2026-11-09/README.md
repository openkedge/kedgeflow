# N2c gateway and SDK qualification — 9 November 2026

The explicit protected Terraform adapter now works through the shipping gateway,
broker and official Node MCP SDK. It preserves the native one-shot intent and
Level C classification. See the [guide](../../../docs/TERRAFORM_GATEWAY.md) and
[RFC 0061](../../../docs/rfcs/0061-terraform-gateway-sdk.md).

Baseline `9fdeaed` plus [source.patch](source.patch);
[source-hashes.json](source-hashes.json) pins the final changed/added source.
[summary.json](summary.json) records versions, measured populations and limits.
Prior native execution evidence remains unchanged and separately pinned.

## Actual results

| Case | Result |
| --- | --- |
| [Normal SDK apply](cases/normal/execution-diagnostic.log) | Real annotation effect, committed original native outcome; one claim, permit, dispatch and intent |
| [Lost SDK apply reply](cases/lost/execution-diagnostic.log) | SDK discards the completed response and resolves the same committed attempt by status; no second effect |
| [Missing writer](cases/missing-writer/execution-diagnostic.log) | Protected gateway starts without reading writer material; execution retains unknown; target unchanged |
| [Legacy native CLI](cases/legacy-cli/execution-diagnostic.log) | Original CLI still publishes its outcome and recovers the discarded reply without apply retry |

Each SDK case uses fresh Cedar admission/issuance, the real `kf-proxy` and
`kf-broker` binaries, verified mTLS/DPoP and signed generated subject/actor identity
fixtures. Native etcd retains the original claim and broker permit; Terraform
1.17.1/provider 2.38.0 operate on the real owned kind target and live backend.
The broker uses its pinned identity snapshot and actual reference-token minter.
An authenticated fixture relay counts successful native writes, rather than
inferring one-shot behavior from agent logs.

All three SDK cases kill and restart the gateway, stop the broker, revoke the
domain, wait for grant expiry and remove writer access. A new SDK process with
only status scope resolves the same attempt and digest. Repeated execution stays
query-only. Native counters remain **[1 claim, 1 permit, 1 dispatch, 1 intent]**;
the backend stays byte-identical during cold recovery. Each `sdk-native-report.json`
retains those correlations and the request trace. Independent target reads and
namespace ownership/cleanup checks are retained alongside the plan observations.

[Regressions](regressions.log): **67 pass** across admission (20), configuration
(6), contracts (11), custody (5), gateway (13), and Terraform inspection/action
binding (12). Two existing live SDK workflows also pass, including lost replies.
With three new SDK cases and one legacy CLI case, this is **73 Rust test runs**
across the stated populations, with no failures, ignored cases or skips.
[SDK vectors](node-vectors.log) pass all six selected suites, including **46 new
Terraform checks** for descriptor/schema/argument/grant/result substitution and
capability downgrade. [Clippy](clippy.log) passes with warnings denied.
[Checks](checks.log) cover formatting, whitespace, schemas, documentation links,
source pins and unchanged prior evidence.

## Scope and reproduction

This is Darwin ARM64, three-member single-host loopback etcd and an owned kind
Kubernetes 1.37.0 cluster. Identities, evidence provider, allow policy and relay
roles are generated same-host fixtures. They do not establish independent
administration, production etcd RBAC, Linux custody or external provider/Vault
acceptance. Native status is historical; it is not a current target read or a
portable signed outcome proof. Level C revocation/state races, partial apply,
process-crash reconciliation and unknown/publication repair remain open.

The [driver](qualification-driver.py) records the remaining cases and regression
commands. The normal case uses the same generator and exact Rust test
`terraform_apply::gateway::official_sdk_shipping_gateway_and_broker_apply_then_cold_query`.
Use a fresh capsule/output per case:

```sh
cargo build --locked --bin kf-proxy --bin kf-broker --bin kf-terraform-plan
ETCD_BINARY=/approved/etcd scripts/start-etcd.sh -- \
  python3 scripts/test-terraform-plan.py \
  --terraform /approved/terraform --provider /approved/kubernetes-provider \
  --kubectl /approved/kubectl --kubeconfig /private/owned-kind-kubeconfig \
  --context kind-kf8-owned-fixture --inspector /build/debug/kf-terraform-plan \
  --expect-effect --output /fresh/public/output \
  --execution-command cargo test --locked --test governance \
  terraform_apply::gateway::official_sdk_shipping_gateway_and_broker_apply_then_cold_query \
  -- --exact --nocapture --test-threads=1
```

Omit `--expect-effect` for the missing-writer case. SDK dependencies are pinned in
`tests/sdk/package-lock.json`; the fixture requires their installed official client
2.3.0. [Protocol samples](protocol-samples.json) are synthetic schema vectors,
separate from actual plan evidence. [Cleanup](cleanup.log) confirms all fixture
namespaces, the owned cluster and its new VM were removed/stopped. Other VM and
user contexts were untouched. Credentials and raw executable plans are absent
from public evidence. No production or complete N2 exit is claimed.
