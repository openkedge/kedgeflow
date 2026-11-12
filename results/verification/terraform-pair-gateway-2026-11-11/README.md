# N2f3: protected pair gateway and official SDK

Qualification date: 11 November 2026 (America/Los_Angeles). Audit timestamps are
UTC and fall on 12 November. Baseline `0fe6ad3`; intermediate implementation
`bc55d94`. The [guide](../../../docs/TERRAFORM_PAIR_GATEWAY.md),
[RFC 0066](../../../docs/rfcs/0066-terraform-pair-gateway-sdk.md) and
[draft schema](../../../spec/drafts/terraform-pair-gateway-v0.1.schema.json)
define the separate selection.

## Observed results

| Case | Native physical history | Ordinary SDK state | Original recovery |
| --- | --- | --- | --- |
| normal | Successful tool/backend and both exact desired targets | committed | Query after cold restart, expiry/revocation, writer absent and broker stopped |
| lost | Same physical completion; actual response bytes drained and withheld from SDK | committed by status | Original status only; no second tools/call |
| partial | First write succeeded; second request denied with 403 | unknown | Restored permission cannot promote or reapply the historical partial outcome |
| partial-lost | Same partial effect; actual reply withheld from SDK | unknown by status | Cold query preserves the original held allowance |
| legacy-sdk | Existing single-resource profile still commits | committed | Frozen single-resource intent shape and original query preserved |

Each case uses the shipping `kf-proxy`/`kf-broker`, official
`@modelcontextprotocol/client` 2.3.0, real Terraform 1.17.1 and Kubernetes provider
2.38.0, an owned kind cluster, Cedar admission and a disposable three-member
etcd 3.6.5 ledger. Generated fixture identity/evidence services provide fresh
inputs; they are not independently administered services.

Actual native counters show one claim, broker permit, dispatch, started intent,
intent outcome and ordinary publication. The fixture verifies exact native
intent bytes, backend bytes and counters before/after repeated original and
cold status queries. Status-only calls carry no grant dispatch header and make
no admission/issuance calls. Second-member write permission is restored and
independently confirmed in partial cases before the cold query. Metadata audit
records show first write completion before the second request and no additional
target writes during query/recovery. Get-only raw target observations separately
check the effects; provider state can already contain the failed member's
desired revision while its actual target remains original.

The direct normal result passes the SDK's exact pair report, member identity/
order, summary digest, backend and original grant/receipt checks. Lost replies
record a positive count of bytes drained and withheld, with no direct result.
Partial results return ordinary unknown; they never expose a successful receipt.
The single-resource SDK/schema runtime is checked separately for compatibility.

## Checks and replay

The [summary](summary.json) and [checks](checks.log) record 103 Rust test runs:
98 core tests plus four pair gateway cases and one legacy SDK case. All qualified
runs pass with zero ignored tests or skips. Seven Node suites pass, including
67 pair checks and all 46 existing single-resource Terraform checks. Clippy
passes with warnings denied. Closed draft schemas, frozen legacy files,
credential scanning and documentation links are checked.

```sh
node scripts/verify-terraform-pair-gateway.mjs results/verification/terraform-pair-gateway-2026-11-11
```

The [read-only replay](../../../scripts/verify-terraform-pair-gateway.mjs)
recomputes plan/effect/resource-incarnation and per-member observation digests,
checks backend lineage/serial progress, ordered audit events and native/SDK
correlation. Four positive cases and five altered-evidence negatives cover
changed targets, false committed partials, false lost-reply claims, second
dispatches and reversed audit timing. This is local evidence replay, not a
signature or independent attestation.

[Source hashes](source-hashes.json), the [complete increment](source.patch),
[prior evidence seals](prior-evidence-hashes.json) and [artifact hashes](artifact-hashes.json)
pin the record. Private credentials, saved binary plan, provider binaries and
native temporary ledger data are excluded. Tool/runtime hashes are in the
summary. The owned namespaces and cluster were deleted and the private VM
stopped; see [cleanup](cleanup.log).

## Excluded preliminary attempts

The `preliminary/` records are excluded from qualified totals. A Rust fixture
scope expression first failed to compile; a later build exhausted host space.
The reused disposable VM recorded I/O errors and a read-only filesystem, causing
a cluster read to fail before admission. The VM and its disposable container
data were recreated, and only obsolete task build-cache outputs were removed.
A subsequent fixture lacked `ETCD_ENDPOINT`: its test returned through an
existing skip path, but the outer backend/effect checks failed. The fixture now
requires the explicit native ledger, and the qualified run boots all three
members through `scripts/start-etcd.sh`. No preliminary apply is credited.

## Limits

This is bounded Level C software qualification on macOS/ARM64 with generated
same-host roles and a fixture-administered cluster/audit policy. It establishes
neither target atomicity nor independent administration. Privileged writers and
the Kubernetes control plane remain outside Terraform backend locking.
Production writer/credential custody, Linux service isolation, active Terraform/
provider child termination, broader dependency/provider graphs, remote backends
and independently accepted deployment evidence remain open. Partial/unknown
authority stays held; no automatic repair, retry, release, refund or inverse is
introduced. The complete N2 deployment exit remains open.
