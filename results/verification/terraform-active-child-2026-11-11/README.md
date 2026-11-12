# N2g: active Terraform/provider failure and late effects

Qualification date: 11 November 2026 (America/Los_Angeles; audit timestamps are
12 November UTC). Baseline `bb80b6b`; intermediate implementation `1ef7a12`.
See the [guide](../../../docs/TERRAFORM_ACTIVE_CHILD_QUALIFICATION.md) and
[RFC 0067](../../../docs/rfcs/0067-terraform-active-child-qualification.md).
There is no wire-profile change.

## Observed cases

| Case | Actual intervention and target observation | Native intent | Ordinary SDK state |
| --- | --- | --- | --- |
| provider-kill | SIGKILL sent to live provider while its real PATCH is held; request dropped; target remains original | unknown | unknown |
| terraform-kill | SIGKILL sent to live Terraform with provider/request still active; remaining group stops; request dropped | unknown | unknown |
| deadline-late | Original grant/dispatch expires with both children active; group stops; captured original PATCH forwarded afterward and commits at Kubernetes | started | unknown |
| legacy-sdk | Existing single-resource normal apply commits and cold-queries | applied | committed |
| pair-partial | Ordered pair first succeeds/second denied, then cold-queries without reapply | partial_observed | unknown |

All live cases use shipping gateway/broker binaries, official MCP SDK 2.3.0,
Terraform 1.17.1, Kubernetes provider 2.38.0, fresh Cedar admission/issuance,
a disposable three-member etcd 3.6.5 ledger and an owned audited kind cluster.
The new loopback gate has a separate CA-signed server leaf, a fixed upstream
with pinned Kubernetes CA, no ambient proxy routing and a single allowed owned
ConfigMap mutation. The saved configuration pins the gate endpoint/CA. Planning
and actual target observations use the real Kubernetes API; no shell/no-op
substitute is credited as an infrastructure effect.

At the held request, `/bin/ps` observes the actual gateway → Terraform → provider
parent chain and common process group. The fixture checks current grant
validity, original started intent and unchanged target/backend before sending a
signal or waiting for expiry. After ordinary unknown publication, it observes
no live local group members and a still-live gateway, then releases the gate.
Signal delivery is recorded from the successful OS kill call and before/after
process observations; it does not claim a separately reaped descendant exit code.

The shared runner now stops remaining group members immediately after Terraform
exits, before draining inherited output pipes. The Terraform-kill case recorded
44 ms from signal intervention to ordinary unknown publication on this host;
this is one local observation, not an SLO or general benchmark. A separate
shell/sleep OS-process regression proves an exited tool cannot keep inherited
pipes open. That helper verifies process mechanics only, and is repeated in the
final core suite.

The provider-kill case advanced backend serial from 1 to 3 while the actual
target stayed original. The deadline case retained backend serial 1 and its
original bytes, even though the captured request later changed the real target.
A get-only target read and Kubernetes metadata audit event establish that late
effect. The delayed operation uses the captured **original request**; it is not
another apply or a new credential/dispatch. The test gate is an administered
network fixture, not evidence that every production server behaves this way.

All cases retain one original claim, permit, dispatch and intent. Direct child
failures retain an unknown intent outcome; expiry cancellation retains started
because the runner future was dropped. Both preserve ordinary unknown. Cold
SDK queries follow expiry/revocation with writer removed and broker stopped;
native bytes/counters, backend and target-write audit records remain unchanged.
Current target coincidence does not repair history or release authority.

## Validation and replay

The [summary](summary.json) records **104 final qualification Rust test runs**:
99 core tests and five live cases, with zero qualified failures, ignored tests
or skips. Seven SDK suites pass, including all 46 single-resource and 67 pair
checks. Clippy passes with warnings denied; formatting, Python lint, frozen
SDK/schema compatibility, credential scanning, links and prior evidence seals
are checked. Four invalid fixture-mode selections refuse before any tool starts.

```sh
node scripts/verify-terraform-active.mjs results/verification/terraform-active-child-2026-11-11
```

The [read-only verifier](../../../scripts/verify-terraform-active.mjs) recomputes
manifest/effect bindings, checks original grant/descriptor registration and
correlates process, gate, target, backend and audit observations. Three positive
records and six altered-evidence negatives cover wrong child ancestry, a claimed
live group, pipe-deadline delay, late forwarding before cleanup, promoted unknown
and erased late target effects. This is local software replay, not independent
attestation or a target-side no-effect barrier.

[Source hashes](source-hashes.json), the [complete source increment](source.patch),
[prior evidence pins](prior-evidence-hashes.json), [artifact hashes](artifact-hashes.json)
and [checks](checks.log) seal the record. Private keys/tokens, saved binary plans,
tool binaries and temporary ledger data are excluded. Tool/runtime hashes are
in the summary. Owned namespaces/cluster were deleted and the private VM was
stopped. Only dead private stages matching completed-case configuration hashes
were removed; see [cleanup](cleanup.log) and [stage cleanup](stage-cleanup.json).

## Excluded preliminary checks

Two initial live fixture attempts failed before the active-request checkpoint.
The test gate presented a CA certificate as its server leaf; the protected Rust
observer refused before apply. Planning GETs alone did not qualify an active
provider case. A separate CA-signed non-CA server leaf corrected the fixture,
and all declared checkpoints then passed. Both failures and sanitized request
traces are retained under `preliminary/` and excluded from qualified totals.
A targeted inherited-pipe unit check initially reached its process-inspection
step inside the desktop sandbox, where `/bin/ps` was denied. It passed with OS
inspection permitted and again in the final core cohort. No preliminary effect
or skip is credited. The production cleanup logic was unchanged across the
final live cohort; the unit-only regression was added during that cohort.

## Remaining limits

Generated same-host identities/evidence services and a fixture-administered gate
and audit policy do not establish independent administration. Unix groups do
not contain a compromised provider that escapes them. Gateway SIGKILL while
children are active, Linux service/cgroup isolation, production credential
custody, broader dependency/provider graphs, remote backends and a qualified
target-side late-effect barrier remain open. This remains Level C. No automatic
reapply, compensation, release, refund, force-unlock or outcome repair is added.
The complete N2 deployment exit remains open.
