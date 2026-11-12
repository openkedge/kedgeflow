# N2h: gateway SIGKILL, active descendants and retained authority

Qualification date: 11 November 2026, America/Los_Angeles; audit timestamps are
12 November UTC. Baseline `25bfbe7`; intermediate implementation `c567cab`.
See the [guide](../../../docs/TERRAFORM_GATEWAY_DEATH_QUALIFICATION.md) and
[RFC 0068](../../../docs/rfcs/0068-terraform-gateway-death-qualification.md).
This increment changes test fixtures, replay and documentation only. Production
runtime, accepted schemas, SDK and existing fixtures remain unchanged.

## Observed cases

| Case | Intervention and actual target | Native intent / ordinary state |
| --- | --- | --- |
| gateway-kill-drop | Gateway reaped with signal 9 while real PATCH held; both children observed alive; fixture explicitly kills owned group and drops captured request after expiry; target original | started / dispatch_authorized |
| gateway-kill-late | Same gateway death and child survival; captured original PATCH forwarded after expiry and commits at Kubernetes | started / dispatch_authorized |
| deadline-late | Fresh N2g regression: cancellation stops local children; captured request commits afterward | started / unknown |
| legacy-sdk | Fresh single-resource normal apply and cold recovery | applied / committed |

The shipping gateway/broker, official MCP SDK 2.3.0, Terraform 1.17.1, Kubernetes
provider 2.38.0, fresh Cedar admission/issuance and a disposable three-member
etcd 3.6.5 ledger operate against an owned audited kind cluster. The fixed
loopback API gate uses its own CA-signed leaf and pinned upstream Kubernetes CA.
It holds only the one exact owned ConfigMap mutation. No no-op/shell substitute
is credited as an infrastructure change.

At the real held PATCH, the fixture observes live gateway → Terraform → provider
parentage, common group, original started intent, current grant validity and
original target/backend. It kills its gateway child and verifies the reaped exit
signal is 9. Separate OS snapshots then observe Terraform reparented away from
the dead gateway, with its real provider still alive. Zero intent outcomes and
zero ordinary terminal publications occur in either whole-death case.

The drop case's process-group kill is explicit **fixture administration**.
The late case records no such kill: its descendants had ended by the expiry
snapshot, after being observed alive immediately following gateway death.
Both cases therefore record the liveness actually observed, without claiming
that children ran through grant expiry. The gate later forwards the captured
original request in the late case and records a real HTTP 200, target revision/
resourceVersion change and Kubernetes metadata audit event after expiry.
Backend serial stayed 1 in both whole-death cases. These are controlled local
network/process observations, not guarantees about every production provider.

The dead gateway cannot run Rust Drop handlers or publish an outcome. Its
first SDK process reports unavailable; that transport result does not replace
the native retained phase. Cold shipping gateway/SDK queries after revocation,
expiry, broker shutdown and writer removal return original `dispatch_authorized`.
Exactly one original claim, permit, dispatch and intent remain; no additional
admission, issuance, granted tool call or apply is made. Intent bytes, backend,
counters and target-write audit events remain unchanged during repeated queries.
Desired target coincidence cannot promote or release that original authority.

## Checks and replay

The [summary](summary.json) records **103 final Rust test runs**: 99 core, two
whole-death and two fresh compatibility cases, with zero qualified failures,
ignored tests or skips. Seven SDK suites pass, including all 46 single-resource
and 67 pair checks. Clippy passes with warnings denied. Formatting, Python lint,
frozen runtime/SDK/spec/fixture comparisons, schema validation, credential scans,
links and prior sealed evidence are checked. Four invalid new fixture selections
refuse before tool startup.

```sh
node scripts/verify-terraform-gateway-death.mjs results/verification/terraform-gateway-death-2026-11-11
```

The [read-only verifier](../../../scripts/verify-terraform-gateway-death.mjs)
recomputes plan/manifest effects and validates original descriptor/grant pins,
reaped gateway signal, surviving child ancestry, request timing, target/backend,
audit correlation and unchanged native/SDK history. Two positive records and
six altered negatives cover a false exit signal, missing surviving provider,
false terminal publication, promoted phase, forwarding before expiry and erased
late target effects. This is local software replay, not independent attestation,
a no-effect barrier or production descendant containment.

[Source hashes](source-hashes.json), the [complete increment](source.patch),
[prior evidence pins](prior-evidence-hashes.json), [artifact hashes](artifact-hashes.json)
and [checks](checks.log) seal the record. Private keys/tokens, saved binary plans,
tool binaries and temporary ledger data are excluded; tool/runtime hashes are
in the summary. Owned namespaces/cluster were deleted, the private VM stopped,
and only dead stages matching completed-case configuration hashes removed. See
[cleanup](cleanup.log) and [stage cleanup](stage-cleanup.json).

One preliminary Rust fixture build compared a JSON value with a borrowed String
and failed to compile. The type error was corrected before any live case. That
log is retained under `preliminary/` and excluded from qualified totals. All
live cases passed in the final cohort.

## Remaining gates

A Unix process group does not bind children to the lifetime of a SIGKILLed
parent. Their later exit is not an authoritative late-effect barrier. Linux
cgroup/service containment, malicious provider group escape, production
credential custody, remote backends, broader graphs and independent deployment
acceptance remain open. The identity/evidence roles, gate and audit policy are
fixture-administered on the same host. This remains Level C, with no automatic
repair, retry, release, refund, force-unlock or inverse. Complete N2 deployment
acceptance remains open.
