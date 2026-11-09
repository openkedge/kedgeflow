# N2d Terraform failure boundaries — 9 November 2026

Six certified failure/state-change cases extend the existing local Level C
gateway. Production Rust/SDK source and wire profiles are unchanged. The
[guide](../../../docs/TERRAFORM_FAILURE_QUALIFICATION.md) and
[RFC 0062](../../../docs/rfcs/0062-terraform-failure-qualification.md) define the
scope. Baseline `4163a41` plus [source.patch](source.patch) and
[source-hashes.json](source-hashes.json) pin the final fixtures/documentation.

## Qualified population

| Case | Target | Intent | Ordinary native status |
| --- | --- | --- | --- |
| [SIGKILL after durable intent, before reply](cases/after-intent/execution-diagnostic.log) | Unchanged | started | dispatch_authorized |
| [SIGKILL after effect, before intent outcome](cases/after-effect/execution-diagnostic.log) | Desired annotation; backend advances | started | dispatch_authorized |
| [SIGKILL before ordinary publication](cases/before-publication/execution-diagnostic.log) | Desired annotation; backend advances | applied | dispatch_authorized |
| [Revocation at intent CAS](cases/revocation/execution-diagnostic.log) | Unchanged | absent | unknown |
| [External target drift before runner checks](cases/target-drift/execution-diagnostic.log) | Certified external annotation | absent | unknown |
| [SIGSTOP/SIGCONT across expiry](cases/suspension/execution-diagnostic.log) | Unchanged | absent | not_dispatched |

Every case starts with a fresh real saved plan and current Cedar admission,
native issuance, claim, broker permit and dispatch authorization. It uses actual
`kf-proxy`/`kf-broker` processes, official MCP SDK 2.3.0, three-member loopback
etcd, Terraform 1.17.1/provider 2.38.0 and the owned kind target. An authenticated
fixture relay counts only successful native writes and gates the declared
request/reply boundary. Independent target/backend observations and signed-grant
validity checks precede intervention. SIGKILL exit signal 9 and stopped OS process
state are verified; SIGCONT occurs after the original grant expires.

Each `checkpoint-observation.json` and `sdk-native-report.json` retains original
phase, intent, counters and intervention evidence. Request commit/forwarding state
is recorded before client cancellation can discard a reply. Revocation must cause
the held native CAS to fail. Target injection changes the actual annotation and
resourceVersion while preserving UID/data/labels; the independent final oracle
expects that external value, not the planned effect.

Cold gateway/SDK restart occurs after expiry and domain revocation with broker
stopped and writer absent. Every cold query and repeated SDK execute retains the
same grant/attempt, backend bytes, intent and execution/outcome counters. The
three crashes preserve nonterminal `dispatch_authorized`; even matching target
state or applied intent does not promote ordinary status. The suspension's first
SDK callback is unavailable because its five-second TLS transport times out;
native publication is observed separately and cold status is not_dispatched.

[Compatibility regressions](regressions.log): **67 pass** (admission 20,
configuration 6, contracts 11, custody 5, gateway 13, Terraform 12). One normal
Terraform SDK apply/cold-query case and one existing lost-reply SDK case pass.
Together with six new cases, the qualified population is **75 Rust test runs**,
with no failures, ignored cases or skips. [Six SDK vector suites](node-vectors.log)
also pass, including the existing 46 Terraform checks. [Clippy](clippy.log) passes
with warnings denied. [Checks](checks.log) cover formatting, Ruff, schemas,
source/artifact pins, protocol compatibility and documentation links.

## Reproduction and provenance

Use fresh output/capsule per case. The [driver](qualification-driver.py) lists
the six exact tests and arguments; the [completion driver](completion-driver.py)
records the final suspension-specific availability check and compatibility runs.
Normal fault cases use `scripts/test-terraform-plan.py --execution-command cargo
test ...`. Select `--expect-effect` for the two post-effect crashes. For external
drift use `--expect-external-revision external`, mutually exclusive with
`--expect-effect`. No caller can use this fixture option to select a production
target or mutation. Paths and owned kind context must be adjusted locally.

The first five cases use the final3 cohort; suspension uses the completion cohort.
The latter changes only suspension's immediate SDK availability handling and
waits read-only for existing native publication. Production binaries are the
same. Source/tool hashes, versions and populations are in [summary.json](summary.json).
Previous gateway evidence is retained unchanged and separately pinned.

Preliminary failed experiments remain under `preliminary/` and are excluded from
the qualified counts: a relay proof field was initially written after cancellable
reply delivery; a 15-second startup wait was below the permitted bounded local
inspection startup; and suspension initially conflated immediate SDK availability
with retained native status. The final fixture records commit state early, allows
45 seconds for startup without extending execution/grant deadlines, and checks
native history independently. These were fixture assumptions, not evidence of
completed runtime repair.

## Limits and cleanup

These are generated same-host Darwin ARM64 identity/evidence/policy/relay roles,
not independent administration, production etcd RBAC or Linux service custody.
The crashes occur before apply starts or after the Terraform child completes.
Active-child termination, systemd/cgroups, multi-resource partial apply, arbitrary
post-check target/dependency races, HCP and automatic publication/unknown repair
remain open. This record adds no target-atomic or production-readiness claim.

Public evidence has no credentials or raw executable plan. Namespace UID/label
checks precede cleanup. [cleanup.log](cleanup.log) confirms removal of owned
namespaces/cluster and shutdown of only VM tf9; other user profiles and contexts
are untouched.
