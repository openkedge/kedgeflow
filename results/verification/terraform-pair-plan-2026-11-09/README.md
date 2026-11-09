# N2f1 two-resource Terraform inspection — 9 November 2026

The protected `kf-terraform-pair-plan` CLI now derives a separate read-only
candidate report for exactly two ordered ConfigMap annotation updates. See
[the guide](../../../docs/TERRAFORM_PAIR_PLAN.md),
[RFC 0064](../../../docs/rfcs/0064-terraform-pair-plan.md) and
[the draft schema](../../../spec/drafts/terraform-pair-plan-v0.1.schema.json).
Baseline `3eaf1bb` plus [source.patch](source.patch) and
[source-hashes.json](source-hashes.json) pin this increment.

## Fresh observations

[The final two-resource case](cases/pair/steps.json) uses actual Terraform 1.17.1
and Kubernetes provider 2.38.0, a fresh owned namespace and a get-only planner.
It imports two existing ConfigMaps into one local backend and saves one real
plan with two annotation updates. Both protected configuration and embedded
binary-derived configuration declare second depends on first. The candidate
report retains both target incarnations, per-member effects, a separate
aggregate effect digest, shared lineage/serial, complete inspection hash and
input hashes. It reports Level C and execution_enabled:false.

The fixture certifies that the planner cannot patch ConfigMaps, that its
environment token does not occur in any saved-plan ZIP member, and that the
report contains no provider credential or CA contents. Independently read
[before/after targets](cases/pair/target-observation.json) are exactly unchanged,
including UIDs/resourceVersions and all fields. Swapped binary plan and pinned
provider hook substitutions refuse. Ambient Terraform options are ignored,
`--apply` is rejected, and the original single-resource inspector refuses the
pair profile. The fixture cannot combine pair inspection with execution.

[Single-resource read-only inspection](cases/single-readonly/steps.json) and
[the normal official-SDK gateway apply/cold-query case](cases/normal-sdk/execution-diagnostic.log)
also pass against this source. Existing SDK runtime, apply action and gateway
wire profiles are unchanged. The latter uses fresh native Cedar admission,
issuance, claim, broker permit and dispatch, followed by one real target effect
and original-attempt query after expiry/revocation with broker/writer absent.

[Required Rust checks](regressions.log) pass: 18 library, 20 admission, 6
configuration, 11 contracts, 5 custody, 13 gateway, 12 single-plan and 7 new
pair-plan tests. Along with the live SDK case, this is **93 qualified Rust test
runs**, with no failures, ignores or skips. The seven new tests cover exact
member views, overlap/order/profile refusal, per-effect limits and unknowns,
dependency/provider/global-input closure, aggregate binding of the second
effect, and protected pre-spawn custody/hook/input checks.

[Six SDK vector suites](node-vectors.log), including the existing 46 Terraform
checks, and [Clippy with warnings denied](clippy.log) pass. Formatting, Ruff,
draft schemas, structural negatives, source/artifact pins, documentation links
and credential scans are recorded in [checks.log](checks.log).

## Provenance and reproduction

[The driver](qualification-driver.py) records the final paired and original
compatibility cases and required native three-member loopback etcd checks.
The retained final paired case additionally confirms the lint-clean iterator
implementation with a fresh plan; [confirmation.log](confirmation.log) records
its command result. The initial discovery case supplied the separately retained
semantic fixture under `fixtures/terraform-pair-plan`. That fixture is input for
semantic unit tests; executable plans and credentials are not distributed.

One preliminary negative unit test assumed an absent metadata array existed,
and failed during test construction. [Its log](preliminary/unit-fixture.log)
is retained and excluded from the final population; the corrected test creates
the intended unknown-UID value explicitly. This changed the test, not a runtime
effect guard. The final seven tests all pass.

Previous backend evidence is unmodified and pinned separately in
[prior-backend-evidence-hashes.json](prior-backend-evidence-hashes.json).
[summary.json](summary.json) records versions, tool/binary hashes and population.
Use fresh output directories and adjust explicit owned kind/private kubeconfig
paths when reproducing. The planning fixture passes `--pair-inspector` alongside
the original `--inspector`; it never mints a writer token or invokes apply.

## Open gates and cleanup

This is candidate inspection only. There is no pair execution registration,
admission/grant binding, apply path, partial-effect verdict or compensation.
Declared planning dependency order has not been qualified as physical execution
order. N2f2 must demonstrate an independently observed first effect followed by
a later failure, retain per-effect and partial/unknown aggregate history and
recover without reapply under separately admitted authority.

Same-host generated identities/evidence/policy/relay roles do not qualify
independent administration, Linux credential custody, active-child termination,
HCP/remote backends or target-atomic invariants. Full N2 remains open.
[Cleanup](cleanup.log) confirms ownership-checked namespace removal, deletion
of only cluster `kf8-tfp20261109` and shutdown of only private VM `tf9`.
Other user contexts/profiles are untouched.
