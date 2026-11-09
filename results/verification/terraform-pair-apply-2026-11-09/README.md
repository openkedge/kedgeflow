# N2f2 native Terraform pair apply — 9 November 2026

The separately admitted two-resource action now executes through the shipping
native CLI and retains per-member partial observations. See
[the guide](../../../docs/TERRAFORM_PAIR_APPLY.md),
[RFC 0065](../../../docs/rfcs/0065-terraform-pair-original-apply.md) and
[the draft schema](../../../spec/drafts/terraform-pair-apply-v0.1.schema.json).
Baseline `994218b`, intermediate commits `6604572` (contract) and `61a2c80`
(runner), plus [source.patch](source.patch) and [source pins](source-hashes.json)
describe the complete increment.

| Fresh case | Actual targets | Retained intent | Ordinary native state |
| --- | --- | --- | --- |
| [Normal](cases/normal/execution-diagnostic.log) | first after, second after | applied | committed |
| [Partial](cases/partial/execution-diagnostic.log) | first after, second before | partial_observed | unknown |
| [Partial with actual reply withheld](cases/partial-lost/execution-diagnostic.log) | first after, second before | partial_observed | unknown |

Each uses a fresh real saved plan, separate compound descriptor/proposal/Cedar
admission/issuance, one original claim, broker permit and dispatch, authenticated
native etcd, protected CLI and actual kind targets. One permanent per-plan CAS
intent precedes backing writer access. The inspected plan is restricted to the
two declared annotations; the approved provider remains trusted code. This is Level C; generic gateway
configuration/discovery/redemption refuses the pair action.

Kubernetes metadata audit records show the first successful write completing
before the second request starts. The second receives a real 403 in partial
cases. Separate get-only target reads and filesystem backend observations are
retained. The failed resource's Terraform state can already contain its desired
annotation while the actual Kubernetes object retains the original value.
Target observations, not that provider state, determine the retained member
observations. Original observed state is not an authoritative no-effect barrier.

After partial failure, the fixture restores the second write permission and
confirms it through authorization, then repeats the original request. It also
refuses another broker permit, replacement claim and conflicting effect.
Fresh CLI processes query after original expiry/domain revocation with writer
absent and broker unavailable. Intent/history, backend bytes, all six native
write counts and target-write audit events remain unchanged. Each count is one:
claim, permit, dispatch, started intent, retained intent outcome, ordinary outcome.
The partial allowance stays held; there is no reapply, refund or automatic inverse.

The lost-reply case closes stdout before spawning the first CLI and checks that
zero response bytes are received. The ordinary native status is recovered from
retained history. A test-only `output()` recapture assumption was corrected to
explicit spawn/wait; the old native CLI lost-reply fixture was corrected too.
Archived earlier records are unchanged and are not retroactively requalified.

## Verification population

[Core/library checks](regressions.log) pass: library 19, admission 20, config 6,
contracts 11, custody 5, gateway 13, pair plan 7, pair apply 3, single plan 12:
96 checks. Three fresh pair cases and existing
[native single CLI](cases/legacy-cli/execution-diagnostic.log) /
[official SDK gateway](cases/legacy-sdk/execution-diagnostic.log) cases bring the
qualified population to **101 Rust test runs**, with no failures, ignores or
skips. [Six SDK vector suites](node-vectors.log), including the existing 46
Terraform checks, and [Clippy](clippy.log) pass.

The [read-only Node verifier](../../../scripts/verify-terraform-pair.mjs)
independently recomputes manifest, both member effects, aggregate effect and
actual target observation digests; checks allowed target changes, backend
progress, immutable cold history, audit identity/status/order at nanosecond
precision, and unchanged post-query write events. [Verifier tests](verifier-tests.json)
pass all three real records and reject altered audit order/correlation, target
observations, promotion of partial to committed, and a false lost-reply claim.
This is consistency replay, not independent attestation or execution authority.

[Checks](checks.log) retain formatting, Ruff, schemas, compatibility, credential
scans, source/artifact pins and documentation links. Existing single-resource
wire shapes remain unchanged, including rejection of a pair field even when null.
Pair retained observations are cross-checked against the original baseline and
their aggregate digest. Pair scope requires the exact logical resource and the
initial simple dispatch-bound grant shape.

## Reproduction and provenance

[The main driver](qualification-driver.py) records the complete live and core
population. [The completion driver](completion-driver.py) confirms the final
three pair cases and 96 core checks; original CLI/SDK compatibility cases come
from the prior full passing cohort. Later changes tighten pair-only validation
and add observations, preserving the single-resource path.
[Environment setup](environment-driver.py), audit policy and kind configuration
are included. The public metadata-only policy must exist inside the private
Docker VM; the driver provisions an explicit task-owned VM path. Adjust local
paths/profile/output names and use fresh outputs when reproducing.

Preliminary logs are retained under `preliminary/` and excluded from qualified
counts: a fixture treated the new named action's fence as a legacy string;
stdout recapture invalidated an initial lost-reply assertion; a parent oracle
incorrectly assumed the failed resource's provider state remained original; and
an additional read-only inspection stopped before admission while disk capacity
was tight. Its first failure had no retained diagnostic; confirmation after
removing two obsolete task binaries passed. No execution deadlines were extended.
The audit server initially failed because a workstation file path appeared as a
directory in the VM; explicit VM policy provisioning corrected setup.

[Previous pair-inspection evidence](prior-pair-plan-evidence-hashes.json) is
retained unchanged. [Summary](summary.json) records source, runtime/tool versions,
hashes and populations. Public outputs contain no raw signed grants, private
keys, backing tokens or executable plans.

## Limits and cleanup

These are generated same-host roles and a fixture-administered cluster/ledger,
not independent custody, production etcd RBAC or portable signed outcomes.
There is no pair gateway/SDK integration, automatic unknown repair, authority
reopening or compensation. Linux service isolation, active-child termination,
broader dependency/provider graphs, HCP and target-atomic safety remain open.
Full N2 deployment acceptance is incomplete.

[Cleanup](cleanup.log) confirms ownership-checked namespaces, deletion of only
cluster `kf8-tfpa20261109`, reclamation of already-free private VM blocks and
shutdown of only `tf9`. Other user profiles, contexts and unrelated work remain
untouched. Source controls and claims are scoped to the archived evidence.
