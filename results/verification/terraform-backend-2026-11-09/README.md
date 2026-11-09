# N2e Terraform backend boundaries — 9 November 2026

This record qualifies four local-backend refusal cases through the existing
Level C saved-plan gateway. See the
[guide](../../../docs/TERRAFORM_BACKEND_QUALIFICATION.md) and
[RFC 0063](../../../docs/rfcs/0063-terraform-backend-qualification.md).
Baseline `2eed498` plus [source.patch](source.patch) and
[source-hashes.json](source-hashes.json) pin this increment. No wire/profile,
SDK runtime, apply command, lock timeout or authority deadline changes.

| Case | Certified intervention | Intent | Ordinary status |
| --- | --- | --- | --- |
| [Lock contention](cases/lock/execution-diagnostic.log) | Exclusive OS lock on the live backend after durable intent; second descriptor refuses; held through native refusal | unknown | unknown |
| [Pre-check drift](cases/precheck/execution-diagnostic.log) | Live state serial advances before runner state check; target unchanged | absent | unknown |
| [Stale saved plan](cases/serial/execution-diagnostic.log) | Live state serial advances after durable intent | unknown | unknown |
| [Changed lineage](cases/lineage/execution-diagnostic.log) | Live state lineage changes after durable intent | unknown | unknown |

All four use fresh actual Terraform 1.17.1/provider 2.38.0 saved plans, owned kind
targets, current Cedar admission/issuance, shipping gateway/broker, three-member
loopback etcd 3.6.5 and official MCP SDK 2.3.0. The authenticated fixture relay
holds an existing native reply. It certifies original grant validity, exact
target UID/resourceVersion/content and backend hash/lineage/serial before the
intervention. Every target remains byte-equivalent as a JSON value afterward.
The plan capsule is immutable. Serial/lineage injection edits live state metadata
only; it is not a second successful Terraform execution.

Each backend case retains `backend-completion.json`, proving that grant expiry
did not mask the refusal and that Terraform did not change the injected backend
bytes. For locking, it additionally certifies contention through refusal and
lock availability after holder release. `sdk-native-report.json` retains the
exact fixed Terraform refusal diagnostic for the three post-intent cases.
Raw tool stderr, state paths and credentials are not copied into intent errors.
Unknown/ambiguous diagnostic text has a generic fallback and does not authorize
another apply.
An independent Python replay reconstructs each injected backend byte sequence
from the archived original state by changing only its declared metadata field.
`backend-replay.json` requires that reconstructed hash to match both the
injection and the actual post-refusal observation.
The standalone [verifier](../../../scripts/verify-terraform-backend.py) also
rejects altered state bytes, a cold recovery execution call and promotion of an
unknown intent. [verifier-tests.json](verifier-tests.json) retains the four real
positive replays and three deliberate negative checks.

All cold gateway/SDK queries happen after original grant expiry and domain
revocation, with broker stopped and writer credential absent. The original
grant/attempt, intent, backend bytes and native execution/outcome counters remain
unchanged. Every case has exactly one claim, permit and dispatch; pre-check drift
has zero intents, while each other case has one started intent followed by one
unknown outcome. Repeated SDK execute is query-only, including after lock release.
There is no force-unlock, disabled locking, automatic replan or second apply.

## Fresh compatibility population

The [driver](qualification-driver.py) runs all four backend cases, a normal real
saved-plan apply, the six existing N2d fault cases and an existing generic SDK
lost-reply case against this source. [Core/library regressions](regressions.log)
cover 18 library tests (including diagnostic non-disclosure), admission 20,
configuration 6, contracts 11, custody 5, gateway 13 and Terraform 12: 85 tests.
Together these are **97 fresh Rust test runs**, with zero failures, ignored
cases or skips. [Six SDK vector suites](node-vectors.log), including the existing
46 Terraform checks, and [Clippy with warnings denied](clippy.log) also pass.
Formatting, 22 real schema records, pins, documentation links and credential
scans are recorded in [checks.log](checks.log).

This bundle separately retains the six freshly executed crash/state-change cases
under `cases/`. Their original archived evidence is untouched and pinned by
[prior-failure-evidence-hashes.json](prior-failure-evidence-hashes.json).
[summary.json](summary.json) records tool/source/binary pins and case population.
The driver uses explicit owned kind context and private kubeconfig paths, which
must be adjusted for reproduction. Each run needs a fresh capsule/output and
the pinned tools, official SDK dependencies and required native etcd harness.

One preliminary lineage case safely retained unknown but failed its diagnostic
assertion: the initial matcher expected “does not apply” instead of the pinned
tool's “does not match” title. Its failed diagnostic/steps remain under
`preliminary/lineage-diagnostic/` and are excluded from the qualified count.
The preliminary driver log also retains its three preceding successful cases;
none of that earlier cohort is counted in the final population.
The final cohort reruns every case after correcting the fixed marker. This
correction adds diagnostic specificity, not a new execution or recovery path.

## Limits and cleanup

Generated same-host identities, evidence, relay and allow policy do not establish
independent administration or production credential custody. Measured platform
is Darwin ARM64, not Linux/systemd. Metadata injection is controlled state-file
editing, not concurrent successful applies. State locking does not guard all
target/dependency writers or make the adapter target-atomic.

Active Terraform/provider child termination, multi-resource partial apply,
HCP/remote backends, automatic unknown/publication repair and independent
deployment acceptance remain open. Full N2 remains incomplete.
[cleanup.log](cleanup.log) records ownership-checked namespace removal, deletion
of only cluster `kf8-tfb20261109` and shutdown of only VM `tf9`. Other user
contexts/profiles are untouched. Public artifacts contain no raw signed tokens,
private keys or executable plan.
