# M8c4 shared family authority — 17 October 2026

Baseline: 5d321ff. [RFC 0052](../../../docs/rfcs/0052-family-authority.md)
and the [operator guide](../../../docs/FAMILY_AUTHORITY.md) add protected shared
capacity, signed live narrowed delegation and mandatory native child checks.

The final complete required run passed **451 Rust tests across 53 binaries**,
**26 SQL storage/peer/restore groups**, **32 Python tests**, both Node suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No failures,
ignored tests or required-mode skips occurred. All **515 source files** remained
unchanged throughout and after this final run. Shipping commands now number
23; the new command is kf-family. Summary, tool/command/log hashes, observation
records and final-source.json pin the exact tested implementation and evidence.
Frozen fixtures/schema/paper, both SQL migrations and earlier committed results
remain unchanged. No source repair occurred during or after the final run.

## Native qualification

Ten new native cases cover:

- Two distinct independently admitted child contracts under one signed delegated
  family branch; original claims/dispatch, stopped fresh authority, retained
  unknown consumption and whole-child holding in both allowance dimensions.
- Last-slot competing attachment, including refreshed-head refusal when there is
  no remaining capacity; exact replay cannot allocate again.
- Nested owner/principal/scope/cost/lifetime narrowing, signature/owner rejection,
  stopped replacement, corrupt/missing state, wrong family/context and legacy
  enrollment refusal. Registration binds the exact namespace: old commands and
  selected registrations cannot replay into another prefix.
- Real etcd relay races root stop against native fence allocation, issuance,
  claim and dispatch. The final authority CAS refuses in each window.
- History exhaustion reserves the final slot for permanent root stop while every
  allowance stays held. Separate-observer replay rejects omissions and semantic
  tampering, including newly signed invalid checkpoints.
- Paired topology is installed atomically with family genesis. Inverse lane
  pinning alone cannot execute; separate fresh compound authority still applies.
  Original inverse recovery after family stop refines the same held spend;
  outcome/delegation key collisions refuse.
- Shipping CLI mTLS enrollment, apply/exact replay, status, observer export and
  offline verification; no remote I/O is needed for offline verification.

The native family proofs attest delegation/allocation history, not aggregate
cross-contract execution or target effects. Child native lineage remains
separately required. Tests use generated identities, one host, fixture providers
and actual disposable etcd/PostgreSQL. No production key/storage custody or
complete writer/predicate boundary is established.

## Preliminary run and timing

The [preliminary record](../rfc-m8-family-preliminary-2026-10-16/README.md) retains
the exact original source archive and failed full-run logs. Its two existing SQL
cases failed across host sleep intervals; subsequent focused retries passed.
Another unrecorded focused development population hit a guard rejection across
further sleep, and that isolated restore case passed on retry. Security windows
were not extended. The final run used process-scoped idle-sleep inhibition.

A [second preliminary record](../rfc-m8-family-transport-preliminary-2026-10-16/README.md)
retains a complete run through all 190 governance cases and the later synthetic
transport response failure. The fixture now emits a range response for every
requested range while preserving its independent etcd token assertions; the
production missing-response guard remains unchanged.

A [third preliminary record](../rfc-m8-family-power-preliminary-2026-10-16/README.md)
retains three SQL inverse recovery failures during another confirmed clamshell
sleep interval. Process-scoped idle-sleep inhibition cannot prevent lid closure.
The final complete run was restarted on the same unchanged source; no production
deadlines were extended and no source repairs were made for that run.

A [fourth preliminary record](../rfc-m8-family-suspension-preliminary-2026-10-17/README.md)
retains six SQL recovery failures during further confirmed clamshell sleep
intervals. It remains failed evidence; the complete final run again uses the
same unchanged source. No production deadlines were extended.

A [fifth preliminary record](../rfc-m8-family-runtime-preliminary-2026-10-17/README.md)
retains static checks followed by failure before native tests: temporary
PostgreSQL support files were missing. The pinned 18.3 runtime was restored
from its verified official source archive before the final qualification.

Before this final freeze, the implementation additionally bound family namespace
into signed registration digests and refused cross-prefix selection/replay. It
also combined legacy family-absence observation with the existing restore-marker
read, removing unnecessary network round trips while retaining final absence CAS.
No production validity, retry, SQL guard, budget or recovery condition was relaxed.

## Remaining M8 work

M8 remains incomplete: core/independent A2A task peers, multi-contract real-SQL
inverse runner and aggregate execution evidence, broader failure composition,
independent whole-saga acceptance, physical SQL restore/cutover and the separate
actual Level C Kubernetes drain remain open. The user has no supplied disposable
cluster. A local isolated cluster is being evaluated; no existing environment was
used or changed by this qualification. No cross-cluster atomicity, refund,
automatic compensation/resume or enterprise acceptance is claimed.
