# Governed Kubernetes drain — 23 October 2026

Baseline: 9e11fa7325744c723df40d2685097ee9995175bb. [RFC 0055](../../../docs/rfcs/0055-governed-kubernetes-drain.md)
and the [implementation boundary](../../../docs/KUBERNETES_DRAIN.md) describe
bounded M8e1: native Level C controller acceptance, original Pending journal,
independent physical observation and complete family aggregate replay.

The exact frozen-source run passed **480 Rust tests across 57
unique binaries** (59 executions across three required batches),
**34 Python tests**, three Node vector suites, formatting, Clippy,
Ruff, mypy, frozen paper/schema checks, and **26/23/23 actual SQL
storage/peer/restore groups** in the primary/family/Kubernetes batches.
Runtime failures, ignored and skipped tests: zero. The target/case manifest
matches the combined executed population exactly once, including zero-test
binaries. All **561 source files** remained unchanged from the pre-run
archive through finalization. Source/evidence hashes and source.zip pin the
tested implementation.

## Actual bounded paths

- A real SQL reservation must commit before the physical child can receive
  native authority. Actual native grant/claim, one-shot broker permit and
  original dispatch precede controller acceptance. Acceptance alone stays
  unresolved in the family aggregate.
- The actual least-privilege controller sends JSON Patch cordon (200), an
  original policy/v1 eviction rejected by the PDB (429), then another freshly
  authorized eviction after fixture availability recovers (201). These are
  three controller mutation requests; API reads and administrator fixture
  readiness/cleanup are separate. No direct delete or force fallback exists.
  Independent normalized observations verify our cordon and original pod absence,
  protected workload availability and remaining Ready nodes. This irreversible
  completion blocks SQL compensation and keeps original 2 forward/1 compensation
  costs held.
- Before any Pending mutation, permanent quiesce defeats advance. Positive
  accepted-with-no-effect closure permits a fresh independently admitted original
  SQL inverse with real barrier/applicability and target restore. Actual row
  version 243/free is asserted; the complete aggregate reports compensated and
  still holds both original costs. There is no physical inverse.
- Seven actual service-account RBAC cases pass: allowed fixed reads and dry-run
  target patch, plus five mutation/scope/secret refusals. The observer credential
  cannot patch or evict; the controller cannot patch another node, delete a pod
  directly or read secrets.
- Re-signed physical omission/current-epoch substitution, altered controller
  journal, malformed historical completion epoch and contradictory closed
  absence evidence refuse. Six separate shipping offline CLI processes replay
  serialized completed/unknown/failed/SDK and both physical aggregates. An
  additional separate CLI refuses the exact re-signed malformed historical epoch
  while the original current bytes pass.

## Retained interruptions and limits

The [first interrupted record](../rfc-m8-governed-kubernetes-drain-2026-10-23/README.md)
preserves the exact pre-repair source and an offline diagnostic that accepted a
malformed historical epoch. The source was preserved before repair; final source
adds strict historical epoch and contradictory absence checks with signed
regressions. The [second partial record](../rfc-m8-governed-kubernetes-drain-2026-10-23-interrupted-2/README.md)
preserves an externally interrupted overnight run of the repaired source. Its
handle/processes were confirmed absent before retry. Neither is a conformance
pass. The [failed fixture record](../rfc-m8-governed-kubernetes-drain-2026-10-23-budget-fixture-failure/README.md)
preserves the required runtime failures caused by a shared helper reducing the
legacy two-leaf compensation enrollment. Final source restores the original
default capacity; native production conservation remains unchanged.
Focused diagnostic gzip files preserve original-byte hashes; only the
required complete run qualifies final source.

The three Kubernetes nodes share one local VM. Pause pods and administrator
readiness gates establish fixture mechanics, not an application SLO or physical
node-failure behavior. Native/controller/observer roles are co-located Rust
tasks; generated signers and actual distinct Kubernetes service accounts do not
establish independent administrator custody. The host performs native orchestration;
shipping controller CLI/gateway/SDK drain execution is unqualified. Normalized
signed observations are historical intervals, not atomic cross-resource snapshots
or consensus proofs, and aggregates convey no current execution authority.

M8e2 shipping process/SDK, actual API reply loss, Pending SIGKILL/restart,
late acceptance versus absent closure, paused final-CAS stop races, recreated UID,
deferred expiry and broader physical evidence qualification remain open. M8e3
independently administered writers/custody, production maintenance, physical
failure and accepted SLO evidence remain external gates. Wider whole-saga,
authority-peer and release acceptance also remain open. **M8 is incomplete.**
