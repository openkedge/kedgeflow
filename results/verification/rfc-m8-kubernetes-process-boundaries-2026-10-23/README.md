# Kubernetes controller process boundaries — 23 October 2026

Baseline: e6b8fbde480d552794ec3cd8ef4630882b22ca48. [RFC 0055](../../../docs/rfcs/0055-governed-kubernetes-drain.md)
and the [implementation boundary](../../../docs/KUBERNETES_DRAIN.md) describe the
bounded M8e2a qualification. This extends the immutable M8e1 implementation;
it does not complete M8 or the current development phase.

The exact frozen-source run passed **487 Rust tests across 57
unique binaries** (67 executions), **34 Python tests**,
three Node vector suites, formatting, Clippy, Ruff, mypy and frozen paper/schema
checks. The primary/family/Kubernetes batches passed
**26/23/23 actual SQL groups**.
Zero tests failed, were ignored or skipped. The required case/target population
matches exactly once. All **564 source files** match the pre-run archive
through finalization.

Nine real-cluster Rust cases each receive a fresh owned namespace, workload and
least-privilege mutator/observer accounts. Each repeats seven actual RBAC checks;
bootstrap adds seven more. Conformance validates the complete case index and
public contract/fixture/RBAC hashes. No SA token, private key or kubeconfig is
published. Twelve separate shipping offline CLI invocations replay the retained
serialized aggregates.

The shipping controller is killed after real etcd durably stores Pending and
before the CAS success reply. Restart after root stop retains the original
Pending/unknown operation. The separate API transport fault forwards exactly one
real cordon (actual API 200), withholds its reply beyond the unchanged five-second
client timeout, and counts zero further mutations after restart. Native committed
is controller acceptance; physical work stays unknown and both costs remain held.
The Pending-only case does not instrument API wire counts or use current absence
as a no-effect proof.

Permanent quiesce and root stop each defeat a paused original final Pending CAS.
Shipping CLI closure proves zero-step accepted-with-no-effect. A distinct paused
acceptance loses to positive closed absence: its real CAS fails, actual target
query 404 remains native unknown, and separately verified physical no-dispatch
permits fresh original SQL inverse admission and actual row version 243/free.
A narrowed one-millisecond protected deferred enrollment refuses its first
mutation without changing production windows. Actual policy/v1 eviction refuses
stale resourceVersion and recreated UID with 409, leaving the replacement
undeleted. Those last probes qualify target preconditions, not a controller retry
or no-effect proof for the original request.

The three Kubernetes nodes share one local VM. Fixture readiness is not an
application SLO. Generated identities and co-located administrators do not
establish independent custody. Native grant/broker/SQL/owner orchestration remains
host fixture code. Gateway/official SDK physical execution, selected generic
recovery query integration, a protected Level C ownership/incident record,
current SQL reservation/fence evidence under a declared writer/storage boundary,
wider evidence attacks and independently administered physical/enterprise
acceptance remain open. Historical native SQL commit does not prove current SQL
state against external writers or restored storage. **M8 is incomplete.**

The [preserved lint failure](../rfc-m8-kubernetes-process-boundaries-2026-10-23-lint-failure/README.md)
pins the pre-repair source and logs. Ruff had scanned an older immutable evidence
finalizer as active source; lint configuration now excludes verification archives.
This is an explicit archive/source boundary, not a modification of old evidence.
Development diagnostics include failed and repaired focused attempts. They do
not qualify final source; only the complete frozen-source run does. Prior
committed verification records remain byte-identical.
