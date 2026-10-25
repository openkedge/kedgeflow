# Managed drain implementation foundation — 24 October 2026

Baseline: e5cdfc2bdd964d8ce42beca02695f919637eac02. [RFC 0056](../../../docs/rfcs/0056-physical-operating-records.md)
and the [foundation guide](../../../docs/MANAGED_KUBERNETES_DRAIN.md)
distinguish source paths, tests and unfinished integration. **Managed execution
is disabled and unqualified. O2–O4, M8 and the current phase remain incomplete.**

The exact frozen-source run passed **512 Rust tests across 61
unique binaries** (73 executions), **34 Python tests**,
three Node vector suites, formatting, Clippy, Ruff, mypy and frozen paper/schema
checks. Primary/family/Kubernetes batches passed
**26/23/23 actual SQL groups**.
No tests failed, were ignored or skipped. The manifest and exact case/target
population match once; all **585 source files** match the pre-run archive.

Ten new pure tests cover explicit managed enrollment/action/schema separation,
closed fields and role pins, shared query-slot accounting, original deadlines,
owned incident/stop ordering, lost Pending, finite budgets/backoff and final
observation cutoff, stable incident identity, acknowledgement without physical
resolution, complete event links and signed current SQL correlation/freshness.
Their records and clocks are synthetic. They do not demonstrate live native
concurrency, managed physical requests, sink delivery, SQL writer/restore
behavior or any application SLO.

Implemented source paths include the original native dispatch anchor and native
expected-head store; acceptance/Pending/current-SQL and final-send controller
gates; permanent owned incident outbox; durable delivery reservations and a fixed
protected sink client/worker. Current SQL types and client do not supply its
provider or protected storage-head lifecycle. The shipping protected controller
configuration still constructs the legacy controller and refuses managed trust.
Before enablement, the store must also check cumulative material bounds before
new material CAS, preserving stop/outbox availability at exhaustion. Managed
supervisor/configuration, gateway/SDK, complete independent per-CAS managed proofs
and actual managed concurrency/crash/SQL/Kubernetes cases remain
required before enablement or qualification.

The existing complete regression repeats eleven actual Kubernetes cases, each
with a fresh owned fixture and seven RBAC checks; bootstrap adds seven, totaling
84. Eighteen separate offline replay commands verify existing family/physical and
O1 operating artifacts. These are legacy mechanics and historical record
qualification, not a managed physical execution test. Generated private
credentials are not retained. Same-host SQL/etcd/Kubernetes is not independent
custody or workload SLO acceptance.

A native committed drain receipt means acceptance, not physical completion.
Incident acknowledgement cannot resolve an unknown, refund capacity or authorize
SQL inverse. Local protected-clock checks and enrolled send intervals do not
make SQL/Kubernetes atomic or establish a hard real-time physical cutoff.
Independent storage/writers/custody, production maintenance, physical node failure,
accepted SLO and whole-saga/authority-peer/release decisions remain open.

Focused diagnostics include the initial Clippy failures and their repair. Only
the full unchanged-source run describes this final source. Prior committed
results, frozen whitepaper/schema/fixtures and SQL migrations 0001/0002 remain
byte-identical.
