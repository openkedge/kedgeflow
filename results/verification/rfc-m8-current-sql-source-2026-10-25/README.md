# Current SQL source implementation — 25 October 2026

Baseline: 8e6df78a2ecb0b61c7a9a73e6f254dae612c8f99. [RFC0056](../../../docs/rfcs/0056-physical-operating-records.md)
and the [managed source guide](../../../docs/MANAGED_KUBERNETES_DRAIN.md) describe
this O3 source increment. Managed physical execution remains disabled/unqualified;
O2–O4, M8 and the current phase remain incomplete.

The exact frozen-source run passed **521 Rust tests across 64
unique binaries** (77 executions), **34 Python tests**,
three Node suites, formatting, Clippy, Ruff, mypy and frozen paper/schema checks.
Primary/family/Kubernetes batches passed
**26/23/23 actual SQL groups**.
Every manifest case ran once, with no failures, ignored tests or skips. All
**596 source files** match the pre-run archive.

The shipping protected current SQL service uses a standalone peer-authenticated
barrier role. Tests cover exact original grant/attempt and row binding, role/ACL
drift, identical-row same-name database recreation and actual postmaster restart.
Database OID and postmaster lifetime are conservative enrollment boundaries, not
universal rollback detection. Outside-SQL signed heads and protected digest/floor
files are checked; durable latest-floor publication and writer/restore custody
remain external requirements.

The actual shipping service case uses mTLS, native etcd and SQL, separately
collected real Kubernetes availability, distinct query/evidence roles and
credentials, exact-proposal admission claims and native original dispatch.
Concurrent reads permit one source claim/result; replay remains refused across a
live-slot process restart. Wrong credentials/tenant/proposal do not consume the
first admission slot. Cached fresh evidence returns the same statement and expiry.
Resources, attempts/outcomes and snapshots remain byte-equivalent as JSON before
and after source requests. No managed physical mutation occurs in this case.

The new offline CLI independently verifies historical source/storage signatures,
original SQL execution identity and exact proposal evidence against signed
admission/issuance authorization. Its result explicitly says native history and
managed physical execution are unverified. This does not replace the complete
managed aggregate. Version0.2/action1.1 distinguishes the source lifetime and
distinct allocation-reservation/execution roots from the earlier prototype.

Twelve real Kubernetes cases each use a fresh fixture and seven RBAC checks;
bootstrap adds seven, totaling 91. Nineteen separate offline commands verify
fourteen family/physical, four O1 operating and one new source artifact. Prior
records retain their original semantics. Native four-claim admission exhaustion,
crash/race coverage, material exact-bound native exhaustion, shipping managed
controller/supervisor, gateway/SDK and complete per-CAS native/mechanical carriage
remain required. Pure material quota tests do not qualify exhaustion behavior.

The topology shares one host and isolated VM. It does not establish independent
custody, all-writer restore safety, production maintenance, physical failure,
workload SLO or independent whole-saga/authority-peer/release acceptance. Original
five-second grant/transport, ten-second ACK, family and inverse windows are
unchanged. SQL/Kubernetes are not atomic; unknown cannot authorize resend or SQL
inverse. Focused failed diagnostics remain retained; only the complete frozen run
qualifies final source. Prior results, frozen paper/schema/fixtures and SQL
migrations0001/0002 remain byte-identical.
