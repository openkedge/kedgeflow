# Managed physical supervision implementation — 26 October 2026

Baseline: 583999acb3b9c85a7972de01fa19c42eeeadcf8c. [RFC0056](../../../docs/rfcs/0056-physical-operating-records.md)
and the [managed-drain guide](../../../docs/MANAGED_KUBERNETES_DRAIN.md) describe
this read-only supervision and complete audit increment. Shipping managed mutation
configuration, gateway/SDK and combined qualification remain open. M8 and the
current phase remain incomplete.

The exact frozen-source run passed **524 Rust tests across 66
unique binaries** (81 executions), **34 Python tests**,
three Node suites, formatting, Clippy, Ruff, mypy and frozen paper/schema checks.
Primary/family/Kubernetes batches passed
**26/23/23 actual SQL groups**.
Every manifest case ran once, with no failures, ignored tests or skips. All
**608 source files** match the pre-run archive.

Two earlier frozen full attempts are preserved with their own source and runtime
evidence. [Attempt1](../rfc-m8-managed-supervision-2026-10-26-failed-1/failure.json)
stopped on a legacy acceptance refusal; unchanged source passed focused reproduction
and that case in the next full run.
[Attempt2](../rfc-m8-managed-supervision-2026-10-26-failed-2/failure.json) passed the
primary/family batches and thirteen Kubernetes cases, then took a third incident
delivery attempt instead of the expected two. The repair retains an already
received signed ACK across up to three local native CAS comparisons within its
original five-second slot, sampling the protected clock after reads and before
CAS. Failed retention leaves the original slot consumed until expiry. A regression
forces a real etcd epoch conflict and requires exactly two sink requests. No
window was widened and no test was removed. Only the complete final frozen run
qualifies this source.

The protected shipping supervisor has independent deadline, observation and
incident-delivery loops. It owns independently pinned observer/operating keys,
read-only Kubernetes access and distinct native/sink mTLS credentials. Closed
configuration refuses wrong profiles/roles/keys, null/unknown fields, root escape
and widened secret permissions. Local file validation does not establish deployed
OS custody or remote RBAC. Every observation reserves its shared native slot before
I/O; failed or interrupted work remains consumed. Existing query budgets,10s whole
managed physical capture,512KiB snapshot and native material limits are unchanged.

Retained-byte decoding and pure replay run off the asynchronous workers with
bounded immutable-input caching and a single verifier per identical input. Every
caller still performs a current native read. Controller final-send preparation
carries forward only its verified Pending successor after the original CAS wins;
its fresh authority comparisons and final protected-clock check remain mandatory.
The original1s maximum authorization-to-send remains enforced. Focused failures
retain measured refusals and do not qualify later source.

The actual completion case uses the explicit managed library controller, shipping
SQL source/supervisor and real cordon/eviction. Native committed acceptance is
first observed as unresolved. Independent physical completion then resolves the
operating record with five original control proofs and three native SQL source
claims. SQL rows remain unchanged by physical supervision. Shipping managed
controller configuration and gateway/SDK are not exercised by this case.

The unknown case discloses original receipt absence explicitly in separate closed
pending outcome/lineage/reserved/control supplements. They retain the actual signed
grant and original journal, require zero receipts/evidence, and report only pending.
Native export compares exact journal/context/nonce/attempt/outbox and absent
receipt head at enclosing checkpoints. Reservation events keep their original
profile. Receipt-based formats still refuse the empty chain. No receipt or effect
classification is fabricated.

A real original deadline opens the owned incident outbox. The sink retains its
signed report and ACK before the supervisor is killed. Restart delivers the same
report after the original delivery slot expires and retains the same ACK on its
finite second attempt. The operation remains unresolved, with both forward units
and its compensation unit held. Incident acknowledgement conveys no outcome,
refund, new mutation or inverse permission.

The complete offline verifier replays every operating event, referenced aggregate
and acknowledgement, original admission/preflight/source claim, mechanical
signature prefix and final-send native authority. Validly re-signed omissions and
missing outer evidence refuse. Its checkpoint attests a complete native operating
and physical prefix under independently pinned observers; it is not an etcd
consensus proof or current execution authority. Operating and physical observation
times are reported separately. Export performs no extra physical query.

Fourteen real Kubernetes cases each use a fresh fixture and seven RBAC checks;
bootstrap adds seven, totaling 105. Twenty-one standalone commands replay fourteen
family/physical artifacts, four original O1 operating artifacts, the current SQL
source and both new managed audits. The unchanged source archive and public
runtime records retain the exact evidence. Previous results, frozen paper/schema/
fixtures and SQL migrations0001/0002 remain byte-identical.

Remaining software includes shipping managed controller/gateway/SDK, positive live
closure, wider concurrent/paused-CAS/stop and exact-bound admission/material
exhaustion cases, then combined all-shipping qualification. Independent custody,
durable storage-head publication, all writers/restore safety, production
maintenance, physical failure, workload SLO and external whole-saga/authority-peer/
release acceptance remain separate gates. This shared-host/VM topology cannot
establish those deployment properties.
