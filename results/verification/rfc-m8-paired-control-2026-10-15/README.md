# M8d2b2a paired action controls — 15 October 2026

Baseline: 2e48421. [RFC 0046](../../../docs/rfcs/0046-paired-action-domain.md)
and the [operator guide](../../../docs/PAIRED_ACTION_DOMAINS.md) add the explicit
`KF-PAIRED-ACTION-DOMAIN-0.1-draft` control prerequisite. A fresh immutable topology
pins separate exact forward/inverse installations over one physical resource /
domain. Global native operation indices and the resource fence counter stay in
the original authority namespace. The inverse lane remains nonexecuting.

The complete final required run passed **414 Rust tests across 49 binaries**,
**18 SQL storage/peer/restore groups**, **32 Python tests**, both Node vector suites,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips occurred. All **477 source files** remained
unchanged during the final run and afterward. `summary.json` pins commands, source,
logs and tool versions; `final-source.json` pins the same source, observations and
this evidence. No source repairs were needed during or after the final run.
`kf-action-domain` brings the shipping binary count to 19. This is local Darwin
software qualification, with disposable single-host etcd and PostgreSQL fixtures.
Linux separate-account/MSRV, physical targets and independent acceptance remain
unobserved here.

## New observations

Ten new native/configuration/CLI groups establish:

- Closed bounded topology material rejects mismatched tenant, resource/incarnation,
  physical domain, ownership, equal action IDs, malformed role keys and mismatched
  resource guards/predicates, plus duplicate/unknown fields and oversized inputs.
- Protected enrollment atomically writes the original topology and legacy
  unknown-profile sentinel. Exact retries preserve it. Changed pins, existing
  legacy policy/ownership/reservation/governance/history or stopped state refuse.
- Separately signed per-lane publications, installations and gateway acknowledgements
  retain distinct native history. Forward admission/issuance works; installing or
  revoking the inverse control cannot enable inverse execution or revoke forward
  control accidentally. Raw unsigned policy publication and omitted configuration
  cannot bypass the managed physical domain.
- Distinct approved forward actions/domains over the same tenant/resource /
  incarnation retain one global operation identity and resource fence allocator.
  Reusing the original QID cannot replace its admission or obtain another fence;
  a distinct operation obtains the next resource fence. The original issuance
  remains byte-identical on replay.
- Scope/lane switching, mismatched reservation attachment in either order, foreign
  physical-domain queries, missing/changed topology and wrong-lane claims refuse.
  The inverse lane cannot enroll another reservation to manufacture compensation
  capacity. Every selected native transaction compares the complete topology and
  legacy sentinel, including read/duplicate and restore-witness paths.
- A permanent whole-domain stop blocks fresh admission/issuance/reuse, claims and
  dispatch. An actual delayed native claim transaction races the stop and loses
  without retaining an attempt. Historical query-only recovery still records the
  original committed outcome once and preserves the original attempt after stop.
- Complete original committed forward-saga history qualifies under RFC 0045 through
  the paired storage layout. Its permanent marker additionally pins the topology;
  changed inverse scope/policy cannot qualify. Synthetic target/applicability
  statements establish no physical barrier, inverse authority or target effect.
- Shipping control/gateway/recovery/broker/outcome/review configurations preserve
  classic omission but require an explicit valid paired selection. Null, unknown
  fields and caller-selected lanes refuse. The protected public example validates.
- The shipping `kf-action-domain` CLI uses fixed mTLS/token configuration, performs
  local checks without remote access, and supports original enrollment/status/stop
  across new processes and exact replay. Stop remains permanent; re-enrollment
  refuses. Only topology/sentinel/stop writes occur; no admission, grant, budget,
  fence, claim, outbox or target mutation is produced by this operator CLI.

## Remaining M8 gates

This completes only M8d2b2a, not M8. Fresh inverse proposal/evidence/Cedar admission,
mandatory signed compound binding, atomic spending from held compensation and
inverse issuance/claim/dispatch remain M8d2b2. Actual registered inverse/barrier,
late-effect, crash, partial/failure/unknown compensation and complete independent
saga evidence remain M8d3. The separate actual Kubernetes drain controller and its
Level C physical/writer qualification remain M8e. Dynamic delegation, complete A2A
peers and enterprise/writer/independent release acceptance remain open.

Single-action lineage remains historical evidence for its exact original scope;
it does not attest the paired topology or complete saga acceptance. No new global
cross-namespace/cluster atomicity, refund, retry or timer-based release is claimed.
