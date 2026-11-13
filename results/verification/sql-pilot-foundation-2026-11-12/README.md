# cura SQL pilot foundation — 12 November 2026

Status: **bounded local software verification passed; Milestone A hosted CI and
remaining implementation verification open; Milestone B BLOCKED_EXTERNAL_INPUT**.
No AWS resources, independent owner approvals, publisher signatures or enterprise
acceptance records were created. The proposed profile is `cura`, us-west-2,
Ubuntu 24.04 ARM64, SQL-only. See [release contract](../../../docs/SQL_PILOT_RELEASE.md)
and [operations](../../../docs/PILOT_OPERATIONS.md).

## Observations

- 128 Python cases and six subtests pass. Seventeen cases cover new infrastructure,
  staging/SBOM, monitor validation and skip rejection. A second environment installs
  the pinned constraints and passes the same 128 cases.
- 87 Node acceptance/CI cases pass, including the original 55 Terraform acceptance
  cases after extracting shared bounded-reader/signature machinery. Seven existing
  SDK vector suites and frozen paper/protocol verification pass.
- Rust 1.98.0 format and all-target feature-enabled clippy pass in the pinned
  ARM64 Rust image. Eleven real-etcd restore cases pass, including the added
  stopped-member physical WAL/backend restore with an untouched separate witness.
- Two real PostgreSQL/etcd/official SDK SQL-leaf cases and all 17 SQL-failure module
  cases pass. Covered failure cases include changed target state, actual row locks,
  process kills, lost replies, original query recovery and retained incidents.
  These are explicit focused modules, not a claim that all 287 governance cases ran.
- Separate-account Linux SQL isolation passes ten groups and five live authenticated
  target queries. Staged systemd qualification passes nine units and 72 file probes;
  this staging-only run supplies **zero** native preflights and starts no units.
- The new Linux PostgreSQL 18.3 cold-copy harness refuses stale cutover against its
  separately retained fixture floor, restores the current original outcome, and
  observes one mutation and zero restore redispatches. Its restored application
  logins stay fenced; it never enables a deployment.
- cfn-lint 1.39.1 validates the proposed nine-host private infrastructure template.
  Static tests check deterministic rendering, network closure, constrained host
  IAM, metadata settings and retained encrypted data volumes. No AWS API is called.

The original Mac cold-SQL attempt failed during cached `initdb` execution. It is
retained as a failed diagnostic, not counted as passing Linux evidence. An initial
Rust reproduction lacked three compile-time frozen JSON inputs; those were supplied
unchanged before the successful lint/native runs. These setup failures do not
establish causes for GitHub's failures.

## CI diagnosis and limits

Public baseline run **43340090551**, source
`d1c6adbfc530de03db4ad754c34b016e2f9020e2`, fails Rust format/lint,
staged Linux qualification and the combined SQL job; identity is skipped. The
retained API responses identify failed steps. Full job logs require authentication,
so their exact error causes are **not established**. The same staged qualifier and
pinned lint pass locally. Changes pin Ubuntu 24.04, Rust 1.98.0, Node 25.2.1,
action commits and tested Python constraints, add diagnostics/provenance and a
required aggregate that refuses failed/skipped prerequisites. They do not prove
the new hosted workflow is green. Branch-protection configuration is an external
repository-administrator action.

The release-CI verifier explicitly rejects the retained red baseline. It additionally
requires the new cold-SQL/infrastructure/aggregate steps, so the old workflow cannot
satisfy the new release contract. Authenticated provenance of CI responses is an
independent-reproducer duty; invented JSON cannot establish a real CI run.

## Evidence interpretation

`source-hashes.json` pins the working implementation files against the baseline;
`artifact-hashes.json` seals this record's retained evidence. Build logs and fixture
records cover their exact sources and environments. No prior frozen result record
was modified or upgraded into enterprise qualification. The SQL runtime and frozen
wire records remain unchanged; Rust changes add a physical-restore test and its
fixture lifecycle support.

The physical authority case restores a stopped single fixture member, not a
quorum disaster or cloud volume. SQL's comparison floor is fixture-owned, not
independently administered production custody. Readiness metrics do not yet export
the full operational admission/incident/unknown-age event populations. The AWS
AMI, source-to-image/package installation, volume mounting, actual role/enrollment
configuration, service CA rollout, SRE budgets, independently owned physical backups,
full deployed writer/descendant probes and signed owner acceptance remain required.
Those limits keep the relevant Milestone A implementation and Milestone B acceptance
items open; none is replaced by local test success.
