# Frozen whitepaper and Rust implementation handoff

The [KedgeFlow v0.9 whitepaper](whitepaper/v0.9/output/pdf/kedgeflow-whitepaper.pdf)
is frozen on 6 October 2026. Rust is the primary implementation language. The
paper defines language-independent authority and effect contracts; Go is not a
protocol requirement. Development now proceeds here against the frozen contracts.

## Pinned baseline

- Paper source: `9ee111e46b32d212bc3d669c86d5dbe96d9d63b2` in the assurance repository.
- Paper freeze commit: `fe298516df815bd91d13a875e79e88920ea41445`, tagged
  `kedgeflow-whitepaper-v0.9` in that repository.
- Primary runtime evidence: Rust commit `0a06d00e2d6f951b7763b85ea01694f31385b159`,
  crate `kedgeflow` version `0.9.0-alpha.1`, executable `kf-proxy`.
- Frozen source, PDF, schema, profiles and fixtures:
  [package](whitepaper/v0.9/README.md) and [SHA-256 manifest](whitepaper/v0.9/FREEZE.json).

The runtime commit records the implementation tested when the paper was frozen.
It does not lock future Rust development. Paper or protocol changes need a new
version; implementation changes may continue against this baseline.

## Language reconciliation

| Artifact | Role and status | Evidence ownership |
|---|---|---|
| Rust crate and `kf-proxy` | Primary, bounded v0.9 execution gateway and trusted authority library ports | [Rust verification](RUST_VERIFICATION.md) and `results/verification/`; 52 Rust tests and 24 Python compatibility tests recorded at the baseline |
| Assurance `acp/prototype` Go proxy | Earlier execution prototype, retained as a supplementary experiment | Historical Go checks in the assurance repository; its 6,560-claim matrix is not a Rust throughput result |
| Assurance `acp/services` Go admission/review services | Separate capacity-reservation experiment; not ported or integrated end-to-end with the Rust gateway | Historical Cedar policy and WebAuthn assertion checks; software fixtures do not establish hardware enrollment |
| Python `src/kedgeflow` | Preserved v0.1 local demonstration and compatibility surface | Python tests; its in-memory controller and HMAC authority do not implement the v0.9 trust boundaries |
| Schema and signed fixtures | Language-independent KF-JSON-0.2 wire contracts | Byte-identical schema and 22 shared fixture files across the paper and Rust repositories |

The full nine-role coverage matrix is in [component boundaries](architecture.md).
Sections 8.4 and 10.4 of the frozen paper distinguish these artifacts and checks.
No test result transfers between languages merely because they share fixtures.

## Map the blueprint to Rust

| Paper responsibility | Current code | Remaining implementation |
|---|---|---|
| Execution Gateway | `gateway`, `server`, `auth`, `tls`, `endpoint`, `bin/kf-proxy` | Production trust provisioning and agent deployment/writer coverage |
| Grant Authority | `issuance`, `control`, `ledger`, `bin/kf-control`; retained chain verification, atomic issuance, IDs/fences and current installed-state/revocation checks | Real-target counter bootstrap, writer coverage and enrollment qualification |
| Enforcement Control | `governance*`, `gateway_control`, `ledger`, `bin/kf-governance`; signed publication/install/revoke/query, native gateway acknowledgement renewal and lifecycle CAS/race tests | Broader component coverage, production trust/RBAC, migration and restore barriers |
| Resource Adapter | `adapter`; fixed HTTPS fenced mock-target contract | Typed production target adapters with truthful guard and outcome semantics |
| Credential exchange and optional grant transport | `broker`, `grant_reference` | M5b adds a trusted independent broker authorizer; real AS verification/mint, target binding and operational controls remain open |
| Outcome Service | Durable ledger attempts/outbox, query-only reconciliation | Worker, authoritative target queries, incident escalation and safe compensation coordination |
| Admission Controller | `admission`, `policy`, `control`, `bin/kf-control`; signed inputs/Cedar, durable certificate/chain and installed control checks | RFCs 0034/0035 supply reviewed evidence/static leases; browser/hardware, leased lineage/SDK and administered enrollment remain open |
| Policy Authority / Resource Registry | `kf-governance`; operator-approved signed policy/CTD publication with epochs and expected installation revisions | Dynamic trust lifecycle, broader resource schemas and accepted deployment administration |
| Evidence Provider / Agent Adapter | Signed fixtures and client compatibility harness | Evidence acquisition/providers and actual agent workflow integration |

The executable supports one nondelegated resource, one `version_eq` predicate,
`Level_A` with `FencingToken`, and `dispatch_bound` completion. Delegated grants,
multiple predicates/resources, other guard contracts, saga execution and
`commit_bound` validity remain refused. Expanding the scope requires implementing
the corresponding invariants and failure tests before accepting new inputs.

## First implementation milestone

Build one Rust path from a real Agent Adapter through admission and issuance to
the existing gateway and fenced target. The bounded admission/issuer service is
now implemented under [RFC 0006](rfcs/0006-leaf-control-http.md), with
[fresh native TLS/etcd evidence](../results/verification/rfc-m2-service-2026-10-11/README.md).
The complete workflow gate remains open. Keep its policy/action scope narrow:

1. Implement an independently administered Admission Controller that verifies the
   signed exact proposal, descriptor and identity bindings, current policy and
   fresh trusted evidence. Emit a KF-JSON-0.2 certificate only when every required
   obligation is satisfied; unknown or invalid evidence must not authorize.
2. Expose a Grant Authority service that authenticates that certificate, checks
   current policy/ownership, and uses the existing atomic issuance ledger ports.
   Preserve root allowance, replacement and replay invariants. Keep signing keys
   and publication/issuance privileges outside the agent domain.
3. Connect a real Agent Adapter to remediation, exact proposal freezing and grant
   carriage. Demonstrate fresh admission followed by issuance and execution,
   rather than supplying a preissued fixture grant.
4. Verify stale evidence, altered parameters/identity, policy changes, concurrent
   claims, expiry around credential exchange, unknown outcomes and bypass denial.
   Report admission refusal separately from target completion.

The Go experiments provide behavioral examples. RFC 0034 now supplies a narrow
native Rust review provider and evidence/admission binding. Human-review deployment
still needs protected display, physical enrollment/attestation and an actual
ceremony; generating a software assertion does not qualify those boundaries.
Production target adapters, an outcome worker and saga support follow as separate
milestones. The bounded [M2c control lifecycle](rfcs/0007-enforcement-control-http.md)
is delivered. The [M3a Agent Adapter/status slice](rfcs/0008-agent-replay-and-status.md)
now performs fresh admission/issuance to mock execution with the official client.
[M3b operation lookup](rfcs/0009-operation-status.md) and bounded issuer/provider
reply and persistence fault tests are delivered. Wider qualification, recovery,
enterprise trust and production target qualification remain later work.

## Verify the freeze

```sh
python scripts/verify-whitepaper.py
python spec/validate.py
```

The first command uses only the Python standard library. It checks every frozen
file and the current schema, grant-reference profile and shared fixtures against
the manifest. Continuous integration runs it before lint and tests. It permits
runtime changes while detecting edits to the frozen protocol baseline. The second
command validates schema, signatures and semantic bindings with the specification
dependencies installed. Frozen source is retained verbatim and excluded from
active-code lint; its bytes are checked instead.

Handoff checks executed on 6 October 2026: the freeze check, specification
validator and repository lint passed. Eight new freeze-check tests passed,
including altered schema/profile/fixture/paper bytes, a missing fixture, a removed
contract pin and an unlisted frozen file. Runtime behavior was unchanged in this
handoff; the 52-test Rust record above remains evidence from the pinned baseline.

The bounded [M4a recovery increment](rfcs/0010-outcome-recovery.md) adds retained
execution history, a query-only worker, signed receipts and offline receipt-chain
verification with missing full-lineage links explicit. Full M4 acceptance remains open.

[M4b1 retained delivery](rfcs/0011-outcome-report-http.md) adds a separate native
collector and current reporter authentication, immutable signed acknowledgements
and historical lookup. It accepts already-retained receipts/evidence only and
changes no execution state. Its tenant labels a dedicated operator namespace;
[M4b2 signed lineage](ADMISSION_LINEAGE.md) now establishes signed proposal/CTD
tenancy and historical authorization bindings under independent trust. Installation/
key history, target proof and independent storage/restore remain open.

[M4b3 governance history](CONTROL_HISTORY.md) retains applied control records and
authenticates an observer-attested prefix plus independently approved historical
key membership. It provides no operation-bound control-state or non-revocation
proof by itself. [M4b4 control bindings](CONTROL_BINDINGS.md) now retain actual
per-transition control snapshots atomically and verify observer-attested historical
comparisons. These remain assertions under trusted observer/ledger operation and
clock assumptions. Enterprise observer/key custody, authenticated fence allocation,
crash/restore qualification and target proof remain open.

[M4c1 process termination](PROCESS_CRASH_RECOVERY.md) now qualifies nine actual
gateway/worker SIGKILL/restart boundaries against native etcd and an atomic software
target in explicit unmanaged fixture mode. Original attempts remain conserved;
possible-send not-found stays unknown. Managed crash/renewal coverage, full admission
lineage across these kills, real target durability, host/power failure, stale-backup
restore quarantine and enterprise custody/RBAC remain open.

The bounded M4c2 [restore gate](RESTORE_QUARANTINE.md) reserves every mutating ledger transaction
in a separately retained witness before local submission. Explicit empty enrollment
and exact ready-head comparison quarantine stale or pending authority, including
recovery writes. Pending repair, migration and production deployment qualification
remain open. M4c3 now supplies bounded owned incidents and automatic delivery.

[M4c3 supervision](OUTCOME_SUPERVISION.md) retains unknown-age deadlines and an operator-enrolled
owner, delivers retained receipts in order and verifies durable collector acceptance
through restart. Native software faults and shipping worker polling are qualified;
external incident routing, production identity/rotation and combined managed restore
deployment remain open. M5a now adds opt-in [shared authentication](SHARED_AUTHENTICATION.md) with durable
DPoP consumption and explicit subject/workload/scope registration. Real AS/SVID
rotation and enterprise deployment remain open; M5b supplies bounded broker authorization.

M5b now supplies [broker authorization](BROKER_AUTHORIZATION.md) before one-shot
credential minting. Native etcd tests qualify grant/claim/target checks; software
provider identities do not establish actual AS verification or token custody.
[Enterprise acceptance inputs](ENTERPRISE_QUALIFICATION.md) keep M5c–M9 gates open.

M5c1 adds [pinned exchange identity verification](EXCHANGE_IDENTITIES.md) with actual
subject/actor signatures, the admission delegation algorithm, bounded trust refresh,
key retirement and registration/token withdrawal. Generated software keys do not
qualify actual AS/SVID provisioning, revocation delivery, broker minting or custody.

M5c2 now supplies the [native broker token service](BROKER_TOKEN_SERVICE.md), strict
exchange form, one permit before one mint and independently verified reference
target-token bindings. Shipping-binary restart and native client/fault tests
qualify software behavior; actual target enforcement and enterprise acceptance
remain open.

M5c3 adds [signed identity refresh](IDENTITY_REFRESH.md), exact protected head
checks and remembered epoch/digest state per exchange. Native actor-key rollover
works without broker restart. Approved publisher administration, independently
retained head/floor custody and real AS/SVID/target qualification remain open.

## 14 October software prerequisites

[RFCs 0029–0033](MILESTONE_PREREQUISITES.md) add SQL kernel peer pinning before
startup bytes, a separate-account Linux CI harness, actual fenced stale logical
SQL restore with external lost-commit history and local storage budgets, canonical
WebAuthn ES256 assertion/durable consumption, hierarchical capacity conservation
and a required conformance runner. The review and reservation ports remain trusted
libraries. Native HITL/lease and grant/A2A/saga/drain integrations remain unfinished;
Linux account/MSRV CI execution, physical hardware/targets and independent release
acceptance remain unobserved locally. Frozen baseline bytes and earlier verification
remain immutable. No original enterprise/release gate is closed by these results.

[RFC 0034 native review](NATIVE_REVIEW.md) now connects a protected provider and
canonical server rendering to generic signed Evidence, with exact durable
consumption and enrollment comparisons in admission/issuance. Native software
composition, revocation races and shipping process recovery are qualified. Frozen
HITL variants, browser/physical enrollment and enterprise acceptance remain
open. The preceding prerequisite record describes its own earlier baseline.

[RFC 0035 static leases](STATIC_ADMISSION_LEASES.md) now retains exact-proposal
static prevalidation, rechecks original evidence and requires fresh JIT observations.
Membership generation/withdrawal and exact lease comparisons cover native admission,
fence allocation and issuance; shipping lost-reply crash/restart preserves original
bytes. Leases have no execution authority. Current historical export schemas refuse
leased packets; versioned leased lineage/SDK, physical ceremony and accepted
provider/membership/custody lifecycle remain open.
