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
| Grant Authority | `issuance`, `control`, `ledger`, `bin/kf-control`; authenticated retained certificate/chain verification, operation-wide atomic issuance, generated IDs and resource fences | Live installed-control ingestion, real-target counter bootstrap and writer coverage |
| Enforcement Control | `ledger`; trusted policy publication, epoch comparisons and claim ports | Authorized publication/install/revoke APIs, installed-version/coverage acknowledgements and lifecycle races |
| Resource Adapter | `adapter`; fixed HTTPS fenced mock-target contract | Typed production target adapters with truthful guard and outcome semantics |
| Credential exchange and optional grant transport | `broker`, `grant_reference` | Real authorization-server bindings, resolver publication/retention and operational controls |
| Outcome Service | Durable ledger attempts/outbox, query-only reconciliation | Worker, authoritative target queries, incident escalation and safe compensation coordination |
| Admission Controller | `admission`, `policy`, `control`, `bin/kf-control`; signed input/evidence verification, pinned Cedar evaluation, durable certificate and raw-chain production | Live control ingestion, richer evidence/human review profiles and administered enrollment |
| Policy Authority, Resource Registry, Evidence Provider, Agent Adapter | Static operator pins, schemas, signed fixtures and client compatibility harness | Authorized policy/registry services, evidence acquisition/providers and actual agent workflow integration |

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

The Go capacity and review services provide behavioral examples for a later Rust
port. Their profile must be reconciled explicitly with the selected action before
integration. Human-review deployment also needs canonical rendering, enrollment,
attestation and replay state; generating a software assertion is insufficient.
Production target adapters, an outcome worker and saga support follow as separate
milestones. Authorized control lifecycle is the next M2c increment; the live
Agent Adapter, recovery worker and production target remain later work.

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
