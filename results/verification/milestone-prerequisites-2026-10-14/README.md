# Milestone prerequisites — 14 October 2026

Baseline: ee1a0ff. RFCs 0029–0033. These are software prerequisites; no original
enterprise, hardware or independent release exit gate is accepted.

The full fixed-command conformance run passed **277 Rust tests / 43 binaries**,
**18 SQL storage/peer/restore groups**, **32 Python tests**, format, clippy, Ruff,
mypy, Node vectors, frozen whitepaper and schema checks. SQL/etcd/official SDK are
required; no Rust failure, ignored test or runtime SKIP occurred. Tool versions and
commands are in summary.json. Platform: Darwin ARM64, Rust 1.98.0, PostgreSQL 18.3,
etcd 3.6.5, Node 25.2.1, Python 3.13.12.

## Observations

- Correct kernel SQL peer pin works in the shipping protected target; incorrect
  pin/path/mode refuses before resource mutation. The SQL driver consumes the same
  verified stream. Two Unix transport groups and all ten native target cases pass.
- Real pg_dump/pg_restore loses a newer externally observed commit in a stale
  logical backup. Application login refuses behind CONNECTION LIMIT 0. The original
  is never redispatched; restored incarnation is changed before access resumes.
  Sixteen new direct storage commits and queries meet the local 3000 ms p95 budget.
- Three synthetic WebAuthn/real-etcd groups verify exact canonical challenge and
  original client bytes, signature, origin/RP/UP/UV, counter/replay, revocation,
  altered bindings and expiry. Expiry during consumption refuses publication while
  retaining the consumed challenge/counter. Hardware-bound enrollment refuses.
- Three real-etcd coordination groups verify one budget per tenant/domain in the
  authoritative namespace, last-slot contention, narrowed nesting, forward and
  compensation conservation, composite-parent refusal, immutable original attempt,
  held unknown/known no-effect state, stopped roots and recreated client status.
  Reservations create no execution grant, credential or dispatch permission.

## Source and evidence scope

summary.json retains the full run's source hashes and raw log hashes. After that
run, only the restore **report metadata** and two documentation files changed to
make its limitation explicit: direct storage calls do not enroll or exercise an
actual authority-ledger allowance. final-storage.json re-executes all eighteen
SQL/peer/restore groups on that final script and explicitly reports
**authority_consumption_tested=false**. Its missing outcome is unresolved, not
proof of no effect. Consumed-authority holding remains a required deployment
contract; the earlier raw tag is not evidence of that contract. final-ruff.log
checks the final script. Rust runtime/tests and all other implementation files
are byte-identical to the full passing run. final-source.json pins current sources,
the precise changed-file set and every retained evidence file. No earlier evidence
is overwritten or promoted to a broader qualification.

The separate preliminary run is retained at
[its record](../milestone-prerequisites-preliminary-2026-10-14/README.md); it predates
the domain-binding and final review-freshness checks and cannot qualify the current
implementation. A sandboxed first Unix-listener attempt refused OS socket creation;
escalated disposable socket tests then passed. The first stale restore lacked
reader schema enrollment; enrollment was moved behind the connection fence before
lookup. Earlier clippy feedback was corrected before the recorded full run.

## Reproduce

Install Python dev/spec dependencies and the locked Node SDK/Cargo dependencies;
provide PostgreSQL 18.3 binaries and etcd 3.6.5. Select a new output directory:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd \
  python scripts/conformance.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --output results/local/conformance-new
```

The runner refuses existing output directories, required runtime skips and source
changes during execution. It records passed_software_checks, not release acceptance.

## Open gates

The Linux separate-account fixture and minimum Rust CI job are implemented but
**unobserved locally**. No host users or production targets were changed. All-service
custody/rotation, approved AS/SVID providers, ACL/mount/launcher policy, deployed
bypass/writer coverage, physical SQL restore/retention, costs/on-call and owner
acceptance remain open. M7's native HITL/admission/lease and protected browser /
physical hardware paths remain unfinished. M8's native grant/claim/A2A/saga /
compensation and Kubernetes drain paths remain unfinished. M9 still requires an
independent controller, second runtime/target, actual intermediaries and reproduced
release evidence. Frozen fixtures, schema, paper, migration and old verification
bytes remain unchanged.
