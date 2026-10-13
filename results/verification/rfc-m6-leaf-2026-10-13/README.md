# M6b2 fresh PostgreSQL leaf path — 13 October 2026

[RFC 0025](../../../docs/rfcs/0025-postgres-leaf-binding.md) connects the named SQL
CTD through admission, issuance, the gateway and official Node client to the native
broker, PostgreSQL target and M4 recovery. Based on `61ea3ce` and the tested working
tree. Frozen v0.9 schema/fixtures/paper, SQL migration and Cargo.lock are unchanged.
[The earlier incomplete record](../rfc-m6-leaf-2026-10-12/README.md) is preserved;
it does not qualify this final source.

## Reproduction

Darwin ARM64; Rust 1.98.0; Node 25.2.1; etcd 3.6.5 (three loopback members);
Python 3.13.12; PostgreSQL 18.3 with M6a's official archive checksum. All services
and SQL data are disposable. Unix-socket login, workload, subject/actor enrollment
and evidence are generated software fixtures. No enterprise target is contacted.

```sh
PATH=/absolute/path/to/rust/bin:$PATH
CARGO_HOME=/isolated/cargo/cache
CARGO_TARGET_DIR=/isolated/cargo/target
ETCD_BINARY=/absolute/path/to/etcd
KF_REQUIRE_SDK=1
export PATH CARGO_HOME CARGO_TARGET_DIR ETCD_BINARY KF_REQUIRE_SDK
python scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --command scripts/start-etcd.sh -- \
  cargo test --locked --offline --workspace --all-targets -- --nocapture --test-threads=1
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
python scripts/verify-whitepaper.py
python spec/validate.py
ruff check .
mypy src
pytest -q
```

The SQL launcher sets `KF_REQUIRE_POSTGRES=1`; the inner launcher requires etcd;
the SDK is also required. Rust cases are serialized for host disk capacity; tests
still race explicit concurrent actors. Plain Cargo runs can skip unconfigured
dependencies. The SQL CI job now requires all three dependencies for target/fresh
leaf cases. Its YAML and shell parse locally; remote Linux/GitHub execution remains
unobserved. Declared minimum Rust 1.88 and Node 20 remain unqualified.

## Final-source observations

[Combined log](tests.log): **249 Rust tests pass across 39 test binaries**, zero
failures/ignored/skipped, with all three dependencies required. [SQL storage](postgres.json):
eleven real storage groups pass. Clippy, format, Node vectors, frozen paper/schema,
Ruff/mypy and all 32 Python tests pass. Source/evidence hashes are in [summary.json](summary.json).

The fresh SQL cases use installed/acknowledged control state; exact signed proposal,
CTD, manifest and witnesses; Cedar admission; retained certificate; issuer-owned
root/fence allocation; the unmodified official MCP SDK and Node adapter; native
broker verification of Ed25519 subject and ES256 JWT-SVID actor signatures; and
original durable claim/current-control CAS before one permit and mint. The SQL
target independently verifies grant/reference token over actual mTLS, then a real
PostgreSQL COMMIT retains the matching outcome.

- Normal execution moves version 241 to 242, applies the exact reservation and
  preserves the issuer's fence plus original grant/root/attempt correlation.
- Discarding the target reply after COMMIT leaves the original attempt unknown.
  Authenticated query-only M4 recovery resolves it as committed without SQL resend.
- A separate Node process resolves the same persisted operation after expiry and
  domain revocation with renewed status-only delegation. Each case retains one
  baseline/collection, one broker mint and one SQL apply.
- Signed application/schema/action-version substitutions refuse admission;
  changed reservation/resource/version and injected authority fields refuse grant
  binding. Explicit SQL gateway configuration refuses fallback, mixed tools,
  wrong profile/registration/audience/scope/key roles. Shipping `kf-proxy --check`
  builds the SQL adapter from local material without probing remote services/SQL.
- Node vectors reject weakened schemas/digests, unsupported named version, extra
  target metadata, wrong resource, malformed labels and unsafe numbers.
- The new deterministic generator regression tests every possible leading byte
  against frozen Id and whole SQL dispatch schemas, with negative controls for
  the old generator's `-` and `_` prefixes. All existing legacy mock, native broker,
  nine process-crash cases and six native SQL target cases pass in the final run.

## Preliminary failures and correction

Three preliminary combined runs reported unavailable entries in different existing
recovery-process tests. [The original partial record](../rfc-m6-leaf-2026-10-12/README.md)
retains the first two; [the third log](pre-fix-third-run.log) retains the worker
receipt-barrier failure. Approval review was initially unavailable because its
model was at capacity; subsequent approval succeeded. Diagnostic runs of all nine
cases and three repeats of the two earlier failures passed before correction;
those logs describe the pre-fix source with temporary diagnostic logging, not
final-source qualification.

The gateway used raw base64url for generated IDs. Its first character can be `-`
or `_` (2 of 64 encodings), whereas the frozen Receipt attempt Id and SQL labels
require an alphanumeric first character. Recovery can therefore reject its own
receipt after a successful claim/effect. The gateway now adds `kf-`, retaining all
144 random bits. [Deterministic regression](id-regression.log) reproduces the old
invalid prefixes and proves schema acceptance of every corrected leading byte.
No schema, recovery behavior or assertion was weakened. Temporary logging was
removed before the final clean regression. Historical consumed attempts retain
original IDs; the fix does not rename, resend or refund them.

## Limits and next milestone

This is same-host software composition with generated identity/evidence and fixture
SQL roles. Evidence is a fixed signed software snapshot, not a live enterprise SQL
provider. The fixture pins version 241 for one transition; automated version-template
or descriptor rollover is unqualified. Existing mock gateway/worker kills and native SQL target restart cases
remain separate qualification. M6c must combine the fresh SQL path with process
kills, restore witness and owned incident/collector delivery. Physical storage loss,
stale SQL backup, production provider refresh/custody/peer maps, writer/bypass
coverage, retention/migration/fence bootstrap, budgets and owner acceptance remain
open. Independent peers and minimum/Linux platforms remain unqualified.

The record began on 12 October and completed on 13 October. Logs normalize workspace
and disposable paths, strip terminal color and preserve semantic test results.
Earlier evidence is preserved byte-for-byte.
