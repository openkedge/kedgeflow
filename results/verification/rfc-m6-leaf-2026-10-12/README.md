# M6b2 fresh PostgreSQL leaf path — 12 October 2026

[RFC 0025](../../../docs/rfcs/0025-postgres-leaf-binding.md) connects the named SQL
CTD through admission, issuance, the gateway and official Node client to the native
broker and PostgreSQL target/recovery. Based on `61ea3ce` and the tested working tree.
Frozen v0.9 wire/schema/fixtures, SQL migration and previous evidence are unchanged.

## Reproduction

Darwin ARM64; Rust 1.98.0; Node 25.2.1; etcd 3.6.5 (three loopback members);
Python 3.13.12; PostgreSQL 18.3 with M6a's official archive checksum. Services and
SQL database are disposable. Unix-socket login/identity/evidence fixtures are
synthetic. No deployed enterprise environment is contacted.

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

The outer launcher requires PostgreSQL and sets `KF_REQUIRE_POSTGRES=1`; the inner
launcher requires etcd; SDK is also required. Rust cases are serialized for host
disk capacity; tests still run explicit concurrent actors. A plain Cargo run can
skip unconfigured dependencies. The SQL CI job now requires SDK/etcd alongside SQL;
YAML and shell syntax pass locally, but remote Linux/GitHub execution is unobserved.

## Observations

[Focused native log](focused-tests.log): two fresh SQL leaf tests pass. [Binding
checks](binding-tests.log): three SQL admission/configuration/grant-binding tests
pass. [SQL storage](postgres.json): eleven real storage groups pass. Clippy, format,
Node vectors, frozen paper/schema, Ruff/mypy and all 32 Python tests pass.
Cargo.lock and frozen storage contracts remain unchanged.

**Complete regression is pending.** Two combined required-mode runs stopped in
existing recovery-process tests: `killed_gateway_after_dispatch_before_response`
and `killed_gateway_before_dispatch_authorization` each reported an unavailable
entry. The former passed in the latter run; both had passed in an earlier run that
caught a now-fixed Node vector output-framing issue. This is not a clean full run.
The failed combined logs are retained as [run one](recovery-transient.log) and
[run two](recovery-transient-2.log). Four diagnostic approval attempts failed
because the automatic review model was at capacity; commands were not executed.
No diagnostic logging remains; no recovery behavior/assertion changed.

The new fresh SQL cases use actual installed/acknowledged control state, signed
proposal/CTD/manifest/witness inputs, Cedar admission, retained certificate and
issuer-owned root/fence allocation. The unmodified official MCP SDK and Node
adapter carry the exact three SQL arguments. The native broker independently
verifies generated Ed25519 subject and ES256 JWT-SVID actor signatures, the original
durable claim and current control before one permit/mint. The target independently
verifies grant and reference credential over actual mTLS before a real SQL COMMIT.

- Normal execution increments version 241 to 242, preserves the issuer's fence,
  sets the exact reservation and retains the original grant/root/attempt outcome.
- Discarding the target's reply after COMMIT makes the gateway/client report
  unknown. The authenticated query-only M4 worker resolves that same attempt
  as committed; SQL apply is never retried.
- A separate Node process, after grant expiry and domain revocation, queries the
  original persisted operation with renewed status-only delegation. Exactly one
  provider collection/baseline, broker mint and SQL apply occur in either case.
- Signed parameter/schema/action-version substitutions refuse admission; changed
  reservation/resource/version/injected authority fields refuse grant binding.
  The SQL gateway opt-in refuses fallback, mixed tools, wrong profile/registration/
  audience/scope/keys. Shipping `kf-proxy --check` constructs the SQL adapter from
  local material without probing a target, broker, ledger or database.
- Node vectors reject weakened SQL schemas/digests, unsupported named version,
  extra target metadata, wrong resources, invalid labels and unsafe numbers.
  Legacy mock, broker, recovery and six native SQL target tests also pass.

## Limits

This is same-host software composition with generated workload certificates,
identity trust snapshot, signed evidence and fixture SQL roles. The evidence
provider is a fixed software snapshot; it is not a live enterprise SQL evidence
service. Existing gateway/worker kill and native target restart tests remain
separate qualification cases; a combined fresh SQL process-kill/restore/incident
matrix is M6c work. No stale SQL backup or physical storage-loss claim is made.
The repeated recovery availability failures remain unresolved, and M6b2 cannot
be marked fully verified until diagnostics and a complete required regression pass.
No assertion or recovery behavior was weakened to obtain targeted results.

Approved provider refresh/custody/peer maps, deployed writer/bypass coverage,
retention/migration/fence bootstrap, budgets, incident operations and owner/pilot
acceptance remain open. Rust 1.88, Node 20, Linux and independent peers remain
unqualified. No dependency or schema release is implied by this draft.

[Summary and hashes](summary.json) pin tested sources and retained evidence. Logs
normalize workspace/disposable paths and strip terminal color; semantic test
results are retained. Earlier evidence is preserved byte-for-byte.
