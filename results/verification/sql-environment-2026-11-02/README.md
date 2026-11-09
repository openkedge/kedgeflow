# N1 controlled SQL target changes — 2 November 2026

Runtime baseline `92169c5eef910fe5c1808b9b9bff5f6f00c477d0` plus
[source.patch](source.patch). [Source hashes](source-hashes.json) pin 435 code,
configuration, schema, test, tool and CI files; planning documents and evidence
files are excluded from that code manifest. The patch changes two test helpers
and adds the environment test module. Production runtime, migrations, frozen
schemas and Cargo.lock are unchanged.

The [qualification guide](../../../docs/SQL_ENVIRONMENT_QUALIFICATION.md) describes
the boundary, oracle and limitations. This is a same-host software qualification,
not production, independent custody or Terraform acceptance.

## Executed evidence

The final [combined regression](regression.log) passes **20 cases**: the six new
environment cases, eleven existing forward SQL fault cases and three existing
compensation fault cases. It has zero failures, ignored cases or dependency
skips, with **23 SQL/peer/compensation storage groups** also passing.
[Summary and artifact hashes](summary.json), [final case records](cases.json)
and [storage results](postgres.json) retain the measured populations.
This combined run sets `RUST_MIN_STACK=8388608`; the default-stack failure below
remains recorded separately.

The [focused run](focused.log) passes **six new composed cases** with no failed,
ignored or skipped cases. Its launcher also passes **23 SQL/peer/compensation
storage groups**. [Case records](focused-cases.json) retain the exact injected
state, independent target observation and original attempt/outcome per case.

- The unchanged control commits exactly one mutation.
- Version/reservation, incarnation, fence and active-state changes reject the
  original mutation and preserve the external writer's state.
- Discarding the committed guard-rejection reply preserves the original unknown
  authority state, even though query retrieves the original target rejection.
- Every case restarts gateway and target, expires the original grant, replays the
  shipping recovery worker, then resumes in a fresh status-only SDK process.
  Claim, credential permit, broker forwarding and target dispatch remain one.
  No additional original effect or replacement claim is accepted.
- All six target oracles reject both a corrupted terminal status and an
  unauthorized resource value: twelve sensitivity checks. Zero violating
  original effects were observed in these six cases. One authority outcome
  remains unresolved; it is not counted as a successful execution.

[Clippy](clippy.log) passes for the governance test target with warnings denied.
Formatting and JavaScript syntax checks pass; the Node agent vector suite also
passes. These checks do not extend the historical frozen M8 completion record.

## Reproduction

Observed environment: Darwin ARM64, Rust/Cargo 1.98.0, Python 3.13.9, Node
25.2.1, PostgreSQL 18.3, etcd 3.6.5 and the installed pinned official SDK.
The launchers use a new peer-authenticated Unix-socket-only PostgreSQL cluster,
three loopback etcd members, generated service identities and a separate
temporary witness per composed case. No production resources or credentials
are used. PostgreSQL shared-memory allocation requires execution outside the
restricted application sandbox on this host.

```sh
export PATH=/path/to/rust/bin:/path/to/python/bin:/path/to/node/bin:$PATH
export CARGO_HOME=/writable/cargo/cache
export CARGO_TARGET_DIR=/writable/cargo/target
export ETCD_BINARY=/path/to/etcd-3.6.5
export KF_REQUIRE_SDK=1
python3 scripts/test-postgres.py --bindir /path/to/postgresql-18.3/bin --peer \
  --command scripts/start-etcd.sh -- \
  cargo test --locked --offline --test governance sql_failure::environment \
    -- --nocapture --test-threads=1
cargo clippy --locked --offline --test governance -- -D warnings
cargo fmt --all -- --check
node --check tests/sdk/live-agent.mjs
node tests/sdk/agent-vectors.mjs
```

For the final combined run, set `RUST_MIN_STACK=8388608` and replace the
`sql_failure::environment` filter with `sql_failure` in the command above.

The broader `sql_failure` filter also selects three existing compensation
cases, beyond the eleven original forward SQL fault cases and six new cases.
Its [first default-stack run](regression-default-stack-failed.log) aborted with a
stack overflow in
`compensation_sql_failure_witness_quarantines_stale_inverse_authority`, after two
other compensation cases passed and before the new cases ran. That failed run
does not qualify the combined corpus. The six-case focused result above uses
the default test-thread stack.

## Scope

The external writer is protected fixture administration; the evidence provider
and enrollment are generated fixtures. PostgreSQL peer maps share one host UID.
The observer is separate code/connection, not an independently administered
service or independent implementer. No production writer coverage, physical
restore, separate-account containment, dependency-wide atomicity, new policy or
suspension semantics, terminal queried-no-effect barrier, comparative advantage
or general violation rate is established. Those remain separate N1/deployment,
protocol or M9 gates.
