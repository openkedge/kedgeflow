# Gateway, SQL and worker readiness — 2026-11-01

This increment extends the monitor-only readiness contract to the gateway, SQL
target, recovery and supervision, and closes the shared listener's shutdown
acceptance gap. It is bounded native source/runtime evidence. Installed Linux
monitoring, production deployment and the complete operations gate remain open.
See [SERVICE_OPERATIONS.md](../../../docs/SERVICE_OPERATIONS.md) for configuration
and semantics, and [PRODUCTION_READINESS.md](../../../docs/PRODUCTION_READINESS.md)
for the remaining release work.

## Changes exercised

Gateway monitoring uses its running ledger, tools and grant verifier. It verifies
the installed record with independent installation-key pins, compares gateway
identity/component and issuer/tool bindings, and checks live control, current
acknowledgement and configured native reservation state. Separately enrolled,
protected monitor clients request fresh broker and SQL-target reports. Exact
origin/path, profile, role, check-set completeness/uniqueness, HTTP consistency,
clock freshness and no-store behavior are enforced; no healthy result is cached.
Missing dependencies remain unverified. Test application authentication,
exchange and dispatch methods panic if called during probing.

The SQL target reports separate executor and query catalog prerequisites using
the running store and its configured kernel peer pin. Withdrawing executor
login produces an unready execution report while authenticated query access
continues. Regrant restores readiness. Complete resource/fence and outcome table
inventories remain unchanged. Wrong query credentials and wrong kernel peer
refuse; generated monitor and agent mTLS identities remain distinct.

Recovery probes guarded ledger reads and its running authenticated query client.
A random missing-attempt lookup on the SQL query-only contract can establish
query availability without creating an attempt, receipt or effect. That missing
reply is never fed into original-attempt resolution or treated as no-effect
evidence. Unsupported providers stay unverified and do not query a real attempt.
Recovery remains available after execution expiry, stop and revocation, but
refuses a stale restore head. Supervision additionally checks protected current
delivery material and a fresh collector observation. Material custody does not
prove that the collector will accept a reporting token.

Workers can explicitly configure a separate protected mTLS monitor listener.
Preflight and one-page mode do not listen. The listener checks the exact monitor
identity and stops with the worker. The shipping recovery binary was exercised
with unavailable reserved fixture origins: it reported unready only to the
monitor, denied the agent, and exited normally on SIGTERM within its bounded
query-page drain. The existing shipping collector process case passed too.

On shared-listener shutdown, the listening socket closes immediately. New work
on existing keep-alive connections gets 503/no-store. A probe already in progress
cannot finish with a healthy reply after drain begins. Previously admitted work
retains the existing bounded completion window; ambiguous attempts remain held.

## Verification

- **193 Rust cases passed**, with no ignored or skipped cases: 189 in the
  affected library/integration suites and four exact native readiness cases.
- **23 peer-authenticated PostgreSQL qualification groups passed**, including
  the existing transaction/replay/guard/restart/role-separation and inverse cases.
- Workspace/all-targets clippy with the pilot feature and warnings denied,
  Cargo formatting and diff whitespace checks passed.
- Frozen whitepaper verification passed: 58 files and 24 contract pins unchanged.

`tests.log` contains the complete affected run and SQL qualification summary.
`native-tests.log` contains the exact managed-state/gateway/read-only cases.
`clippy.log` and `checks.log` retain static verification. `source.json` and
`source.tar.gz` bind implementation, tests, fixtures, configuration, contracts,
deployment guidance and runner inputs. `summary.json` records counts and limits;
`artifacts.sha256.json` binds every record artifact except itself.

The temporary PostgreSQL installation initially lacked initialization files.
Its 744-file installation inventory was verified against the retained local
runtime cache; 734 missing files were restored without replacing differing
files. `runtime.json` retains that restoration report. The final run used actual
PostgreSQL 18.3 with peer HBA/ident and private Unix sockets. This repair changed
only the disposable test runtime. Earlier fixture/debug failures are excluded
from passing evidence.

Reproduce with Rust, the locked dependencies and PostgreSQL 18.3/etcd 3.6.5:

```sh
ETCD_BINARY=/path/to/etcd python3 scripts/test-postgres.py \
  --bindir /path/to/postgres/bin --peer --command scripts/start-etcd.sh -- \
  cargo test --locked --lib --test operations --test operations_process \
  --test operations_client --test operations_worker --test postgres_target \
  --test postgres_peer --test operational_custody --test service_custody \
  --test outcome_report --test recovery --test supervision --test restore \
  --test ledger --test broker_authorization --test broker_service --test control \
  --test managed_gateway --test identity_refresh --test exchange_identity \
  --test config --test transport -- --nocapture --test-threads=1
ETCD_BINARY=/path/to/etcd scripts/start-etcd.sh -- cargo test --locked \
  --test governance readiness:: -- --nocapture --test-threads=1
cargo clippy --locked --workspace --all-targets --features selfhosted-pilot-tests -- -D warnings
cargo fmt --all -- --check
python3 scripts/verify-whitepaper.py
```

The runners reap their fixture children and remove temporary stores and generated
credentials. No external deployment, provider or user account was changed.

## Limits

This run used macOS ARM64, Rust 1.98.0, generated software mTLS identities and
same-host loopback etcd/Unix-socket PostgreSQL. SQL roles shared one fixture OS
UID; this is not independent service-account isolation. Combined gateway tests
use real signed native control and software upstream reports; they do not
establish a full live production topology. No Linux bundle was rebuilt here;
the earlier retained executable archive predates readiness and ledger-token
renewal. Linux-installed monitoring, real provider monitor enrollment, PKI and
credential publication/rotation, metrics/alerts, workload SLOs, physical restore,
upgrades, MSRV 1.88, independent reproduction and owner acceptance remain open.
