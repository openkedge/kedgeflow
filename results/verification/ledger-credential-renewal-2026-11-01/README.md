# Protected ledger credential renewal — 2026-11-01

This source increment removes the startup-only etcd token from protected core
and operational service loaders. It is bounded same-host software evidence,
not a new Linux release or production acceptance.

## Behavior and scope

`EtcdLedger::with_auth_token_file` validates the current file locally, then keeps
the protected `ServiceFiles` root and path. Each transaction reloads and validates
the current token; no prior token is cached as fallback. Token acquisition,
transport and response consumption share one five-second deadline. Tokens are
sensitive HTTP headers and are never printed. Acquisition or auth failure does
not trigger a mutation retry or automatic password authentication.

Gateway execution and acknowledgement renewal, control, broker, collector,
governance, recovery/supervision and restore operator loaders use this source,
including their independent restore-witness clients. Legacy unprotected and
explicit static-token library calls retain their snapshot behavior. Other
physical/family/operator loaders outside the managed package retain static
sources and their separate credential procedures.

## Observed verification

The new Unix library tests start their own disposable etcd 3.6.5 processes;
authentication is never enabled on the shared three-member test cluster.
Namespace-scoped service roles and two independent endpoints exercise:

- Real token expiry, with a static client as a refusing negative control.
- Atomic primary-token replacement while the expired witness still refuses;
  witness replacement then permits the same running client and its clone to
  look up the original consumed attempt.
- Missing files, widened secret modes, outside-root symlinks, empty/non-UTF8/
  oversized/header-invalid contents, with no cached fallback.
- Actual etcd RBAC denial outside the namespace, role withdrawal and fresh-token
  refusal, followed by regrant and original-attempt lookup. Renewal and reads
  leave the retained restore head unchanged.
- A real accepted create-only CAS whose successful reply is withheld by a relay.
  The relay publishes a renewed credential and returns HTTP 401. The client sends
  one mutation request and returns unavailable. A later explicit create-only
  operation refuses replacement of the consumed original.

The complete affected run passed **141 Rust cases**, with no ignored or skipped
cases: all library tests plus broker authorization/service, control, ledger,
identity refresh, managed gateway, operational custody, outcome report, recovery,
restore, service custody and supervision suites. Workspace/all-targets clippy
with the pilot feature and warnings denied passed. Cargo formatting and the
frozen whitepaper verifier passed (58 files, 24 contract pins unchanged).

`tests.log`, `clippy.log` and `checks.log` retain the results. `source.json` and
`source.tar.gz` retain and hash the Rust/config/spec/fixture inputs and relevant
documentation/CI. `summary.json` gives machine-readable scope and counts;
`artifacts.sha256.json` binds record artifacts except itself. The etcd fixture
uses the [official v3 JSON gateway authentication API](https://etcd.io/docs/v3.6/dev-guide/api_grpc_gateway/).

Reproduce on a non-root Unix host with Rust, the locked dependencies and etcd
3.6.5 available:

```sh
ETCD_BINARY=/path/to/etcd scripts/start-etcd.sh -- cargo test --locked \
  --lib --test operational_custody --test service_custody --test outcome_report \
  --test recovery --test supervision --test restore --test ledger \
  --test broker_authorization --test broker_service --test control \
  --test managed_gateway --test identity_refresh -- --nocapture --test-threads=1
cargo clippy --locked --workspace --all-targets --features selfhosted-pilot-tests -- -D warnings
cargo fmt --all -- --check
python3 scripts/verify-whitepaper.py
```

The tests reap their own etcd children and remove temporary stores/credentials;
the shared test wrapper also reaps its three members. No external host, account,
provider or deployment was changed.

## Remaining gates

This run used native macOS ARM64 Rust 1.98.0 and loopback HTTP etcd with simple
five-second test tokens. It does not qualify deployed HTTPS token publication,
etcd JWT mode, service certificate/CA rotation, credential publisher custody,
Linux installed renewal, AMD64, release CI or MSRV 1.88. The earlier Linux
operational bundle remains bound to its earlier source and must be rebuilt for
this change. Application readiness, live full Linux topology, independent
custody, storage recovery, upgrades, workload SLOs and owner acceptance remain
open in [PRODUCTION_READINESS.md](../../../docs/PRODUCTION_READINESS.md).
