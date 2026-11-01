# Core service material custody

Observed on Darwin ARM64, Rust 1.98.0, etcd 3.6.5 and PostgreSQL 18.3.
Status: **passed bounded service custody checks**. This is same-UID software
evidence. Linux account isolation, systemd deployment and production readiness
remain open.

The shipping gateway, control and broker accept `--custody-root`, consume checked
descriptor bytes for configuration/keys/TLS, and propagate the policy into
restore-witness clients. Live gateway assertions/acknowledgements and broker
head/snapshot reads keep the startup root. Tests observe unsafe-file refusal,
atomic replacement, normal renewal and original-claim conservation. Protected
control CLI enrollment methods also propagate the selected policy; registration
printing reads only the protected configuration. The existing SQL target API
reexports the extracted shared reader.

[summary.json](summary.json) lists 126 unique Rust cases and 23 PostgreSQL peer
groups. The main run observed 124 Rust cases; subsequent targeted runs exercised
the expanded broker nested-witness/static checks, one live gateway acknowledgement
case and one protected SQL target commit/query case. Complete command stdout was
not retained; these counts summarize observed command results. The archive and
file hashes retain the tested runtime inputs, not production credentials.

Run from the repository root with the declared Rust toolchain and etcd binary:

```sh
ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --offline \
  --test custody --test service_custody --test config --test auth \
  --test exchange_identity --test broker_authorization --test broker_service \
  --test identity_refresh --test keycloak_pilot --test control --test restore \
  -- --nocapture --test-threads=1

ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --offline --test governance \
  native_gateway_configuration_verifies_and_renews_installed_acknowledgement \
  -- --nocapture --test-threads=1

python3 scripts/test-postgres.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --peer --command cargo test --locked --offline --test postgres_target \
  shipping_sql_custody_checks_and_retained_startup_snapshot \
  -- --nocapture --test-threads=1

cargo clippy --locked --offline --workspace --all-targets \
  --features selfhosted-pilot-tests -- -D warnings
cargo fmt --all -- --check
python3 scripts/verify-whitepaper.py
```

All checks above passed, including unchanged 58 frozen files / 24 contract pins.
The offline commands require the locked dependency cache. The etcd wrapper sets
`KF_REQUIRE_ETCD=1`; required native services were present, with no silent skips
in the selected cases. No Linux, provider-container or full historical M8 rerun
is claimed by this increment. Root README and prior verification records remain
unchanged. See [service custody](../../../docs/SERVICE_CUSTODY.md) and the
[production worklist](../../../docs/PRODUCTION_READINESS.md).
