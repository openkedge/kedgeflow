# Monitored service readiness — 2026-11-01

This increment adds opt-in readiness monitoring to control, broker, governance
and receipt-collector services. It does not close the complete production
operations gate. See [SERVICE_OPERATIONS.md](../../../docs/SERVICE_OPERATIONS.md)
for the launch flags, response contract and role-specific semantics.

## Observed behavior

The exact configured monitor SPIFFE identity can issue an empty GET over the
existing service mTLS listener. Wrong identity, no certificate, Origin, alias
Host, query, body and method cases refuse before calling the probe. Monitoring
cannot shadow an application path or use another origin. Protected launchers
refuse overlap with their configured application workloads. Probe concurrency
is one per endpoint and the complete probe deadline is five seconds; responses
are no-store and contain no credential/error text. The original application
route still works. Unverified and unavailable prerequisites return HTTP 503.

Native managed tests exercise absent installation, absent acknowledgement,
successful installation/acknowledgement, acknowledgement expiry and renewal,
reservation stop, domain revocation and an actual captured earlier restore
marker. Execution prerequisites become unready after expiry/stop/revocation,
while administration and receipt collection remain usable. A mismatched restore
head blocks all four roles. Repeated probes leave the complete namespace's
key/value/modification-revision inventory and witness head unchanged. Test
identity verification and mint methods panic if called, so probing cannot
quietly exercise those authority-producing paths.

Plain-leaf control additionally accepts an explicit `operations_scope` bound to
the configured gateway audience and descriptor digest; current installation,
policy, ownership and acknowledgement still govern the live result. Missing
scope selection reports unverified, mismatched pins refuse, and present null,
malformed or unknown top-level scope fields refuse decoding. Broker material
checks observe current snapshot/key intervals and signed live head consistency
without obtaining subject or actor tokens. Unknown provider readiness remains
unverified.

The shipping `kf-outcomes` process was launched in protected managed mode with
generated credentials and two reserved, deliberately unaccepted loopback
authority origins. It listened but returned a typed unavailable readiness
report only to the enrolled monitor; the agent received 403. After the process
stopped, a new readiness request failed. No authority received a transaction in
that process test.

## Verification retained

- **162 distinct Rust cases passed**, with no skipped or ignored cases:
  158 across the affected library/integration suites, three exact native
  governance readiness cases, and one shipping-process case.
- The three monitor transport/configuration tests were rerun after bounding the
  test's own wait. They are included once in the distinct-case count above.
- Workspace/all-targets clippy with the pilot feature and warnings denied,
  Cargo formatting and diff whitespace checks passed.
- Frozen whitepaper verification passed: 58 files and 24 contract pins unchanged.

`tests.log`, `governance-tests.log`, `process-tests.log`, `http-tests.log`,
`clippy.log` and `checks.log` retain those observations. `source.json` and
`source.tar.gz` bind the current implementation, test/fixture, configuration,
contract and documentation inputs. `summary.json` records scope and counts;
`artifacts.sha256.json` binds every record artifact except itself.

With Rust and etcd 3.6.5 available on a non-root Unix host, reproduce using:

```sh
ETCD_BINARY=/path/to/etcd scripts/start-etcd.sh -- cargo test --locked --lib \
  --test operations --test operational_custody --test service_custody \
  --test outcome_report --test recovery --test supervision --test restore \
  --test ledger --test broker_authorization --test broker_service --test control \
  --test managed_gateway --test identity_refresh --test exchange_identity \
  -- --nocapture --test-threads=1
ETCD_BINARY=/path/to/etcd scripts/start-etcd.sh -- cargo test --locked \
  --test governance readiness:: -- --nocapture --test-threads=1
cargo test --locked --test operations_process -- --nocapture
cargo clippy --locked --workspace --all-targets --features selfhosted-pilot-tests -- -D warnings
cargo fmt --all -- --check
python3 scripts/verify-whitepaper.py
```

The fixture reaps its own process/witness/etcd children and removes temporary
credentials and stores. No external deployment or provider was changed. Earlier
fixture/debug failures are excluded from passing evidence.

## Open requirements

This is native macOS ARM64/Rust 1.98.0 evidence with generated test identities and
loopback real-etcd authority. It does not qualify actual provider-issued monitor
credentials, CA/monitor revocation, deployed HTTPS ledger renewal, installed
Linux monitoring, gateway upstream dependencies, SQL-target or recovery status,
metrics/alerts, workload capacity, full deployed bypass/egress, physical storage
recovery, upgrades, independent reproduction, MSRV 1.88 or owner acceptance.
The retained Linux executable bundle predates both this increment and ledger
credential renewal; it has not been rebuilt here. Probe success establishes
local read-only prerequisites and creates no execution authority or guarantee
that a future request will succeed. Production readiness remains open in
[PRODUCTION_READINESS.md](../../../docs/PRODUCTION_READINESS.md).
