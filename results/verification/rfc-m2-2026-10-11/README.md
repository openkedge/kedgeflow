# M2 library verification — 11 October 2026

Working-tree implementation based on `769c0a8`; hashes and tool versions are
retained in [summary.json](summary.json). The earlier disk-space block is resolved.

| Check | Fresh result |
| --- | --- |
| Locked Rust workspace, all targets | **69 passed**, zero failed/ignored/skipped |
| Required backing services | Real three-member etcd 3.6.5 and pinned official MCP SDK |
| Issuance library cases | 8 passed, including 16 concurrent fresh-root candidates and consumed retry |
| Admission/input-chain cases | 9 passed, including real-etcd issuance/claim/reuse and all 13 frozen vectors |
| Clippy | Pass with `-D warnings` |
| Python suite | **32 passed** |
| Frozen white paper | Pass: 58 files and 24 contract pins unchanged |
| Existing schema/fixture conformance | Pass: all 13 signed record kinds and declared bindings |
| Formatting and whitespace | Pass |

Logs: [Rust workspace](rust-tests.log), [issuance](issuance.log),
[admission](admission.log), [clippy](clippy.log), [Python](python-tests.log),
[white paper](whitepaper.log), [schemas](schema.log).

The final workspace run includes both new test suites after full certificate and
grant schema validation was added. The earlier isolated issuance log records its
eight cases before that schema extension; the final workspace log is authoritative
for the final source. The admission log records its final nine test cases.

## Reproduction

Use the locked dependency graph, Rust 1.98 used for this run, etcd 3.6.5 and the
repository's SDK lockfile. The host was macOS on ARM64. The system Bash 3.2 empty
array issue in `scripts/start-etcd.sh` was corrected; its disposable cluster cleanup
also ran successfully. No frozen artifact files or published paper results changed.

```sh
npm ci --prefix tests/sdk --ignore-scripts --no-audit --no-fund
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python -m pytest -q
python scripts/verify-whitepaper.py
python spec/validate.py
```

This run reused the installed Rust toolchain and local Cargo target/cache paths
under `/private/tmp`. Python ran through `.venv/bin/python` with `PYTHONPATH`
including `src` and the already provisioned fixture-validation dependencies in
`/private/tmp/kedgeflow-review-20261010-deps`. A clean environment should provision
the Python dependencies declared in the repository first.

The etcd ARM64 archive was downloaded from the
[official v3.6.5 release](https://github.com/etcd-io/etcd/releases/tag/v3.6.5)
and checked against its published SHA-256
`14d7743f9ed07950a8e85491646e067e394a09e049e42083e2f6473fefa717a8`.
The JSON Schema validator is pinned to 0.58.6 with default features disabled and
a retriever that denies every external URI; local schemas enforce formats.
See its [configuration documentation](https://docs.rs/jsonschema/latest/jsonschema/).

## Scope and remaining gates

M2a's library checks now pass. M2b's input-chain library verifies signed proposals,
descriptors, manifests and evidence against role/workload/configuration pins,
closed schemas, exact state/parameter bindings and freshness. Server-selected
ternary evidence predicates must be satisfied. The stronger issuer API binds
certificate constraints/discharges to those opaque inputs and persists one
allowance through the existing atomic ledger.

Synthetic identity and signing fixtures establish software mechanics. The tests
do not establish enterprise enrollment, target truth, deployed writer coverage,
global fence allocation, a public admission/issuer service or policy evaluation.
Policy/descriptor/obligation pins still come from trusted authority configuration;
installed-control ingestion is not implemented. Existing SDK tests still obtain
fixture grants, so the live client admission path remains M3 work.

Next M2b work is Cedar over verified server inputs, certificate production,
authenticated admission/issuer services and issuer-owned identifiers/fences.
M2c adds authorized publish/register/install/revoke operations. Minimum Rust
version qualification and independent paper reproduction remain M0 follow-ups.
The full M2 milestone is still in progress.
