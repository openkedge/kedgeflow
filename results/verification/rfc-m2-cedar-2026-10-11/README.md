# M2b Cedar and certificate verification — 11 October 2026

This increment follows committed RFC/input-chain checkpoint `733febf`. Source
and log hashes are in [summary.json](summary.json). M2 remains in progress.

| Check | Result |
| --- | --- |
| Locked Rust workspace, all targets | **78 passed**, zero failed/ignored/skipped |
| Required backing services | Three-member real etcd 3.6.5 and pinned official MCP SDK |
| Admission cases in final workspace run | **18 passed**, including Cedar and durable certificate production |
| Clippy | Pass with `-D warnings` |
| Frozen white paper | 58 files and 24 contract pins unchanged |
| Frozen schema/fixtures | All 13 signed records and declared bindings pass |
| Formatting and patch whitespace | Pass |

Logs: [workspace](rust-tests.log), [clippy](clippy.log),
[white paper](whitepaper.log), [schemas](schema.log). The earlier isolated
[admission run](admission.log) has 17 cases before the final certificate
freshness-boundary case was added; the final workspace run is authoritative.
Captured logs have trailing blank lines removed for repository formatting.

## What this establishes

The verified input library now recomputes required predicate and obligation
definition pins, including provider keys, schemas and freshness rules. A draft
Cedar ABI accepts authority-constructed verified context only. Exact source/ABI
pins, strict schema validation, default deny, forbid precedence and refusal on
any runtime diagnostic are exercised. A permit alongside an arithmetic evaluation
error still refuses. Input-role keys cannot sign produced certificates.

Certificates copy verified scope and discharge references/times, fix one attempt
and no lease/saga, and intersect verified freshness with installed policy TTL.
Expired candidates refuse before ledger access. Sixteen concurrent preparations
with distinct certificate IDs return one persisted signed certificate. A later
unchanged retry returns exactly that certificate without extending its expiry;
an expired original stays retained and cannot be refreshed under the same qid.
Freshly satisfied but changed evidence conflicts. Policy and ownership changes
are tested independently and block both duplicate return and fresh creation.

The resulting produced certificate passes independent issuer verification,
atomic issuance, one claim and unchanged consumed retry. These remain trusted
library calls, with synthetic identities and software signing fixtures. Tests
do not establish live admission/issuer endpoints, enterprise enrollment, deployed
writer coverage, target truth, installed-control ingestion, or issuer-owned grant
ID/fence allocation. The official MCP SDK path still uses fixture grants.

## Reproduction

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python scripts/verify-whitepaper.py
python spec/validate.py
```

Host: macOS ARM64, Rust 1.98. The lockfile resolves compatible dependencies for
the declared Rust 1.88 minimum; execution on Rust 1.88 is still unqualified.
Cedar is pinned to **4.7.1**, the newest available release compatible with that
minimum. All Cedar extensions are disabled. Cargo used existing cache/target
paths under `/private/tmp`. No existing locked package versions were removed or
updated; 76 transitive packages were added. See
[Cedar crate metadata](https://docs.rs/crate/cedar-policy/4.7.1) and
[authorization diagnostics](https://docs.cedarpolicy.com/auth/authorization.html).

etcd is the same verified [official 3.6.5 release](https://github.com/etcd-io/etcd/releases/tag/v3.6.5)
used at the prior checkpoint: archive SHA-256
`14d7743f9ed07950a8e85491646e067e394a09e049e42083e2f6473fefa717a8`.
It ran as a disposable three-member loopback cluster, with required mode and
owned cleanup. Python fixture/freeze checks used `.venv/bin/python` and the
existing validation dependencies in `/private/tmp/kedgeflow-review-20261010-deps`
with `PYTHONPATH=src:/private/tmp/kedgeflow-review-20261010-deps`.
The prior checkpoint's **32 passing Python tests** remain historical evidence;
the Python implementation was unchanged and its full suite was not repeated here.

Next: authenticated admission/issuer service composition with installed-state
and durable chain lookup, then issuer-owned grant IDs and target fence allocation.
RFC 0002 control publication/install/revoke and the full M2 service exit tests
remain open. See [RFC 0005](../../../docs/rfcs/0005-cedar-leaf-admission.md) and
the [milestone plan](../../../docs/IMPLEMENTATION_ROADMAP.md).
