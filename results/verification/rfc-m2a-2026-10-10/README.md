# RFC / M2a verification — 10 October 2026

Working-tree increment based on `769c0a8`. This is not a completed M1/M2 exit gate.

The disk block recorded here is historical. See the
[11 October rerun](../rfc-m2-2026-10-11/README.md) for executed real-etcd/runtime
tests and the subsequent input-chain increment. Preserve these earlier results
as the record of what was verified on 10 October.

| Check | Result |
| --- | --- |
| Rust formatting and whitespace | Pass |
| Frozen white paper verification | Pass: 58 files, 24 contract pins |
| Existing schema/fixture conformance | Pass: 13 signed record kinds and declared bindings |
| New draft schema | Pass: Draft 2020-12 meta-schema; 7 operation shapes; 14 closed/required-field refusals; status correlation |
| Current production Rust library | Metadata-only compilation passes with Rust 1.98 and local dependency artifacts |
| New issuance test source | All 8 tests type-check; execution is not established by this check |
| Locked Cargo build / test execution | Blocked by disk exhaustion; library archive and development dependency unpacking failed |
| Python suite rerun | 27 passed; 5 fixture-copy setup errors from disk exhaustion; not a full pass |

The Rust test source covers four local validation checks and four real-etcd
checks: 16 concurrent fresh-root candidates converge on one allowance; consumed
authority is not reopened; cross-domain rebinding refuses; stale policy blocks
creation/reuse; changed certificates conflict and separately admitted operations
remain independent. These behaviors are **test expectations**, not executed
results. `KF_REQUIRE_ETCD=1` prevents the real-etcd cases from silently skipping.

The [metadata command record](rust-metadata.json) captures exact arguments, source
hashes and local dependency artifact hashes. This is a limited compiler check;
it does not replace a packaged locked build, runtime tests, clippy, minimum Rust
version qualification or enterprise interoperability testing. No production
admission/issuer endpoint is advertised by this increment.

After making build space available, run the focused gate first:

```sh
cargo fmt --all -- --check
ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --test issuance -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
python scripts/verify-whitepaper.py
python spec/validate.py
python -m pytest -q
```

The existing complete runtime/SDK gate remains in the repository README. Passing
the focused gate completes verification of this library increment only. M2b still
requires raw chain validation, Cedar and authenticated live services; M2c requires
authorized publication/installation/revocation and race qualification.
