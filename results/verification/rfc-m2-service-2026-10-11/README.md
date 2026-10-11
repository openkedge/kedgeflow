# M2b authenticated service verification — 11 October 2026

This increment follows committed Cedar/certificate checkpoint `3a90308`.
Source and log hashes are recorded in [summary.json](summary.json). The bounded
service increment is delivered; M2's control lifecycle exit gate remains open.

| Check | Result |
| --- | --- |
| Locked Rust workspace, all targets | **85 passed**, zero failed/ignored/skipped |
| Required infrastructure | Three real etcd 3.6.5 members and pinned official MCP client 2.3.0 |
| New control tests | **7 passed**, including six native TLS/etcd service cases and public operator configuration/pin output |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 file hashes and 24 mirrored contract pins unchanged |
| Frozen schema and signed fixtures | All 13 envelopes and declared bindings pass |

Logs: [workspace](rust-tests.log), [clippy](clippy.log),
[white paper](whitepaper.log), [schema](schema.log). Trailing whitespace and final
blank lines are normalized for repository review. The final full workspace run
includes the independent bound on operations that survive HTTP disconnect.

## What this establishes

`kf-control` serves two closed draft operations over the same native verified
mTLS transport as the gateway. Generated software certificates enroll a test
SPIFFE workload; pinned EdDSA access tokens and actual DPoP proofs authenticate
requests with distinct endpoint permissions and a shared delegation binding.
Wrong scopes, subjects, workload assignment, proof replay/URL, extra authority
fields and missing client certificates refuse. Administrative routes are absent.
Application responses are checked against the unchanged draft carriage schema.

Admission atomically stores the certificate and original signed evidence chain.
The test destroys the service instance, recreates it without operation memory,
and resolves unchanged admission/issuance from etcd. The issuer reloads and
reverifies retained signatures, bindings and freshness; damaged raw evidence
refuses before allocation. Certificate substitution and missing/stale control
state refuse. The fixture clock is fixed for deterministic validity checks;
existing admission/issuance tests separately exercise freshness boundaries.

Sixteen concurrent authenticated issue requests with new request IDs return
one exact signed grant, with one created response and fifteen reused responses.
The issuer generates IDs/nonces and reserves one fence for that operation. One
claim succeeds; subsequent issuance returns the original envelope, a second
claim is consumed, and the counter remains unchanged. A new admitted operation
in another conflict domain advances the same tenant/resource/incarnation
counter from one to two. Exhaustion at the safe-integer maximum refuses.
The public example's computed pins match the signed test descriptor; conflicting
record roles and unknown configuration fields refuse. `--print-pins` succeeds
with no private files provisioned and publishes nothing.

## Reproduction and limits

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python scripts/verify-whitepaper.py
python spec/validate.py
```

Host: macOS ARM64, Rust/Cargo 1.98.0. Execution on the declared Rust 1.88 minimum
remains unqualified. Existing locked dependencies, including Cedar 4.7.1, are
unchanged. Cargo used cached dependencies and target paths under `/private/tmp`.
etcd used the already verified official 3.6.5 release archive SHA-256
`14d7743f9ed07950a8e85491646e067e394a09e049e42083e2f6473fefa717a8`,
running three disposable loopback members with required mode and owned cleanup.
Python fixture/freeze commands used `.venv/bin/python` and the existing packages
in `/private/tmp/kedgeflow-review-20261010-deps`. The unchanged Python runtime's
prior **32 passing tests** are historical evidence; its full suite was not repeated.

These checks establish service mechanics with software keys and generated
enrollment. They do not establish enterprise trust provisioning, cross-replica
DPoP replay defense, production etcd TLS/RBAC administration, target fence
bootstrap/restore barriers or deployed writer coverage. Fences cover one
authority namespace and tenant/resource/incarnation. Legacy trusted issuance
and other authority prefixes do not automatically share this allocation.

Operator descriptor/provider/policy pins are static and compared with current
ledger policy/ownership. Authorized control publication/install/revoke and
installed-state ingestion remain **M2c**. The official MCP test still uses fixture
grants; a fresh Agent Adapter → control → gateway → target workflow and durable
attempt/status correlation remain **M3**. A real SQL target, recovery and
enterprise identity remain later gates. See [RFC 0006](../../../docs/rfcs/0006-leaf-control-http.md)
and the [plan](../../../docs/IMPLEMENTATION_ROADMAP.md).
