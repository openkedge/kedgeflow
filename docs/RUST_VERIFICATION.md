# Rust integration verification — 5 October 2026

The runtime port is `d481650`, based on the whitepaper execution prototype at
`517dc9d` and the preserved repository contracts at `8c07a55`. The following review
iteration adds rollout tests, fixes inherited specification-tool lint, and records
the checks. Generated schemas and published fixture envelopes are unchanged.

| Check | Observed result |
|---|---|
| Rust integration/unit tests | 52 passed; required etcd and SDK modes enabled; no skips |
| Real authority store | etcd 3.6.5, three Raft members on one host; 256 claim contenders across eight roots, 96 contenders through three member endpoints, replacement/claim and policy/ownership races |
| Full mock execution path | Actual TLS broker and fenced target; confirmed effect, stale-state refusal, lost-response unknown, conserved consumption |
| Identity and transport | Ed25519 access-token/DPoP negatives and replay; actual TLS 1.3 client enrollment, wrong roots/chains, endpoint/Origin refusal, redirects and deadlines |
| Grant carriage | Inline/reference shared claim; a large signed envelope refused inline and executed through a bound reference once; lookup scope, encoding, size and timeout bounds |
| Credential exchange | Subject/actor/grant/attempt fields, assertion deadline, overbroad token lifetime refusal and oversized valid-prefix refusal |
| Native CLI | Build/help and configuration check using generated local trust material; no remote probe or public authority issuance |
| Optimized executable | Release build and `kf-proxy --help` pass; local toolchain lacks `libLLVM.dylib` for its optional symbol-stripping step, so that step emitted a warning |
| Official MCP client | Unmodified `@modelcontextprotocol/client` 2.3.0, Node 25.2.1, protocol 2026-07-28: discovery, catalog, remediation, signed-fixture retry, terminal result and replay refusal |
| Rust quality checks | Formatting and clippy with warnings denied pass |
| Python compatibility | 24 tests pass; both existing demo scripts complete |
| Specification harness | Thirteen Ed25519 envelopes, semantic fixture bindings, OAuth/DPoP vectors, descriptor YAML and Agent2Agent reference pass |
| Schema regeneration | Normative `spec/kedgeflow.schema.json` remains byte-identical after regeneration |
| Python quality checks | Ruff passes; mypy reports no issues in 22 source files |

Rust 1.98.0 / Cargo 1.98.0 executed these checks on macOS ARM64. The locked
dependencies declare minimum Rust versions at or below 1.88; a separate 1.88
compiler run was not performed. Python 3.13 ran compatibility/specification checks
from an isolated temporary environment assembled from locally cached packages.
The cluster used the official etcd 3.6.5 embedded server as temporary test
infrastructure; no Go runtime source was added to the Rust repository.

The SDK test uses explicit synthetic authentication and broker ports over loopback;
cryptographic authentication and real authenticated outbound transport are separate
checks. Generated software certificate fixtures establish mechanics, not production
enrollment. The full-path target supplies a mock atomic version/fence/mutation
primitive; it is not a Kubernetes, SQL or SaaS adapter.

## Reproduce

```sh
npm ci --prefix tests/sdk
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --bin kf-proxy
cargo build --locked --release --bin kf-proxy
python -m pip install -e '.[dev,spec]'
pytest
python spec/validate.py
python spec/build_schema.py
git diff --exit-code -- spec/kedgeflow.schema.json
ruff check .
mypy src
```

Raw results are retained under [`results/verification`](../results/verification).
The single-host results do not establish cross-vendor interoperability, distributed
availability or performance, production issuer/store enrollment and RBAC, target
writer coverage, native OS containment, hardware human review, saga recovery or
legacy compensation legality. The Docker recipe and remote CI workflow were not
executed locally. Deployment gates remain in [the gateway guide](RUST_GATEWAY.md).
