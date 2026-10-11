# M2c administrative control verification — 11 October 2026

This increment follows committed service checkpoint `7405545`. The bounded
administrative lifecycle is implemented under a separate draft profile. Owner
acceptance and enterprise deployment qualification remain open; M3 is next.
Source and log hashes are recorded in [summary.json](summary.json).

| Check | Result |
| --- | --- |
| Locked Rust workspace, all targets | **93 passed**, zero failed/ignored/skipped |
| Required infrastructure | Three real etcd 3.6.5 members; official MCP SDK 2.3.0 |
| Administrative lifecycle suite | **8 passed**, including native TLS, gateway renewal and combined admission/issuance |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema and signed fixtures | 13 envelopes and declared bindings pass |

Logs: [workspace](rust-tests.log), [final governance suite](governance.log),
[public example](example.log), [clippy](clippy.log),
[white paper](whitepaper.log), [schema](schema.log).
Trailing whitespace and final blank lines are normalized for repository review.
The full workspace pass preceded stronger legacy issuance/replacement refusal
assertions; all eight governance tests then passed again. The public example was
rechecked after role-specific credential paths changed. These reruns are subsets
of the 93 cases, not additional distinct tests. Initial template test failures
were corrected by provisioning the newly required local enrollment material;
no authority checks were relaxed.

## What this establishes

`kf-governance` authenticates fixed-scope administrative roles with native mTLS,
pinned access tokens, DPoP and separate signed-record keys. Closed typed payloads
and an embedded draft schema reject unknown fields, unsupported profiles, wrong
roles, tenants and workload assignments. Schema references cannot retrieve
caller-selected files or URLs. Administrative operations are separate from agent
admission/issuance. A public operator registration can be computed without
private files or network access.

Signed policy and descriptor publication precede expected-revision installation.
Installation establishes a permanent managed marker. Missing, expired or older
revision acknowledgements refuse authority. Native gateway configuration verifies
the coordinator signature and its actual tool, audience and issuer keys before
signing acknowledgement; renewal persists a fresh bounded record. This covers
only gateway control checks. It does not attest target guards or writer coverage.

Authority transactions compare installed scope, policy, ownership, trust,
acknowledgement and revocation absence in the same etcd CAS as admission,
allocation, issuance, claim and final dispatch authorization. Duplicate issuance
checks the original persisted root/grant. Managed domains reject legacy direct
issuance, unallocated issuance, replacement and grant-shaped control publication.
Unmanaged historical fixtures remain supported explicitly.

Native admission/issuer tests refuse before installation/acknowledgement, then
produce a valid grant and retained claim when control is ready. Domain, root and
grant revocation tests retain consumed attempts and exercise races with issuance,
claim and dispatch authorization. A transition authorized before revocation may
already send; revocation does not retract effects or refund consumed allowance.

## Reproduction and limits

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --test governance -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python scripts/verify-whitepaper.py
python spec/validate.py
```

Host: macOS ARM64, Rust/Cargo 1.98.0. The declared Rust 1.88 minimum is not
execution-qualified. No dependency or lockfile changes were needed. Cargo used
cached dependencies and target paths under `/private/tmp`. The already verified
official etcd archive SHA-256 is
`14d7743f9ed07950a8e85491646e067e394a09e049e42083e2f6473fefa717a8`.
Three disposable loopback members ran in required mode with owned cleanup.
Freeze/schema commands used the existing Python environment and dependency cache.
The unchanged Python runtime's prior **32 passing tests** remain historical;
its full suite was not repeated.

Enrollment certificates and keys are software fixtures. The gateway configuration
case uses a TLS intermediary forwarding authenticated requests to actual etcd;
it checks pinned transport/token carriage, not production etcd RBAC provisioning.
Fixed operator-approved policy/descriptor/trust snapshots and one required gateway
are supported. Production enrollment/key lifecycle, shared DPoP replay,
multi-component coverage, clock uncertainty, counter bootstrap, legacy migration,
restore barriers and real target effects remain unqualified.

The official MCP test still uses fixture grants. The combined native service test
does not establish an actual supported Agent Adapter → gateway → target path.
[M3](../../../docs/IMPLEMENTATION_ROADMAP.md) must align control/gateway delegation,
acquire fresh admission/issuance through a real client, and resolve the original
persisted attempt after lost responses without additional claims or effects.
See [RFC 0007](../../../docs/rfcs/0007-enforcement-control-http.md) and the
[operator guide](../../../docs/GOVERNANCE_SERVICE.md).
