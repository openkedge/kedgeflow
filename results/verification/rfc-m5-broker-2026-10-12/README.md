# M5b broker authorization prerequisite — 12 October 2026

Based on `973a510` and 156 final source hashes in [summary.json](summary.json).
The trusted library implements [RFC 0019](../../../docs/rfcs/0019-broker-authorization.md);
see the [integration guide](../../../docs/BROKER_AUTHORIZATION.md).

| Check | Result |
| --- | --- |
| Required Rust workspace/native suite | 194 passed across 32 binaries; zero failures, ignored cases or skips |
| New broker cases | 11 real-etcd authorization/schema/fault cases |
| Clippy / formatting / whitespace | Pass; warnings denied |
| Node vectors | Pass |
| Frozen white paper | 58 files and 24 pins unchanged |
| Frozen fixtures | 13 signed envelopes and declared bindings pass |

Independent authorizers race the original recorded claim: one permit is returned,
and repeated/recreated authorization refuses. Unclaimed/unrecorded/foreign attempts,
wrong gateway, target widening, wrong independent issuer key, signed-request
substitution, provider identity/workload/confirmation/delegation/scope substitution,
tool/incarnation/contract changes and invalid provider expiry refuse. Verification
failure/delay and shorter actor lifetime are enforced. Current policy/ownership,
revocation, required control, dispatch/terminal state, corrupt context and restore
quarantine refuse. A paused permit write loses to intervening root revocation.
A successful write with a lost reply leaves a retained permit but returns no
authorization; retry refuses. A successful reply after expiry also refuses.
Store outage has no local fallback. Consumption remains held.

Tests use real same-host three-member etcd, generated certificate workload
contexts, trusted software provider identities, a native loopback transaction
fault proxy and deterministic trusted clocks. There is no native broker endpoint,
real subject/actor token verification, minted credential, target effect, actual
AS/SVID lifecycle or production custody/RBAC claim. The existing one-resource
node/version FencingToken leaf is the only accepted binding. CTD-driven SQL,
provider verification/minting and enterprise integration remain open.

During qualification an existing witness-startup failure exposed a released-port
allocation race. The fixture now serializes startup through health readiness,
reserves both ports until launch and includes witness logs on failure. All ten
separate-witness restore cases pass in the final required run. The permit tests
do not establish combined production witness/broker deployment.

The full final output is in [rust-tests.log](rust-tests.log); source/tool/archive
pins, named cases, repairs and limits are in the summary. Earlier retained
evidence is unchanged. [Remaining enterprise inputs and gates](../../../docs/ENTERPRISE_QUALIFICATION.md)
make the next M5c–M9 qualification explicit.

## Reproduction

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
PYTHONPATH=src python scripts/verify-whitepaper.py
PYTHONPATH=src python spec/validate.py
```

Executed on Darwin ARM64, Rust 1.98.0, Node 25.2.1 and etcd 3.6.5.
Minimum Rust 1.88 and Node 20 remain execution-unqualified.
