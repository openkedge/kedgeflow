# M4b4 operation control bindings — 11 October 2026

Based on `44c44c26398ccc3447d9877ca85d5541c3292ad4` plus working-tree source
hashes in [summary.json](summary.json). This qualifies the bounded software
increment in [RFC 0014](../../../docs/rfcs/0014-operation-control-bindings.md);
see [operator instructions](../../../docs/CONTROL_BINDINGS.md). M4/M5 enterprise
acceptance and production observer/ledger/clock custody remain open.

| Check | Result |
| --- | --- |
| Required workspace/native suite | 138 passed; zero failed, ignored or skipped; actual etcd and official SDK required |
| New cases | Five integration cases and one deterministic native ledger CAS test |
| Undispatched operation | Admission/issuance/claim bind head 4; query-only recovery seals original attempt; no dispatch binding |
| Dispatch authorization | Admission/issuance/claim bind head 4; renewed acknowledgement binds dispatch to head 5 |
| Renewal between admission and issuance | Admission binds head 4 and short acknowledgement; issuance/claim bind renewed head 5; dispatch binds head 6; old history-only verifier refuses while new per-phase verification passes |
| Same-clock later revocation | Revocation at head 6 shares dispatch's millisecond; snapshot at head 5 verifies; a re-signed snapshot claiming head 6 refuses |
| Atomic head conflict | Publication advances head while installed pointers remain unchanged; pending control CAS writes neither authority marker nor binding; fresh observation succeeds |
| Retry and missing retention | Admission/issuance retry preserves original binding; consumed attempt stays held; failed dispatch leaves no binding; deleted claim retention refuses export without synthesis |
| Negative carriage | Nineteen independently re-signed alterations refuse: omissions/order, authority/attempt/target substitution, stale/wrong/out-of-range heads, installation/ack digests, clocks/expiry and checkpoint correlation |
| Offline process | Actual `kf-verify-control-bindings` binary accepts expired historical carriage and returns nonzero for a re-signed wrong snapshot |
| Bounds and trust | Unknown fields, duplicate JSON, aggregate oversize, wrong observer key/signature refuse; existing nested bounds and role separation retained |
| Clippy / formatting / patch whitespace | Pass; warnings denied |
| Node vectors | Pass |
| Frozen white paper | 58 file hashes and 24 contract pins unchanged |
| Frozen schema / signed fixtures | 13 envelopes and declared bindings pass |

Logs: [Rust/native tests](rust-tests.log), [clippy](clippy.log),
[formatting](format.log), [Node vectors](node-vectors.log),
[white paper](whitepaper.log), [schema](schema.log). Trailing whitespace and final
blank lines are normalized for repository review. Prior evidence is unchanged.

## What was exercised

Integration fixtures publish and install controls through the actual TLS governance
listener with JWT/DPoP administrative authorization and workload-authenticated
gateway acknowledgement. Actual AdmissionController/GrantAuthority libraries
persist signed admissions and grants against etcd. Recorded claim and dispatch
authorization transactions retain their snapshots atomically with runtime state.
An independent software observer key 17 signs both the old history checkpoint and
the new exact operation binding assertion. Public verifier trust is separate from
exported metadata and carries no signing material.

Undispatched fixtures use the query-only recovery worker after grant expiry; their
target query panics if called. Dispatch fixtures authorize dispatch in etcd and
write an explicitly synthetic committed terminal observation before receipt
recovery. **These new cases do not dispatch a real target or prove a target commit.**
Existing required-suite gateway/target and official SDK tests also pass; their
pre-existing mock target boundary remains unchanged.

The deterministic native CAS test bootstraps signed software control records via
private ledger methods, samples the exact runtime comparison, and appends a policy
publication without changing installation/ack pointers. Applying the pending
comparison with authority and binding writes refuses atomically. Applying a fresh
comparison succeeds. This isolates head serialization; it is not an additional
authenticated service or real target qualification.

The new verifier authenticates both observer assertions and original signed lineage
and governance records. It reconstructs exact latest installed/acknowledged state
at each named sequence, verifies operation pins and clock validity, and refuses
applicable revocations already present at that sequence. Later revocations retain
historical verifiability. Independent re-signing of altered observer data does not
bypass these semantic checks.

## Reproduction and limits

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
node tests/sdk/agent-vectors.mjs
PYTHONPATH=src python scripts/verify-whitepaper.py
PYTHONPATH=src python spec/validate.py
git diff --check
```

Executed with Rust 1.98.0, Node 25.2.1 and etcd 3.6.5 on three single-host loopback
members. Declared Rust 1.88 and Node 20 minimums remain execution-unqualified.
The tested etcd Darwin ARM64 release archive SHA-256 is
`14d7743f9ed07950a8e85491646e067e394a09e049e42083e2f6473fefa717a8`.

The new profile is a closed draft supplement; old schemas/signing domains remain
unchanged. Missing older bindings cannot be synthesized. Managed domains without
history refuse control-checked transitions. Unmanaged fixture authority stays
available and cannot claim this export. Complete histories over 64 events still
refuse export; pagination/migration remain separate work.

Verification establishes observer-attested retained control comparisons under
trusted ledger operation, observer access/custody and authority clocks. It is not
etcd consensus evidence, latest-head proof, live permission, an independently
authenticated fence allocation or target-signed no-effect/commit proof. Original
runtime authentication, registered tool-name mapping, production key/identity
custody, complete writer coverage and independent-peer acceptance remain open.

Next: M4c1 actual process termination/restart barriers, followed by M4c2 stale-backup
quarantine and M4c3 owned incidents/automatic delivery. No gateway/target process
kill, backup restore, production identity service or real enterprise target is
newly qualified by this increment.
