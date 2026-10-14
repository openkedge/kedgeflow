# M7b native reviewed evidence — 14 October 2026

Baseline: a73666a. [RFC 0034](../../../docs/rfcs/0034-native-review-evidence.md)
implements a bounded native provider and explicit reviewed-evidence rule. It does
not close the original browser, hardware, lease or enterprise acceptance gates.

The required conformance run passed **285 Rust tests across 44 binaries**, **18
SQL storage/peer/restore groups** and **32 Python tests**, with zero Rust failures,
ignored tests or required runtime skips. Format, Clippy, Ruff, mypy, Node vectors,
frozen schema and whitepaper checks pass. summary.json pins commands, tool versions,
logs and the working-tree sources of that full run. Platform: Darwin ARM64, Rust
1.98.0, PostgreSQL 18.3, etcd 3.6.5, Node 25.2.1, Python 3.13.12.

## New observations

Eight native review groups (including the example registration check) pass:

- Real verified workload mTLS and OAuth/DPoP begin/complete, exact challenge/rendered
  bindings, signed Evidence, and fresh capacity evidence through native admission
  and issuance. Recreated services return identical evidence; duplicate issuance
  preserves the original grant and one resource fence.
- Wrong reviewer subject/workload/scope, reused proof, Origin/grant metadata, unknown
  fields/profiles, bad UV/counter/signature/origin and substituted approval refuse.
  Rejection, expiry and changed policy cannot discharge a required review.
- Provider-signed fabricated nonce, assertion, parameters/rendering/policy, times,
  enrollment, counter, approved/hardware or extra-field facts cannot authorize.
  Current active enrollment and exact durable consumption are compared independently.
- Revocation before issuance produces no fence. Revocation after issuance blocks
  admission/issuance reuse while preserving the earlier grant/fence. Separate
  barriers revoke enrollment after review reads but before admission, fence
  allocation and issuance CAS: all refuse. A previously allocated fence stays held
  when the final issuance transaction refuses.
- A shipping `kf-review` process is SIGKILLed after independently observed durable
  consumption and before any evidence publication put reaches etcd. Restart
  reconstructs the original sign count and verification time without reconsumption;
  another restart returns the exact signed bytes. Privileged revocation blocks retry.
- Offline shipping configuration checks perform no remote operation, reject exposed
  or symlinked signing seeds and cannot use duplicate enrollment to reset state.
  Changed publisher registration cannot overwrite an existing nonce's evidence.

All authenticator keys, certificates and enrollment are synthetic software fixtures.
There is no observation of a human viewing the rendered document or of physical
credential enrollment/attestation. Native reviewed evidence uses the existing
Evidence envelope; frozen HitlWitness variants and AdmissionLease remain unsupported.

## Final source scope

After the full passing run, only the test fixture's temporary-directory selection
changed, from a macOS-specific path to the canonical platform temporary directory.
All implementation, schema, configuration and documentation bytes are identical
to the full run. final-native-review.log reruns all eight affected groups against
real TLS/etcd on that final test source. final-clippy.log and final-format.log verify
the final workspace. final-source.json records the exact changed-file set, final
source hashes and retained evidence hashes. The full run's original summary/logs
are preserved. No previous verification record was modified.

The Linux fixture path is now portable, but Linux execution, separate-account CI
and minimum Rust CI remain unobserved locally. Existing SQL results remain a
same-host logical restore and direct storage budget rehearsal, including
`authority_consumption_tested=false`; they do not certify physical restore or an
accepted enterprise workload/SLO.

## Reproduce and remaining gates

Install locked Cargo/Node SDK dependencies and Python development dependencies;
provide PostgreSQL 18.3 and etcd 3.6.5. Use a new output directory:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd \
  python scripts/conformance.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --output results/local/native-review-new
```

See the [operator guide](../../../docs/NATIVE_REVIEW.md). Protected browser display /
ceremony, approved physical enrollment/attestation, hardware profiles, static
leases, all-service custody/rotation, approved AS/SVID providers, deployed writer /
bypass/restore/retention and owner acceptance remain open. Native coordination
binding to grants/claims, A2A, durable saga/compensation and Kubernetes drain remain
M8 work; independent controller/second runtime/target and reproduced release
acceptance remain M9 work. Frozen fixtures, schema, whitepaper and migration remain
unchanged. These results establish software checks, not release acceptance.
