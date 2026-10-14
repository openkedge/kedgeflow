# M7c exact-proposal static leases — 14 October 2026

Baseline: 1f9e9c8. [RFC 0035](../../../docs/rfcs/0035-static-admission-leases.md)
adds bounded native static prevalidation, retained non-authorizing leases and
fresh JIT evidence through the existing admission/issuer. It does not close
hardware, browser, approved provider/membership/custody or enterprise gates.

The final required run passed **295 Rust tests across 44 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, format, Clippy, Ruff, mypy,
Node vectors, frozen schema and whitepaper checks. Zero Rust failures, ignored
tests or required-mode skips. summary.json pins every command, source and raw log;
all sources remained unchanged throughout that final run. Platform: Darwin ARM64,
Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5, Node 25.2.1, Python 3.13.12.

## New observations

Ten focused lease groups pass within the required corpus:

- Sixteen competing native mTLS/DPoP requests across two replicas retain identical
  signed leases. Recreated services return the original issue/expiry times. Static
  prevalidation produces no fence and a lease is not a redeemable grant.
- Complete exact-proposal static plus fresh JIT evidence produces a lease-bound
  certificate and one original native issuance/fence. Duplicate issuance returns
  the original grant. Legacy context-only issuer validation refuses its non-null
  lease digest; new native issuance verifies the retained full input chain.
- Withdrawal blocks prevalidation, leased and ordinary full-evidence admission,
  issuance and duplicate reuse. Initial enrollment cannot reset a member. Explicit
  expected-generation replacement invalidates older leases, even with identical
  registration. Rewriting cached member generation cannot reactivate an old lease:
  its signed identity is recomputed from retained input binding, member and signer.
- Four actual-etcd barriers withdraw membership after state reads and before cache,
  admission, fence allocation and issuance CAS. Every pending write refuses. An
  already allocated fence stays held when final issuance refuses; no grant appears.
- Missing/static/JIT evidence, false static predicates, altered proposal parameters,
  delegation, descriptor/ownership, provider keys, bad lease signature/context,
  wrong subject/workload/scope, reused proof, Origin/Host/query/grant aliases and
  unknown fields/profiles refuse. Expired static evidence, JIT, delegation, lease
  and existing cache cannot be converted into fresh admission by retry.
- A successful static prevalidation followed by full Cedar denial produces no
  execution allowance. Static reviewed evidence still requires the current active
  credential and original consumed challenge; revocation blocks leased issuance.
- The shipping `kf-control` process is SIGKILLed after independently observed durable
  lease retention with its reply withheld. Restart returns byte-identical signed
  lease bytes without timestamp renewal, then fresh JIT admission/issuance succeeds.
  Actual CLI check/enrollment/withdrawal/expected-generation replacement behavior
  passes, including duplicate and stale-generation refusal.
- Example registration checks prove static/JIT partition and key/lifetime bounds.
  Legacy serialized packets omit the optional internal lease field. Existing v0.1
  historical carriage refuses leased packets rather than silently labelling them
  compatible. The no-lease runtime corpus remains passing.

The first shipping attempt exposed a fixture-only delegation timestamp mismatch:
JWT expiry is integer seconds while the test packet retained millisecond precision.
The shared test helper now uses the same expiry as the token; actual native
verification was unchanged. An oversized test JSON macro was split before the
recorded full run. No preliminary failing diagnostic is promoted as qualification.

## Evidence and preliminary scope

final-source.json pins the exact final sources and retained evidence files. No
implementation, configuration, schema, test or documentation changed after the
full passing run. The earlier [preliminary record](../rfc-m7-static-leases-preliminary-2026-10-14/README.md)
passed the broad corpus but predates signed cache-identity recomputation and its
corrupted-membership test. Its original summary/logs remain unchanged and cannot
qualify this final source. Previous M7b/M6 verification remains immutable.

## Reproduce and remaining gates

Install locked Cargo/Node SDK dependencies and Python development dependencies;
provide PostgreSQL 18.3 and etcd 3.6.5. Select a new output directory:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd \
  python scripts/conformance.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --output results/local/static-leases-new
```

[Operator guide](../../../docs/STATIC_ADMISSION_LEASES.md). Test memberships,
providers and authenticator credentials are software fixtures, not independently
approved enrollment/lifecycle or protected browser/hardware observations. Existing
control material loading/custody and production RBAC/rotation remain unqualified.
Leased lineage/history/control-binding export requires a separately versioned
profile; current closed historical schemas refuse it. Automatic Node lease
acquisition remains open. Current authority withdrawal does not retroactively
revoke already issued grants; normal execution-authority revocation remains required.

Linux/minimum-Rust CI execution and separate-account observations remain unobserved
locally. The SQL rehearsal remains same-host logical restore and direct storage
budgets with authority_consumption_tested=false, not physical restore or an
accepted enterprise SLO. M8 native grant/claim/reservation/A2A/saga/compensation /
Kubernetes drain and M9 independent implementation/reproduction/release acceptance
remain open. Frozen fixtures, schema, whitepaper, migration and old evidence bytes
remain unchanged. This record qualifies software checks, not a protocol release.
