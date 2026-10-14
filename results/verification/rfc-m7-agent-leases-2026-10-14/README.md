# M7d2 Node Agent Adapter leases — 14 October 2026

Baseline: e94ffd0. [RFC 0037](../../../docs/rfcs/0037-agent-static-lease-workflow.md)
adds approved client stage/provider pins, static-only preparation and immutable
lease reuse, fresh JIT acquisition and a durable boundary before admission.
[Operator guide](../../../docs/AGENT_STATIC_LEASES.md).

The final required run passed **305 Rust tests across 44 binaries**, **18 SQL
storage/peer/restore groups**, **32 Python tests**, agent and lease Node vectors,
formatting, Clippy, Ruff, mypy and frozen schema/whitepaper checks. No Rust failures,
ignored tests or required-mode skips. All final sources remained unchanged during
the complete run. summary.json pins commands, sources and logs; final-source.json
pins final sources/evidence. Darwin ARM64; Rust 1.98.0, PostgreSQL 18.3, etcd 3.6.5,
Node 25.2.1, Python 3.13.12 and pinned official MCP client 2.3.0.

## New observations

Five native test groups exercise twelve scenarios with actual mTLS/DPoP/etcd,
installed control and separate Node processes:

- Automatic `execute` and explicit `prevalidate` both freeze the original proposal,
  obtain static witnesses/lease and admit with fresh JIT. Ready-cache reuse in a
  separate process obtains no extra baseline/static witness/lease. Final native
  admission/issuance yields one original guarded mock effect; later execution is
  query-only. Every wire request uses a distinct DPoP proof.
- A successful native prevalidation reply is discarded. The client retains the
  original static packet, with no lease or execution grant. A separate process
  retries it, returning the original signed lease digest and issue/expiry times,
  with one static collection and no prevalidation fence allocation.
- Lost JIT replies and failed pre-admission marker persistence occur before any
  authorizing request. The ready state remains; the next process recollects only
  JIT and admits/executes once. Original static evidence and lease remain unchanged.
- Lost successful admission/issuer replies and failed grant persistence retain
  `authority_started`. Unissued/unclaimed status does not permit another admission,
  issue or dispatch. Subsequent processes perform query-only recovery and produce
  no target effect in these possible-authority cases.
- Expired leases, withdrawn/replaced member generations and changed delegation
  cannot create new execution authority. Missing membership is enforced natively;
  expiry/delegation mismatches fail before JIT acquisition. Changed arguments under
  a prepared qid conflict. Renewed status-only delegation discloses original history
  after expiry/domain revocation without lease/JIT/admission/issuance or dispatch.

Independent Node vectors reject closed-field/profile/endpoint aliases, role overlap,
wrong signatures, proposal/tenant/workload/delegation/policy/ownership links,
discharge/JIT substitutions, duplicate/missing/changed static records, stale/future
observations, invalid markers/configuration and certificate lease/expiry links.
Canonical formatting variations remain accepted. The no-lease SDK, SQL, review,
history, crash and recovery corpus remains passing. CI now includes both client
vector sets; its remote execution is not claimed by this local record.

The initial targeted native fixture had retained a paper state digest while its
baseline provider sampled current mock state; native admission correctly refused
it. The fixture now binds static evidence to the observed baseline. A separate
[diagnostic run](../rfc-m7-agent-leases-diagnostic-2026-10-14/README.md) failed client
vectors after a stricter single-leaf check exposed a copied paper saga/commit-bound
proposal. Its test copy now uses the supported null-workflow/dispatch-bound profile.
Frozen records remain unchanged. Original diagnostic logs/summary remain immutable
and are not promoted as qualification.

## Reproduce and remaining gates

Provide locked Cargo/Node dependencies, Python development dependencies,
PostgreSQL 18.3 and etcd 3.6.5. Select a new output directory:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd \
  python scripts/conformance.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --output results/local/agent-leases-new
```

This is software qualification with a guarded mock target, synthetic providers /
memberships and simulated lost replies/writes plus ordinary client recreation.
It does not qualify actual client SIGKILL/crash-lock recovery, power-loss/stale
store restoration, a leased SQL enterprise pilot or hardware review. Existing
native service kill/SQL non-lease evidence remains separately retained. Protected
application storage, honest atomic durable writes, key custody and explicit owner
recovery of crashed locks remain assumptions. Current native member/cache/review /
control comparisons remain necessary; a local lease is not execution authority.

M8b native reservation/grant/claim integration is next. M7 protected browser /
physical enrollment/attestation and approved provider/membership lifecycle, M5c/M6
enterprise owner/custody/writer/restore acceptance and M9 independent peers /
reproduction/release gates remain open. Linux separate-account and minimum Rust
CI execution are unobserved locally. SQL restore/budgets remain same-host logical /
storage-only checks with authority_consumption_tested=false. Frozen schema,
fixtures, paper, migration and prior evidence bytes remain unchanged.
