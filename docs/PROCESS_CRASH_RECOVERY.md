# Process termination qualification

[RFC 0015](rfcs/0015-process-crash-qualification.md) adds bounded M4c1
qualification for the shipping `kf-proxy` and `kf-recover` binaries on Unix.
Nine tests reach controlled barriers, send SIGKILL, await termination and restart
the same binary with the same operator configuration and ledger namespace.
The test parent owns the transport barriers; production configuration and wire
profiles have no fault-injection flags or endpoints.

| Killed process / boundary | Observed result after restart and expiry |
| --- | --- |
| Gateway before claim submission | Unclaimed; no nonce, exchange, dispatch or recovery receipt |
| Gateway after claim, before response | Original attempt sealed not-dispatched; no target query |
| Gateway before dispatch authorization | Original attempt sealed not-dispatched; no new credential exchange |
| Gateway after dispatch authorization, before response | Target not-found remains consumed unknown |
| Gateway after mock target commit, before reply | Query resolves original commit; target effect occurs once |
| Gateway after target reply, before terminal transaction | Query resolves original commit; no second dispatch |
| Gateway after terminal transaction, before response | Recovery signs retained completion without target query |
| Worker before receipt transaction | Restart persists one correlated receipt |
| Worker after receipt/head transaction, before response | Restart reuses the exact retained receipt/head |

The ledger transport terminates verified mTLS and forwards transactions to actual
etcd. Gateway and recovery identities use different workload IDs and software role
tokens. After-transaction barriers require a successful etcd response before
notifying the test. Before-transaction barriers never submit that request, even
after the child dies. Dropping the scoped server aborts pending connection tasks.

The software broker verifies the signed grant and original claimed attempt before
returning a short target token. The target validates resource incarnation, version
and monotonic fence, then updates resource state and retains attempt/grant
correlation atomically under a mutex. Its query API authenticates a separate
query-only recovery identity. The target process stays alive during this matrix.

For consumed grants, an immediate request with a new RPC ID and DPoP proof resolves
`NONCE_CONSUMED` to the original attempt. After expiry, repeated authenticated
status calls and repeated worker restarts produce zero additional claims,
credential exchanges, target dispatches or commits. Replacement refuses. Each
claimed case retains one signed receipt; receipt/evidence chains verify offline.
Possible-send not-found remains unknown, with the original nonce still held.

## Run the required matrix

```sh
ETCD_BINARY=/path/to/etcd-3.6.5 scripts/start-etcd.sh -- \
  cargo test --locked -p kedgeflow --test crash -- --nocapture
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
```

Tests fail when required etcd is unavailable. Each case prints its boundary,
pre/post state, SIGKILL/restart confirmation, successful claim/exchange/dispatch/
commit/query counts and retained receipt count. Startup/barrier/process waits are
bounded; child processes use kill-on-drop cleanup. The 12-second fixture execution
budget is allowed to expire before worker takeover of claimed attempts.

## Qualification boundary and next work

This matrix uses operator-bootstrapped signed fixture grants and the gateway's
explicit unmanaged fixture mode. It exercises actual gateway authentication,
shipping HTTPS broker/adapter clients, native etcd transitions and the shipping
recovery worker. Managed control comparisons remain covered by
[M4b4](CONTROL_BINDINGS.md); managed installation/renewal under process kill and
full signed admission lineage across these kills are additional gates.

Software CA/enrollment, actor assertion and role tokens are test fixtures. Target
commit/query data is an in-memory software resource assertion, with no target
signature or independent disk durability guarantee. SIGKILL here qualifies a
single-process failure while the host, etcd and target stay live. It does not
qualify power loss, target-process failure, stale backup restore or production
identity/broker/RBAC/custody.

M4c2 now supplies [restore quarantine](RESTORE_QUARANTINE.md) and an independently retained authority
high-water mark before allowing a restored ledger to resume execution. Local
restored state cannot prove its own freshness. [M4c3 supervision](OUTCOME_SUPERVISION.md) now supplies owned incidents and automatic
delivery. Pending repair, managed kills under witness enrollment, real
targets and independent physical failure domains remain open.

See [fresh evidence](../results/verification/rfc-m4-process-crash-2026-10-11/README.md).
