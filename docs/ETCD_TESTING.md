# Real authority ledger tests

The Rust authority ledger uses the etcd v3 HTTP JSON gateway. It has no local
authority fallback. All durable root, nonce, attempt, and outbox writes use a
single etcd transaction; target mutations remain outside that transaction.

Install the platform-specific **etcd 3.6.5** binary from the
[official release](https://github.com/etcd-io/etcd/releases/tag/v3.6.5), following
the [official installation instructions](https://etcd.io/docs/v3.6/install/).
Set `ETCD_BINARY` to the resulting executable. The launcher checks the exact
version and does not download or execute an unpinned release.

From the repository root, run:

```sh
ETCD_BINARY=/absolute/path/to/etcd scripts/start-etcd.sh -- \
  cargo test --locked --workspace --all-targets -- --nocapture
```

The launcher starts three members on loopback, waits for health, exports
`ETCD_ENDPOINT`, all three member URLs in `ETCD_ENDPOINTS`, and
`KF_REQUIRE_ETCD=1`, runs the command, then stops its own members and removes its
own disposable data directory. It requires Bash and curl. Default client ports
are `12379,22379,32379`; peer ports are `12380,22380,32380`. Set
`KF_ETCD_CLIENT_PORTS` and `KF_ETCD_PEER_PORTS` to override the six distinct ports.
Running the launcher without a command retains the cluster until interrupted
and prints the environment variables for a second terminal.

To use an independently managed three-member test cluster:

```sh
export ETCD_ENDPOINT=http://127.0.0.1:12379
export ETCD_ENDPOINTS=http://127.0.0.1:12379,http://127.0.0.1:22379,http://127.0.0.1:32379
export KF_REQUIRE_ETCD=1
cargo test --locked -p kedgeflow --test ledger -- --nocapture
```

The required mode fails when an endpoint or the three-member list is missing;
optional local runs print explicit skip messages. Each test uses an isolated
namespace. The suite covers 256 competing claims across eight roots, 96 claims
against one root through three independent member endpoints, claim/replacement
races, monotonic policy and ownership updates, one-time dispatch authorization,
retained consumption after completion, correlated query-only reconciliation,
and unavailable authority. The test suite does not stop an independently managed
cluster. The unavailable-authority case uses a separate closed local endpoint.

These tests establish the bounded ledger behavior on a real single-host Raft
cluster. They do not establish geographically distributed availability, target
mutation atomicity, or production etcd TLS/RBAC configuration. Loopback HTTP is
accepted by the ledger only for disposable tests; production CLI configuration
requires a separately trusted HTTPS endpoint and client credentials.
