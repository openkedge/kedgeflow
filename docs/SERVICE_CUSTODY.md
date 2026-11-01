# Protected service material

`kf-proxy`, `kf-control` and `kf-broker` accept `--custody-root` to apply
the SQL target's descriptor-based file rules to configuration and every material
reader reached by these entry points. This covers inbound and outbound TLS,
ledger and witness bearers, admission/issuer/target signers, gateway actor
assertions and acknowledgement renewal, and broker identity snapshots/floors
and live signed snapshots/heads. The shared
reader is in `file_custody`; `postgres_custody::{Root, Material}` remains available
to existing target callers.

```sh
/opt/kedgeflow/bin/kf-broker \
  --custody-root /etc/kedgeflow/broker \
  --config /etc/kedgeflow/broker/config.json --check
```

Use the same flags with `kf-proxy` and `kf-control`, under each actual non-root
service account and its own custody directory. The existing SQL target uses
`--custody-root` with its separate `--check-custody` mode. Every configured file path
must be absolute and inside the specified root, with no symlinks or `..` path
components. Resolve platform aliases before provisioning configuration. Root and
its traversed directories must be owned by root or the service UID and must not
be group/world writable. The only writable-ancestor exception is a root-owned
sticky ancestor such as `/tmp`; the custody root itself has no such exception.

Files must be regular, singly linked, owned by root or the service UID, and have
no group/world write or execute/set-ID permissions. Private keys, bearer values,
target signing seed and epoch floors must have no group/world permissions;
use service-owned `0600` files or another restrictive mode the account can read.
Public records and certificates can be `0644`. Files are bounded and read from
the checked descriptor; size/timestamp changes during a read refuse. This is
Unix mode/descriptor enforcement, not isolation from root, a compromised service,
or another process with the same UID.

The root directory descriptor is retained for the service lifetime. Live trust
reads reopen each component relative to it and recheck modes, type and ownership.
Publish snapshots and matching heads by atomic replacement *inside the retained
root*. Do not replace the root directory itself; a running process deliberately
continues using its original descriptor. The signed refresh protocol's exact
head, epoch, digest, freshness and second-head checks still apply. Unsafe/missing
files refuse new exchanges even after valid trust has been loaded; cached keys
never bypass the file policy. The minimum epoch remains sampled at startup.

Protected gateway preflight also reads the initial actor assertion source, while
legacy fixture mode permits that file to be provisioned later. Live assertion
requests and acknowledgement renewals retain the same root and recheck the
material. Control enrollment/withdrawal/replacement commands pass the file policy
through service validation and ledger/witness client construction; registration
printing reads only protected configuration and requires no private key.

`--check` creates no listener and makes no remote authority calls. It validates
material custody and local configuration, not deployed identity ownership,
network access or ledger permissions. Omission of `--custody-root` retains the
legacy fixture/library loading path. The production launcher must explicitly
require the protected mode.

Tests cover protected shipping-binary preflight for all three services, signer,
TLS, witness and actor paths, broker static and signed modes, path escape and
symlink refusal, unsafe live trust files after startup, atomic higher-epoch
renewal and one successful original-claim redemption without restarting. A live
acknowledgement test proves an unsafe acknowledgement key publishes no new
record, then safely renews after the file is repaired. A rotating assertion test
checks workload scope, atomic replacement, mode widening, symlinks and outage. Shared
reader tests cover hard links, FIFO non-blocking refusal, unsafe directories,
path traversal and replacement of the root path. These same-host tests do not
establish separate Linux account isolation or independent publisher/head/floor
storage. Auxiliary administrative/recovery/collector entry points still need their own
protected loaders and deployment isolation. These remain [production gates](PRODUCTION_READINESS.md).
