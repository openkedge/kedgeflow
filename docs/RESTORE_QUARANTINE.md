# Restore quarantine (bounded M4c2)

[RFC 0016](rfcs/0016-restore-quarantine.md) adds a write-ahead witness to prevent a
stale authority backup from reopening consumed roots or resetting resource fences.
It is a draft internal storage contract; frozen signed records remain unchanged.

Provision an empty authority prefix and an absent witness prefix in a separately
administered etcd cluster whose storage and backups survive authority restores.
A second prefix in the authority cluster is insufficient. Retire unguarded writers
and retain witness configuration independently of authority backups. Use separate
mTLS enrollment, CA pins and scoped role token files for local and witness access.
Production identity, RBAC, custody and failure-domain separation still need review.

Add the following closed field to each gateway, leaf-control, recovery and
collector configuration; governance inherits it through `control`. All services
using the same authority prefix must pin the same witness origin and prefix.

```json
{
  "restore_gate": {
    "endpoint": "https://witness.example:2379/",
    "prefix": "/kedgeflow-witness/tenant-42",
    "ca": "/etc/kedgeflow/witness-ca.pem",
    "certificate": "/etc/kedgeflow/witness-client.pem",
    "private_key": "/etc/kedgeflow/witness-client-key.pem",
    "token_file": "/etc/kedgeflow/witness-role.token"
  }
}
```

The operator file for `kf-restore` contains this field plus `etcd_endpoint`,
`etcd_prefix`, `etcd_ca`, `etcd_certificate`, `etcd_private_key` and
`etcd_token_file` for local access. It does not contain grant or outcome signing
keys. With all application writers stopped and the namespace entirely empty:

```sh
kf-restore --config /etc/kedgeflow/restore.json --enroll-empty
kf-restore --config /etc/kedgeflow/restore.json --status
```

Enrollment is explicit and changes both stores. Status performs authenticated live
reads only. Service material validation does not enroll or certify freshness.
Do not use a new witness prefix to resume existing authority. The CLI refuses
nonempty enrollment and never clears or repairs an existing pending witness.

Each mutating transaction reserves the next independent sequence, atomically
stamps local state and finalizes the witness before returning authority. A lost
reservation/local response can quarantine the entire prefix. A false original
comparison may still advance the head; it confers no authority. Read-only status
checks do not advance it. Contention and outages can refuse requests; capacity and
availability qualification remain open.

Restore only while services and resource writers are quiesced. A consistent
snapshot matching the independently retained latest ready head can resume the
same enrollment, preserving original attempts and fences. A stale or empty
snapshot, mismatched/missing witness or pending reservation refuses. Keep consumed
allowances held. There is no automatic pending repair, force flag, migration,
refund or fence reset. Preserve evidence and obtain an approved future repair
procedure; target quiescence and complete authoritative state are required.

The local marker also blocks current unconfigured clients in an enrolled
namespace. Restoring a pre-enrollment backup removes that marker, so independent
configuration and exclusive guarded-writer coverage are mandatory. Raw storage
access, older binaries, altered trusted configuration or restoring both stores
can bypass the assumption and are outside this qualification.

The [tests](../crates/kedgeflow/tests/restore.rs) use real authority etcd, a separate
single-member witness process/data directory, verified software mTLS and the
shipping operator CLI. They roll back stopped local prefixes, lose transport
responses and stop the witness. This qualifies logical restore isolation on one
host, not production backup tooling, target/host power failure, managed service
kills with witness enrollment or separate physical failure domains. See the
[fresh evidence](../results/verification/rfc-m4-restore-2026-10-11/README.md).
