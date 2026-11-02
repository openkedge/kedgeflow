# Protected etcd credential renewal

The optional Linux publisher renews bearer tokens for explicitly configured etcd
principals. It does not provision users, grant permissions, enable authentication,
change ledger records, or rotate service certificates. An etcd administrator must
first approve and provision users, roles, random passwords, TLS identities and
permission sets. Keep that administrator's credentials outside the publisher.

`kf-ledger-credentials` runs as `kf-credentials`, without capabilities. It reads
protected configuration and mTLS material, authenticates each ordinary user,
verifies that reading the root user's metadata is forbidden, and reads its own
roles twice. Both observed permission unions must exactly match the configured
policy. Root users/roles, additional/missing permissions, ambiguous JSON,
redirects, unsafe files and dependency failures refuse issuance. No service token
is printed. Each principal has one five-second deadline covering material loading,
authentication and audit. The publisher performs no ledger transaction.

These are issuance-time observations. They do not lock role administration or
create an atomic server-side permission snapshot. An administrator can change
roles after either read; etcd enforces current permissions and token validity.
The publisher is trusted to issue credentials for all configured principals and
must be isolated from agents and service accounts.

Etcd's authenticated JSON gateway requires client certificates without a Common
Name. Enroll the client using the approved SAN identity and CA policy; the
publisher refuses a client leaf containing a CN during local preflight. The server
certificate must satisfy etcd's embedded gateway connection requirements. See
upstream [RBAC](https://etcd.io/docs/v3.6/op-guide/authentication/rbac/) and
[transport security](https://etcd.io/docs/v3.6/op-guide/security/) documentation.

## Optional installation

A verified v3 Linux bundle includes `bin/kf-ledger-credentials`,
`libexec/kf-ledger-publish.py` and `share/ledger-credentials`. The management units
are not started by `kedgeflow.target`. Python 3.11+ is required by the local writer.

As root, review and install the optional `sysusers.conf` and `tmpfiles.conf` into
`/usr/lib/sysusers.d/kedgeflow-ledger-credentials.conf` and
`/usr/lib/tmpfiles.d/kedgeflow-ledger-credentials.conf`. Run `systemd-sysusers` and
`systemd-tmpfiles --create` for those files after the core accounts/directories
exist. Audit preexisting account/group memberships. Install the two `.service`
files and `.timer` into `/etc/systemd/system`, then run `systemctl daemon-reload`.

Provision `/etc/kedgeflow/ledger-credentials/issuer.json` from the example as
root-owned `0440`, group `kf-credentials`. Public CA/certificate files may be
`0444`; private keys and passwords must be owned by `kf-credentials`, `0400`,
without links. Use random high-entropy passwords, 32–4096 visible ASCII characters
after trimming. All material paths must remain inside this root-owned `0750`
directory, group `kf-credentials`. The publisher cannot replace its configuration.

Provision `mapping.json` from the separate example as root-owned `0400`. It closes
staged names, usernames, scopes, permissions and destination role/filename pairs;
the issuer and mapping policies must agree. A token is installed into
`/etc/kedgeflow/<role>/credentials/<filename>`, service UID/GID, `0400`. Its
directory must be root-owned `0750`, group of that service. The writer refuses
unsafe existing targets, including links and widened modes, and replaces files
relative to retained directory descriptors. The publisher cannot select arbitrary
output paths or ownership.

The example grants a whole namespace to illustrate the format. This does not
establish least privilege between service roles: current ledger keys interleave
root, grant and attempt operations. Approve narrower exact-key or lexical-range
grants where supported; complete service-level ledger isolation remains a separate
deployment gate. The allowed interval for `/kedgeflow` is `/kedgeflow/` inclusive
through `/kedgeflow0` exclusive.

Configure each daemon's existing `token_file` to use its assigned file, including
separate witness credentials where required. Services reload protected ledger
token files for each raw transaction; the publisher does not restart them. Use
the actual daemon's primary/witness configuration schema.

Run `kf-ledger-credentials --check` as `kf-credentials`, passing `--config` and
`--custody-root`. This checks local material without authentication or publication.
Then start `kedgeflow-ledger-publish.service` and verify application readiness with
the enrolled monitor. Enable/start `kedgeflow-ledger-publish.timer` only when its
cadence fits the approved token lifetime. It runs 30 seconds after the previous
activation becomes inactive. Allow measured issuance time, load and failure
margins when selecting etcd's TTL. Timer activity does not establish readiness.

## Failure behavior

The issuer atomically stages one `0440` batch in its own `0750` runtime directory
after every principal passes. Its timestamp precedes the first authentication.
The writer accepts batches at most ten seconds old and one second in the future;
large/slow batches can therefore fail safely. Keep the full measured cycle below
that bound.

The publish unit requires a successful fresh issuer invocation. The root writer
has only `CAP_CHOWN`, no Internet socket family, and write access to the nested
credential directories. It validates the whole batch and prepares/fsyncs every
new file before replacing any destination. Each replacement is atomic; several
files are not one transaction. A crash or I/O failure can leave old and new tokens
together. Consumers must handle unavailable credentials without replaying an
ambiguous mutation.

Authentication, audit and publication failures record a failed unit without
cached-success publication. Existing files remain and may be valid or later expire
under etcd's policy. Stopping the timer does not revoke tokens or permissions;
revoke at etcd and restrict network access when required. Keep agents out of
publisher/service groups and administrative paths. Monitor issuance failures,
credential lifetime and application readiness. Service CA rotation remains separate.

## Disposable Linux qualification

On an otherwise empty disposable systemd host with Python `cryptography`, etcd
3.6.5 and a built Linux publisher:

```sh
sudo python3 scripts/qualify-ledger-credentials.py --ephemeral-host \
  --binary /absolute/path/to/kf-ledger-credentials \
  --etcd /absolute/path/to/etcd > ledger-publisher.json
```

This creates/removes three host accounts, two units and an isolated TLS etcd node.
It observes UIDs, capabilities, syscall restrictions, credential access refusals,
actual token expiry, repeated systemd issue/install, authentication/audit failure,
stale/link refusal and journal secret exclusion. Generated PKI, one fixture-owned
node and a namespace-scoped role do not establish a production topology, all-role
least privilege, a full managed workflow or service CA rotation.
