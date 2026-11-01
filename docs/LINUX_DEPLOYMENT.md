# Linux core runtime deployment

This package targets Linux ELF64 on x86_64 or AArch64, Python 3.11+ for packaging
and verification, and systemd 247+ for the declared unit directives. It contains
the gateway, admission/issuer, broker and PostgreSQL target. It is an **alpha core
runtime bundle**, not a production-qualified release. Recovery/collector/operator
packaging, complete deployment qualification and the production release gates
remain open. The repository's production worklist remains authoritative.

## Build and inspect

On Linux, build the four locked release binaries and assemble a bundle:

```sh
python3 scripts/package-linux.py --output dist/linux \
  --source-date-epoch 1793404800
for bundle in dist/linux/*.tar.gz; do
  python3 scripts/verify-linux-package.py "$bundle"
done
```

The output filename includes its architecture and a 16-character content ID;
changes to binaries, unit files, migrations, documentation or epoch produce a new
immutable release directory. The full content digest is checked in the manifest. `--binary-dir` can package
prebuilt Linux binaries from another build host; it verifies ELF architecture and
hashes, not that those binaries were built from the checkout. Retain the build
source archive, Cargo.lock, compiler/tool versions, commands and logs separately.
The archive has normalized timestamps, paths, modes and numeric root ownership;
with the same packaging toolchain, inputs and epoch, the archive bytes repeat. Existing packages are never
overwritten. No accounts, systemd state or deployment configuration are changed
by the build or verification commands.

The companion `.sha256` detects accidental corruption. Obtain its expected hash
through your approved release channel; an adjacent checksum and an internal
manifest do not authenticate a publisher. The verifier checks every member,
required component, hash, mode and architecture without extracting or executing
the archive. It rejects links, special files, duplicate/escaping paths and
unlisted files. The current bundle explicitly records `production_qualified=false`.

## Qualify the package

The disposable Linux qualification command is:

```sh
sudo python3 scripts/qualify-linux-package.py --ephemeral-host \
  --binary-dir /absolute/path/to/linux-binaries > linux-preflight.json
```

It requires systemd tools, util-linux `setpriv` and Python `cryptography`. All
account databases and files stay inside a new temporary root; the host's account
database and services remain untouched. Seven staged account declarations produce
distinct kernel UIDs. The fixture observes 56 file-access cases and 44 shipping
preflight cases: each core role accepts its own protected configuration and
refuses other roles/agent, group-readable or symlink private keys, and applicable
unmanaged/zero-peer settings. It validates all five unit files and repeatable
account setup. Generated credentials and temporary files are deleted.

Omit `--binary-dir` to run staged unit/DAC checks only; that mode substitutes
`/bin/true` for executable-path validation. Neither mode starts systemd units,
exercises their process sandbox, contacts the database, tests live provider or
ledger authority, or proves end-to-end deployment. SQL native preflight uses
`--check`; the installed target unit additionally requires live `--check-database`.
The Linux ARM64 release build and native cases have been observed locally; AMD64
CI and actual installed lifecycle remain separate evidence.

## Install the immutable release

Verify the bundle, then extract it into a new private staging directory. Review
`manifest.json` and `DEPLOYMENT.md`. Copy the single verified release directory to
`/opt/kedgeflow/releases/<bundle-name>` as root, with root ownership and the
verified modes. Refuse an existing release directory; do not modify installed
release contents. Keep the previous version for rollback.

While the services are stopped, create or atomically replace
`/opt/kedgeflow/current` with a symlink to that exact release. Install the files
from `share/systemd` into `/etc/systemd/system`, `share/sysusers.d/kedgeflow.conf`
into `/usr/lib/sysusers.d`, and `share/tmpfiles.d/kedgeflow.conf` into
`/usr/lib/tmpfiles.d`. Inspect existing configuration and accounts before changing
them. These package files are root-owned `0644`; service binaries are `0755`.
Run `systemctl daemon-reload` after installing the units. Installation does not
enroll authority, initialize or migrate databases, or start services automatically.

Run the declared account/directory setup only after approving its changes:

```sh
systemd-sysusers /usr/lib/sysusers.d/kedgeflow.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/kedgeflow.conf
```

The package declares seven distinct non-login accounts: `kf-gateway`,
`kf-control`, `kf-broker`, `kf-sql-target`, `kf-recovery`, `kf-collector` and
`kf-operator`. The database, agent and identity/publisher/witness services are
separately administered. Do not make the agent or its descendants members of
service groups. Audit any preexisting accounts: sysusers does not replace their
identity or group memberships.

## Provision protected configuration

Each core service reads `/etc/kedgeflow/<role>/config.json`, where role is
`gateway`, `control`, `broker` or `sql-target`. Its directory is root-owned
`0750` with only the corresponding service group. Provision service-readable
private material as service-owned `0400` or `0600`; public certificates and
records can be `0644`. Every configured material path must be absolute, have no
symlinks and remain inside that service's protected root. Startup consumes
descriptor-checked bytes, and live assertion/acknowledgement/trust refresh uses
the same root. Do not replace the root directory while a service is running.

The units always pass `--custody-root --require-managed`. Gateway/control refuse
configuration without managed control, shared proof consumption and a restore
witness; the gateway also requires installation acknowledgement and ledger
authentication. The broker requires managed authority, a restore witness and
signed identity refresh. All other strict configuration and key-role validation
still applies. These local checks do not prove remote authorization or production
storage independence.

Broker head and epoch-floor storage must survive independently of broker and
snapshot restore. Mount independently administered **directories** read-only
under the broker custody root; publish atomic replacements within those
directories from the administrator's writable mount. A file bind mount can pin
an old inode across a publisher's rename, so it is unsuitable for live updates.
Verify owner/mode compatibility and delivery in the actual deployment. Do not
copy the witness into the broker backup or give the broker publisher credentials.

The SQL target additionally reads the root-owned `0644` file
`/etc/kedgeflow/sql-target/service.env`:

```sh
KF_POSTGRES_PEER_UID=<actual-non-root-database-kernel-uid>
```

Replace the placeholder with the database account's numeric UID. This pins the
actual Unix-socket peer before SQL authentication; omission or zero refuses.
Configure the database socket outside `/tmp` and `/var/tmp`, because the units use
private temporary directories. Configure exact SQL peer/HBA mappings and roles;
the target unit's non-mutating `--check-database` must pass before it can start.
The package does not create PostgreSQL, Keycloak, SPIRE, etcd, witness or collector
services or approve their databases, keys, backups or network policy.

## Preflight, enrollment and lifecycle

Run `systemd-analyze verify` against the installed unit files. Inspect each
effective unit and any drop-ins. Before launching, run each unit's exact
`ExecStartPre` command under its service account and verify the expected effective
UID, protected paths and database peer pin. The preflights do not write protocol
authority. Provision and independently enroll the exact managed action, controls,
registrations, shared proof capacity, witness and target before live requests.

Start with `systemctl start kedgeflow.target`; inspect all four services and their
journals individually. The target's active state and `Type=exec` are **not**
application readiness. Exercise an authorized end-to-end action and original
outcome query, and deployed negative/bypass cases, before admitting traffic.
Once that deployment is accepted, enable the target for boot.

Units run with separate UIDs, no capabilities, read-only system files, protected
home/kernel/control-group paths, private devices/temp, bounded tasks/descriptors
and restricted syscall/address-family policies. Qualify these restrictions on the
selected kernel and systemd version; add destination firewall/egress rules and
workload-specific memory/capacity budgets independently. The unit settings alone
do not establish deployed isolation or network allowlisting.

Stop using `systemctl stop kedgeflow.target`. SIGTERM stops acceptance and allows
up to 30 seconds for existing HTTP connections; systemd allows 40 seconds before
terminating remaining processes. A stop or forced kill can leave an attempt
uncertain. Recovery must query the original attempt and retain consumed authority;
never remint, redispatch, refund or reset state because a process stopped.

For upgrades, drain traffic, stop services, retain the independent authority and
storage heads, verify/install a new immutable release and its compatible units,
run preflights and accepted migration procedures, then start and verify the exact
original-attempt and refusal behavior. Roll back code only when its data/protocol
compatibility is established. Do not restore older authority databases, key
histories, floors or outcomes as part of a code rollback. Uninstall by stopping
and disabling the units, then removing their unit files and immutable runtime
release after retention approval. Preserve accounts, protected configuration,
database/witness/outcome/receipt state and backups until their retention and
ownership procedures explicitly permit removal.

Systemd references: [execution restrictions](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html),
[service lifecycle](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[system account declarations](https://www.freedesktop.org/software/systemd/man/latest/sysusers.d.html).
