# Cold provider storage restoration — 31 October 2026

**Passed the bounded provider storage qualification.** Actual Keycloak 26.8.1
H2 data and SPIRE 1.15.5 SQLite/disk signing-key state were copied while stopped
and restored through three replacements of both provider containers. Fresh
credentials from latest and stale copies were verified with the shipping broker
and its native identity verifier. See the [summary](summary.json),
[storage-copy proof](provider-storage.json), [native results](identity-lifecycle.json)
and [required execution log](identity-lifecycle.log).

Two private cold copies were captured: initial state and post-Keycloak-rollover
state. The SPIRE agent/server exit gracefully before SQLite `quick_check`; both
containers must be stopped, and Keycloak must exit cleanly without OOM before
copying. The complete `/opt/keycloak/data/h2` and `/var/lib/spire/server`
directories are copied, including SPIRE's datastore and disk `keys.json`.
Public proof retains archive SHA-256 values/sizes and old/new container IDs.
The database/key archives themselves remain private and are deleted on exit.

Each restoration creates fresh containers from the declared images. The restore
path does not import a realm or recreate the SPIRE workload registration. TLS
and client bootstrap material are supplied separately. The agent reattests with
fresh memory keys; agent private state is not restored. Latest → initial → latest
restoration requires genuinely fresh token issuance at each step. The latest
copy preserves the pre-restore issuer key and subject; the stale provider issues
a different, valid old-key token. New SPIRE assertions verify under the original
server JWT keys, demonstrating recovered enrollment and signing-key continuity.

Issuer verification pins come from the trusted rollover observation **before**
restoration, not from newly advertised restored-provider metadata. The independent
native verifier accepts the stale-restored token under initial trust, then refuses
it under current approved trust. The shipping broker also refuses that token
before mint, with zero credential permits. The existing fourteen lifecycle cases
run alongside four storage checks. Fresh epoch-six publication and broker restart
redeem the same original claim once; replay leaves the single permit unchanged.
No target dispatch or SQL mutation occurs in this mode.

The [75 supporting Rust identity/configuration/broker regressions](required-auth.log)
passed with required three-member etcd and no runtime skips. All
[49 Python tests](python.log), [feature-enabled clippy](clippy.log),
[format](format.log), [Ruff](ruff.log), [mypy](mypy.log) and the
[frozen paper/contract check](whitepaper.log) passed. The orchestration cleanup
regression now includes storage mode. [CI](../../../.github/workflows/ci.yml)
includes `--identity-storage-restore` with artifact retention; remote AMD64
execution remains unobserved.

The [410 source hashes](source.json) match the [pre-run source archive](source.tar.gz)
and remained unchanged through final execution. The [baseline revision](revision.txt)
is the committed identity/SQL pilot and public README cleanup (`9595270`); this
archive captures the storage increment before its subsequent commit. The native
report pins the shipping broker binary SHA-256. [Tools](tools.json),
[workload image metadata](workload-image.json), [image build](workload-build.log)
and [three helper source hashes](image-source.log) retain runtime/build inputs.
All earlier frozen evidence remains byte-identical.

This is a stopped, same-version, same-host **H2/SQLite/disk-key fixture**.
Provider containers run on Linux ARM64; native broker and loopback three-member
etcd run on Darwin ARM64. Publisher/head/floor, execution grant and service PKI
remain generated fixtures outside the provider archives. The broker uses the
explicit unmanaged test ledger transport. Native head/floor files are constructed
for the verifier test; a live broker is not held across the physical provider
replacements. The result does not establish online/distributed backup, production
Keycloak database recovery, physical storage durability, cross-version migration,
HSM/KMS recovery, revocation delivery budgets, SPIRE issuer rollover or independent
custody/deployed owner acceptance. The existing lifecycle record remains separate.

The registered workload is refused access to the administration secret and SPIRE
signing keys. Every restored workload also refuses JWT-SVID acquisition to the
unregistered UID. No raw access tokens, DPoP seeds, workload private keys,
administration secrets, backup contents or provider logs are retained publicly.
Exact owned containers/network, private temporary files and native test processes
are cleaned up. No host mounts, published ports or privileged mode are used.
The [VM stop log](vm-stop.log) restores the initially stopped test VM, preserving
its pre-existing cluster and disk.

Reproduction and limits are in the [pilot runbook](../../../docs/SELF_HOSTED_PILOT.md#cold-provider-storage-backup-and-restore).
The [artifact manifest](artifact-sha256.json) covers this retained record.
