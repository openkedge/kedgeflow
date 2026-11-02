# Managed providers and shipping services under systemd

This record exercises real Keycloak/SPIRE credentials through four shipping
managed services under separate Linux accounts, with the official Node SDK under
its own agent account. It is bounded software qualification, not production
acceptance.

## Runtime and observations

The exact ARM64 bundle is
`kedgeflow-core-0.9.0-alpha.1-linux-aarch64-22c3fbfe206bc010.tar.gz`, SHA-256
`59dac3a300e0c1ece9294b9f8bc128a005bcbaf0c98c2c3e73a73489706c15f5`.
All four observed executable hashes match its retained
[manifest](../linux-readiness-package-2026-11-01/bundle-manifest.json).
The shipping runtime is unchanged; this increment changes qualification,
fixtures, CI and documentation.

`systemd-workflow.json` records two fresh workflows: normal execution and
deliberately discarded completed SDK execution response. Each runs the shipping
admission/issuer (`kf-control`), broker, gateway and PostgreSQL target with
`--custody-root --require-managed`. The contained unit templates retain their
sandbox settings; fixture overrides select temporary accounts, paths and launch
commands. Six distinct kernel UIDs belong to those four services, the SDK agent
and PostgreSQL owner.

The strict launch includes shared proof replay protection, an enrolled separate
witness process, signed identity refresh and gateway installation acknowledgement.
Observed process UID/capability/seccomp/no-new-privileges flags and effective unit
settings are checked. Agent private-key reads refuse for every service. A
successful non-root database-owner client check precedes twelve refused direct
SQL logins from non-target service/agent accounts. The SDK checks its actual UID,
GID and absence of other supplementary groups.

Both workflows commit one SQL action and retain one broker exchange permit and
one original SQL attempt. After domain revocation, actual grant expiry and a
systemd gateway restart, the SDK resumes the same attempt/grant without another
broker exchange or resource effect. Each resource advances from version 241 to
242. The final witness check succeeds. These observations do not inject loss of
the gateway-to-target response before the gateway records completion.

`cleanup.json` independently confirms no fixture users, groups, units, data or
source copies remain. The final run reports successful account/group and database
cleanup, provider container/network cleanup, and unchanged sources. Both pilot
VMs were restored to their original stopped state; owned build containers were
removed and reusable caches retained.

## Reproduction and provenance

The [Linux deployment guide](../../../docs/LINUX_DEPLOYMENT.md) documents the
disposable-host command using `--managed-sql-workflow` and
`scripts/systemd-sql-workflow.py`. `run-vm.py` retains the observed SSH adapter;
`pilot-source.*` retain the 442 inputs captured before that actual run. The
combined `source.*` snapshot additionally includes CI, documentation and regression
test inputs. No working private provider/service credentials are archived.

The Linux harness was compiled with pinned Rust 1.98.0, reduced harness-only
optimization and 16 code-generation units. `harness-build.json` binds the
successful selected compiler artifact, executable hash and exact sources.
Remaining automatic CLI builds were stopped after that artifact completed; no
complete Cargo release build is claimed. The deployed executables come from the
previously verified immutable bundle. The selected harness then passed its actual
Linux test, covering both workflows, in 15.88 seconds. Node/etcd checksum provenance,
PostgreSQL 18.3 runtime reference and the Node `libatomic1` dependency are retained.

Validation additionally passed 45 focused Python regressions, all-target Clippy
with pilot features, formatting and frozen-paper/contract checks. The default
native fixture path passed its existing governance test. The original native
provider/SDK workflow also passed both legacy cases (`legacy-*`), with its own
source snapshot and unchanged-source/cleanup result. CI now defines managed
native and exact-bundle systemd provider runs; no GitHub Actions execution is
claimed here.

## Remaining boundaries

Administrative governance, evidence, service PKI, identity publication/head/floor
and TLS ledger relays remain generated same-host fixtures. Provider credentials
are issued in disposable containers and copied through fixture custody, rather
than attesting the production host agent or qualifying its secret publisher.
Keycloak uses disposable development storage. Primary/witness etcd backing
servers use fixture loopback access behind the relays: real per-role etcd RBAC
and complete agent/descendant network bypass denial are not established.

The shipping governance, recovery/supervision and collector services are outside
this live workflow. Independent administration/storage, service PKI rotation,
physical recovery, upgrade/rollback, capacity, release/security review and owner
acceptance remain open in the
[production worklist](../../../docs/PRODUCTION_READINESS.md).
