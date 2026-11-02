# Live SQL component under the shipping systemd sandbox

This record qualifies the SQL target component of the self-hosted Linux MLP.
It does not establish production readiness or a full managed-authority deployment.

## Exact runtime

The immutable ARM64 bundle is
`kedgeflow-core-0.9.0-alpha.1-linux-aarch64-22c3fbfe206bc010.tar.gz`, SHA-256
`59dac3a300e0c1ece9294b9f8bc128a005bcbaf0c98c2c3e73a73489706c15f5`.
Its shipping `kf-postgres-target` is SHA-256
`e2b64b5064fd8d08d0c39d23f579f85f2ee7b8537948952d2bf11215a53230d4`.
Its SQL unit is SHA-256
`a82852304ac1a12c309e37207f43516db34f52477f6206fdac8b216d427f3633`.
The preceding [release record](../linux-readiness-package-2026-11-01/README.md)
retains the executable build and all 395 unchanged build inputs. This increment
changes qualification tooling, CI and documentation; it does not rebuild Rust.

PostgreSQL 18.3 was built from the repository-pinned official source SHA-256
`d95663fbbf3a80f81a9d98d895266bdcb74ba274bcc04ef6d76630a72dee016f`
inside the pinned Rust 1.98.0 Debian builder. `postgres-build.json`, the compressed
build log and installed runtime inventory retain its provenance. The build
exited zero without OOM; its owned container was removed.

## Observations

`systemd-sql.json` records a real Linux/systemd run with six distinct non-root
kernel UIDs for the database owner, target, gateway client, recovery client,
agent and monitor. PostgreSQL accepts only the target's exact peer mappings for
its function-only executor/query roles; the protected target pins the database
server's separate kernel UID. The target uses the exact bundle's executable and
unit text, with fixture overrides for accounts, paths, commands and monitoring.
It runs in a temporary actual systemd unit, with private data under `/run` so
`PrivateTmp` remains enabled. Effective unit restrictions and actual process
UID/capability/seccomp/no-new-privileges flags are checked. This is not a full
installation/upgrade rehearsal.

Ten isolation groups and eleven workflow events passed:

- A generated signed grant/target JWT causes one real PostgreSQL COMMIT.
  The client deliberately discards the response body after observing HTTP 200;
  an authenticated original-attempt query recovers the exact grant/root binding.
- Replaying the original dispatch preserves one attempt and resource version 2.
  A systemd target restart preserves the same authoritative query result.
- Withdrawing executor LOGIN produces typed 503 readiness while query access
  still succeeds. Dispatch refuses and complete resource/attempt inventories do
  not change. Regranting LOGIN restores typed 200 readiness.
- Withdrawing query LOGIN produces typed 503 readiness and unavailable queries;
  regrant restores readiness. Readiness checks leave both inventories unchanged.
- Actually expired execution credentials refuse. The original query still
  returns the retained commit, with no second attempt.
- Same-CA agent query, dispatch and monitor access refuse; a wrong query bearer
  and missing client certificate refuse. Agent shell/Python descendants cannot
  read or change protected material or bypass the target through its socket.
  Recovery cannot authenticate directly to the SQL reader role.

The original four-account isolation mode also passed with zero effects and five
live query/refusal observations (`legacy-isolation.json`). All 32 focused Python
package, mTLS and fixture-ownership/cleanup tests passed. Ruff, CI YAML parsing,
diff checks and the frozen paper check passed. No GitHub Actions run is claimed.

`cleanup.json` confirms no fixture accounts, units or data remain after the final
run. The database and unit stopped, source copies were removed, and the owned VM
was returned to its original stopped state. Existing fixture VMs were untouched.

## Reproduction and limits

On an explicitly disposable systemd Linux host, with PostgreSQL 18.3, Python
cryptography, OpenSSL and account utilities:

```sh
sudo python3 scripts/qualify-systemd-sql.py --ephemeral-host \
  --package /absolute/path/to/the/exact-bundle.tar.gz \
  --sha256 59dac3a300e0c1ece9294b9f8bc128a005bcbaf0c98c2c3e73a73489706c15f5 \
  --bindir /absolute/path/to/postgres/bin
```

The command snapshots/verifies the bundle before provisioning. It refuses
optimized Python, never replaces an existing fixture unit, and cleans up on
failure. The host driver and exact source inputs are retained alongside raw
reports. `artifacts.sha256.json` hashes this record; `source.json` hashes the
archived implementation/CI/documentation inputs.

The authority signatures and service PKI are disposable generated fixtures.
There is no independently consumed broker permit or live control/identity
provider in this component run. The gateway and recovery callers are separate
UID Python clients, not the shipping gateway, SDK or recovery worker. No claim
is made about ambiguity before HTTP headers, receipt delivery, ledger renewal,
service PKI rotation, physical storage restore, upgrades, capacity or external
egress. Full managed Linux integration and production acceptance remain open in
the [production worklist](../../../docs/PRODUCTION_READINESS.md).
