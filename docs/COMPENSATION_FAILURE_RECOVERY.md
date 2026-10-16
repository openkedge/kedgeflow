# Inverse failure and recovery qualification

[RFC 0050](rfcs/0050-inverse-failure-recovery.md) qualifies three bounded cases
against the shipping `kf-compensation-target`, disposable PostgreSQL and etcd:

| Failure | Required retained result |
| --- | --- |
| SIGKILL while actual inverse SQL waits on the protected row lock | Forward row/version/fence unchanged; original inverse absent at target, unknown in native recovery; compensation cost stays held |
| SIGKILL after COMMIT while an external relay holds its reply | Actual restored row and original SQL outcome survive; query-only recovery after stop/expiry retains the original committed receipt |
| Stopped local authority prefix restored from before inverse issuance | Separate witness quarantines stale authority; target still reports original commit; exact latest prefix restores the same receipt, spend and historical evidence |

The native tests use a fresh inverse admission, verified subject/actor signatures,
original claim and one-shot broker permit, the mandatory signed compound binding,
separate mTLS dispatch/query identities, an explicit 15-second inverse test
budget (five-second broker credential ceiling), actual clock expiry and permanent shared
stop. Each sends once. Repeated recovery queries the original attempt and retains
the same signed receipt. Complete compound lineage independently replays the
original forward and inverse admission, held costs, qualifications and outcomes.
A missing target result remains unresolved; it never releases cost or permits
replacement execution.

The paired test harness enrolls its restore gate while the namespace is empty,
before writing topology. The inverse service checks that same witness before
joining the shared namespace. This exercises the existing production restore
gate; there is no production crash hook or new migration.

Run the focused native cases using the disposable test runner:

```sh
python scripts/test-postgres.py --bindir /path/to/postgres/bin --peer --command \
  scripts/start-etcd.sh cargo test --locked --offline -p kedgeflow \
  --test governance compensation_sql_failure_ -- --nocapture --test-threads=1
```

Set `ETCD_BINARY` to the supported etcd executable and use the repository's
required conformance runner for the full source-pinned corpus. The
[verification record](../results/verification/rfc-m8-inverse-failure-2026-10-16/README.md)
records the final checks. Earlier committed evidence and frozen fixtures,
whitepaper, schema and migrations remain unchanged.

This local software qualification uses generated identities and one OS UID.
The authority restore replaces logical prefix values only while authority
services are stopped; SQL storage and the independent witness remain intact.
It does not qualify physical SQL restore, distinct backup/failure domains,
complete deployed writers, production custody or independent peers. Inverse
storage restore and wider process-loss/partial-failure composition remain open,
as do multi-contract inverse families, dynamic delegation, full A2A peers,
independent whole-saga acceptance and actual Kubernetes drain. M8 remains open.
