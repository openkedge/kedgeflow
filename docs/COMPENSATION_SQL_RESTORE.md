# Inverse SQL restore with consumed native authority

[RFC 0051](rfcs/0051-inverse-sql-restore.md) extends the
[inverse failure qualification](COMPENSATION_FAILURE_RECOVERY.md) with real stale
PostgreSQL dump/restore copies and consumed native authority. It complements the
forward-only RFC 0030 storage rehearsal, which does not exercise native spending.

| Original native state | Stale restored lookup | Required reconciliation |
| --- | --- | --- |
| Dispatched with no native terminal receipt | Missing, despite an externally observed actual inverse commit | Same original attempt remains unknown, signed unknown receipt and unchanged held inverse cost; no replacement, mint or send |
| Original committed signed receipt already retained | Missing | Same committed signed receipt survives; it is not replaced by unknown and no target query is needed |

Both tests capture a custom-format dump after actual forward commit and protected
snapshot but before inverse issuance. Fresh native inverse admission, verified
subject/actor signatures, one-shot broker authorization and the mandatory compound
binding precede one shipping target dispatch. An external mTLS relay holds its
actual COMMIT reply; the target is killed and an unavailable reply is delivered.
Shared root stop and real expiry precede query-only reconciliation.

The restore uses a fresh random database only. All five original application
roles fail actual login under CONNECTION LIMIT 0 before and after pg_restore.
With the database still fenced, the owner removes inherited PUBLIC/application
privileges, rotates the restored resource incarnation and enrolls only the inverse
reader's CONNECT/USAGE/lookup privileges. Executor, barrier and forward logins
remain denied after opening the query role; reader mutation and normal target
preflight refuse. No native target/gateway resumes. The original source database,
authority ledger and separate witness stay intact.

Native recovery uses a query-only SQL client against the restored copy. A separate
test-owner record of the actual commit cannot promote native uncertainty. An
already retained signed commit cannot be erased by missing restored SQL. The
same forward budget and inverse spend, original identities and signed receipt
survive. Complete compound lineage verifies as unresolved or historically
compensated. Historical `compensated` describes the original recorded workflow;
the restored row can still be the earlier booking. The audit supplies no execution
authority and makes no live-state claim about that copy.

Run the native cases with the pinned disposable runner:

```sh
python scripts/test-postgres.py --bindir /path/to/postgres/bin --peer --command \
  scripts/start-etcd.sh cargo test --locked --offline -p kedgeflow \
  --test governance compensation_sql_storage_restore_ -- --nocapture --test-threads=1
```

The runner passes its pinned PostgreSQL tool directory to native tests; missing
tools fail required mode. [Verification](../results/verification/rfc-m8-inverse-sql-restore-2026-10-16/README.md)
retains full required conformance, dump/external-record hashes and scope limits.
Earlier committed evidence and frozen schemas, fixtures, paper and migrations
remain untouched. No production restore command or protocol version is added.

This qualifies stopped logical-copy behavior with local generated identities and
one UID. Physical backup/PITR/cutover, independent storage/key/history custody,
accepted ingestion of externally retained outcomes, fresh deployment enrollment,
all-writer coverage and production restore remain open. Wider inverse failures,
multi-contract/dynamic/A2A protocols, independent saga acceptance and actual
Kubernetes drain remain separate M8 gates. No automatic resume is authorized by
this rehearsal.
