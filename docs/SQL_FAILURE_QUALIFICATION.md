# Fresh PostgreSQL failure qualification (M6c)

[RFC 0026](rfcs/0026-sql-failure-qualification.md) composes the fresh signed SQL
leaf path with process failure, witnessed quarantine and retained incident delivery.
The [source-pinned verification](../results/verification/rfc-m6-failure-2026-10-13/README.md)
records eleven cases within the 260-test required regression. This is bounded
software qualification on disposable same-host services; enterprise acceptance
remains open.

Each case installs and acknowledges control after empty witness enrollment, obtains
fresh signed admission/issuance through the official Node client, and uses the
shipping gateway, one-shot native broker and real PostgreSQL target. Generated
subject and ES256 actor signatures, exact CTD/evidence pins and verified workload
mTLS remain required. A test-owned transport relay observes the specified boundary;
SIGKILL and wait/reap precede each killed process's restart. Production services
receive no fault-control interface.

| Killed process / observed boundary | Qualified result |
| --- | --- |
| Gateway after fully witnessed claim; broker request held before forwarding | Original attempt seals not_dispatched after expiry; no permit, mint, dispatch or target query |
| Gateway after native mint; response held before gateway receives it | One permit/mint remains consumed; not_dispatched; no target resend |
| Gateway after witnessed dispatch authorization; dispatch held before forwarding | Native target absence remains consumed unknown |
| Gateway after real SQL COMMIT; response held before delivery | Native query recovers original committed attempt; one SQL effect |
| SQL target while its transaction waits on an actual owner-held row lock | Kill/reap, release lock and observe backend exit/rollback; missing target outcome remains consumed unknown |
| SQL target after COMMIT; successful response held before gateway delivery | Restart retains the committed SQL outcome; query resolves the original unknown |
| Broker after successful native mint; response withheld | Restart preserves the original permit; failed exchange delivery seals not_dispatched without remint |
| Gateway after local claim; witness ready-finalization held before submit | Independent witness remains pending; recovery, replacement and gate-removal bypass refuse; no SQL effect; repair remains open |
| Gateway after COMMIT, then stopped logical source-ledger rollback to preclaim values | Independent witness quarantines the stale source; SQL query retains original commit; exact latest logical copy preserves consumed nonce, fence and receipt |
| Recovery worker after receipt retention and witness ready-finalization, before its reply | Kill/reap and restart retain the exact original signed receipt/head |
| Supervisor after native collector accepted an unknown receipt, before acknowledgement delivery | Restart looks up the same signed acknowledgement, escalates the retained owner/deadline during query outage, then resolves from correlated SQL commit and delivers its linked successor acknowledgement |

A fresh Node process resolves its persisted operation using renewed status-only
delegation after normal recovery. It retains the original grant digest/attempt,
refuses changed call arguments and sends no new granted tool call, admission or
issuance request. The pending-witness case remains quarantined and deliberately
cannot resume normal status. Repeated workers preserve stable receipt identities.
Tests compare SQL row/outcome before and after recovery, counters for successful
claim/permit/authorization and actual broker/dispatch forwarding, and exact signed
acknowledgement lineage. Unknown, absent or unavailable results never refund the
nonce or authorize replacement/mint/resend.

## Reproduce

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/path/to/etcd-3.6.5 \
  python scripts/test-postgres.py --bindir /path/to/postgresql-18.3/bin \
  --command scripts/start-etcd.sh -- \
  cargo test --locked --test governance sql_failure -- --nocapture --test-threads=1
```

The launchers require PostgreSQL and etcd; SDK required mode rejects missing client
dependencies. CI's PostgreSQL job runs these governance cases with all three
required. Plain Cargo runs may skip unconfigured dependencies. The retained run
uses Rust 1.98.0, Node 25.2.1, PostgreSQL 18.3 and etcd 3.6.5 on Darwin ARM64;
remote Linux and declared minimum toolchains remain unqualified.

## Limits and next work

The source-ledger rollback is a privileged stopped prefix copy, with deletion and
bounded put batches. It preserves record values, not physical etcd history or
revisions. The independently retained witness and SQL database are never rolled
back. This does not qualify power/disk loss, physical backup restore, stale SQL
backups, host failure or pending-witness repair.

The evidence provider is a fixed signed software snapshot and the CTD pins one
241-to-242 transition. Actor/provider/CA enrollment and scoped ledger tokens are
fixtures; the relay does not prove deployed etcd RBAC or OS containment. The native
collector verifies separate reporter/collector roles while sharing source receipt
storage. Independent collector storage, transport administration, real evidence,
provider refresh/custody, version rollover and distributed failure domains remain
open. The eight-second grant and one-second incident deadline are test budgets,
not accepted service objectives; the named fixture SRE owner is not a real on-call
assignment.

M6d should qualify protected deployment custody, covered writers and bypasses,
retention/restore procedures, operational budgets and resource/security/SRE owner
acceptance on an approved isolated target. Track M5c provider acceptance in
[enterprise qualification](ENTERPRISE_QUALIFICATION.md) alongside this work.
