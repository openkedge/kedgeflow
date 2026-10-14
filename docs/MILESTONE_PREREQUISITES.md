# Remaining milestone software prerequisites

These increments advance the original [roadmap](IMPLEMENTATION_ROADMAP.md).
They do not close its deployment, physical hardware or independent release gates.
The native executable grant profile remains a single nondelegated SQL/mock leaf.

## PostgreSQL peer transport and separate accounts

[RFC 0029](rfcs/0029-postgres-peer-transport.md) adds explicit launch selection:

```sh
kf-postgres-target --config /etc/kedgeflow/sql/target.json \
  --custody-root /etc/kedgeflow/sql --postgres-peer-uid 10002 --check-database
```

Choose the actual nonzero database server kernel UID; the example is not an
enrollment. This option requires protected local file loading. Every execution
and query connection checks protected socket path/modes and the connected kernel
peer before sending any PostgreSQL startup bytes. The driver consumes that same
stream. Wrong pins refuse with no fallback. Local file checks remain offline.
Group access on a socket permits connection without directory-entry replacement.
ACLs, mounts, root/database administration and launcher configuration remain trusted
or unqualified. No HBA inspection or credential rotation is implied.

The separate-account harness is intentionally restricted to an explicitly disposable
Linux host as root. It creates new database/target/agent accounts, a new private SQL
cluster and generated test keys, then removes them in finally. It checks exact peer
mapping, role scope, connected native server UID, direct file/socket denial and
shell/Python descendant attempts. It is not a production installer. CI runs it and
uploads its result; **this Mac has no Linux account-fixture observation**.

```sh
sudo python3 scripts/qualify-postgres-isolation.py --ephemeral-host \
  --bindir /absolute/path/to/postgresql-18.3/bin \
  --target /absolute/path/to/kf-postgres-target
```

## Stale SQL restore and local budgets

[RFC 0030](rfcs/0030-postgres-restore-rehearsal.md) adds --recovery-rehearsal to
the existing disposable launcher. A separate new database is dumped before an
observed commit. Restoring that stale dump under CONNECTION LIMIT 0 refuses the
actual application login. Revoke PUBLIC privileges, re-enroll function roles and
rotate the resource incarnation before lifting the fence. The externally observed
commit remains retained; missing restored lookup remains unresolved,
with zero original redispatches. No running target/gateway is automatically resumed.
This storage-only rehearsal does not enroll or test an authority-ledger allowance;
consumed authority must remain held by the deployment's separate accepted procedure.

Sixteen serial fresh-incarnation storage reservations/queries publish separate
attempted/committed/refused/unresolved counts and monotonic p50/p95/max timings.
The declared local p95 budget is 3000 ms. These are direct storage timings, not
end-to-end admission/broker/target latency or an enterprise SLO. Physical restore,
pending witness repair, CTD/control cutover, immutable history/retention, operator
decisions and the full accepted restore procedure remain open.

## Review and coordination libraries

[RFC 0031](rfcs/0031-review-consumption.md) supplies trusted review enrollment,
server nonces/time, the frozen canonical ApprovalPayload challenge, original-byte
WebAuthn ES256 verification and atomic real-etcd challenge/counter consumption.
It rejects wrong origin/RP/binding, missing UP/UV, backups/extensions, zero/stale
counters, replay, expiry, revoked enrollment and hardware-bound profile requests.
Counter/revocation comparisons span replicas and recreated clients. It does not
perform registration/attestation or issue an execution grant/HITL witness. RFC 0034 now supplies the [native evidence/admission path](NATIVE_REVIEW.md).
Protected browser rendering, actual ceremony and static lease integration remain
M7 work.

[RFC 0032](rfcs/0032-coordination-reservations.md) supplies create-only root capacity,
a create-only tenant/domain budget binding, exact admitted-operation allocation
identity, narrowed action/resource scope and
separate forward/compensation conservation. One 128 KiB record holds at most 256
allocations/depth 8. Parents become non-executable composite state; only leaves
consume one original attempt. Unknown, committed and known no-effect allocations
stay held. Stop preserves history; query observation can refine unknown but cannot
refund or contradict known state. The caller remains a trusted controller, with
current admission/policy/delegation verification outside these library ports.
Native grant/claim integration, A2A, durable saga/compensation and an actual Kubernetes
drain target remain M8 work. Existing gateways still reject these execution variants.

## Required conformance bundle

[RFC 0033](rfcs/0033-release-conformance.md) supplies one fixed-command runner:

```sh
KF_REQUIRE_SDK=1 ETCD_BINARY=/absolute/path/to/etcd \
  python scripts/conformance.py --bindir /absolute/path/to/postgresql-18.3/bin \
  --output results/local/conformance-new
```

Install Python dev/spec dependencies, the locked Cargo dependencies and pinned
Node SDK first. The runner uses locked offline Cargo, formatting/clippy, Python
lint/type/tests, frozen paper/schema verification, Node vectors and the entire
required SQL/etcd/SDK Rust suite plus actual restore rehearsal. Output must be new.
Logs, command/source/tool hashes, populations and remaining gates are retained.
Success is `passed_software_checks`, not enterprise or independent release acceptance.
The minimum Rust CI check and separate Linux account fixture are additional CI
observations; their execution is unobserved in the local bundle.

See [the new verification record](../results/verification/milestone-prerequisites-2026-10-14/README.md).
Approved providers/owners, full service custody/rotation and pilot acceptance remain
M5c/M6; complete M7/M8 native services and actual hardware/target observations remain
unfinished; M9 requires independently implemented wire peers and reproduced release
evidence. These gates cannot be marked complete from the library tests above.
