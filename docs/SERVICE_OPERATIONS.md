# Service readiness monitoring

Gateway, control, broker, SQL-target, governance and receipt-collector services support an opt-in
read-only monitoring endpoint on their existing verified-mTLS listener. An
operator explicitly supplies both arguments in the protected launch command:

```sh
--operations-url https://control.example.org:9443/ops/ready \
--operations-workload spiffe://example.org/operations/monitor
```

The URL must use the same authority as every configured application endpoint and
a distinct path. These flags require `--custody-root`. A monitor identity must
be separately enrolled in the listener's workload CA; the launchers reject
reuse of their configured agent, gateway, reporting source or administrative
workloads. No monitoring endpoint exists when the flags are omitted. The shipped
units do not enable one automatically: enroll the monitor and update the exact
protected launch command in the selected deployment.

Send an empty GET using the monitor's actual client certificate and key. The
endpoint checks the exact verified SPIFFE identity, Host and raw path, refuses
browser Origin, queries, request bodies and other methods, and returns
`Cache-Control: no-store`. Monitoring uses its enrolled mTLS identity, consumes
no access-token/DPoP replay entry and grants no application permission. The
application endpoints retain their independent authentication and authorization.

Responses use `KF-SERVICE-READINESS-0.1-draft`, with a role, observation start
time, elapsed milliseconds, `scope: "local_prerequisites"`, `ready`, checks, and
`execution_authority: false`. Each check reports `ready`, `refused`,
`unavailable` or `unverified`. HTTP 200 requires every check to be ready; other
observations return 503. Request-boundary refusals and saturation can return a
plain refusal without a report. Only one probe runs per endpoint at a time;
one five-second budget covers the entire observation. A timeout reports an
unavailable probe. Always query live and check the response; never retain a
report as a lease or substitute process/socket activity for readiness.

| Role | Live read-only prerequisites |
| --- | --- |
| Control | Ledger reads with configured restore/family guards; installed control, current acknowledgement, domain revocation and active native reservation matched to the configured reservation scope/policy/ownership |
| Broker | Guarded ledger reads; installed control pinned to this broker's tool and trust digest, acknowledgement and active configured native selection; fresh published subject/actor identity material |
| Governance | Guarded ledger reads; administration remains available after execution stops |
| Collector | Guarded ledger reads; receipt delivery/query remains available after execution stops |
| Gateway | Guarded reads and current control/acknowledgement matched to independently pinned installation keys, gateway identity, issuer keys and tools; fresh broker and SQL-target monitor observations |
| SQL target | Separate read-only executor and query-role catalog/permission checks, through the running store and configured kernel peer pin |
| Recovery | Guarded ledger reads and the running client's authenticated, query-only target path; execution stop/expiry does not block existing-attempt recovery |
| Supervision | Recovery prerequisites, current local reporting material custody, and a fresh collector monitor observation |

The control probe uses its native reservation scope or an explicit
`operations_scope` object in the protected control configuration. For a plain
leaf, copy the exact `scope` from the approved governance registration; the
service checks its gateway audience and descriptor digest, then compares its
full binding, policy and ownership against current installed control. A
conflicting reservation scope refuses configuration. Omitted scope selection
reports `unverified`, even when the process listens; present null, malformed or
unknown-field scope objects refuse decoding. A broker identity provider without a token-free material
probe also reports `unverified`. Published identity observation checks live
signed head/snapshot consistency, retained epoch policy and current snapshot/key
intervals; it does not obtain a token or test provider issuance.

Probes issue only reads and comparisons. They never enroll, acknowledge,
allocate, reserve a witness transition, consume proof capacity, sign/mint,
dispatch, repair a stale head or synthesize an outcome. A native stop or expired
acknowledgement makes execution prerequisites refuse while administration and
receipt handling remain usable. A missing, pending or mismatched restore
witness blocks all affected roles. Every actual operation still performs its
fresh authorization and final authority comparisons; a successful probe cannot
authorize a future operation or guarantee a particular request's result.

During shutdown the shared listener closes immediately and rejects new work on
existing keep-alive connections with 503/no-store. Already running probes cannot
return healthy after drain begins. In-flight operations retain their bounded
completion window; worker monitor listeners stop with their owning worker.
A failed worker monitor listener is reported as unavailable; query-only recovery
may continue, and monitoring clients must not use an earlier healthy reply.

## Gateway upstreams

In protected gateway configuration, `operations_dependencies` explicitly supplies
both `broker` and `target` objects. Each object contains `url`, `ca`,
`certificate` and `private_key`, with absolute paths inside the gateway's custody
root. The URL must share its actual application upstream's origin and use a
different path. Enroll these client certificates as the respective upstream
monitor identities; application workload credentials are not monitor credentials.
Local preflight loads this material without making requests. Missing dependency
configuration reports `unverified`, even if upstream TCP ports listen.

Every probe requests a new no-store observation, checks the exact response URL,
profile, role, scope, complete unique check set and HTTP/result agreement, and
rejects stale, future or malformed reports. Observations must start no more than
ten seconds before receipt and no more than one second in the future; synchronize
deployment clocks. There is no cached healthy fallback. Upstream certificate/CA
material is sampled at startup and still needs a qualified rollout procedure.

## Recovery and supervision listeners

Workers have no application listener to share. An optional `operations` object in
the protected recovery configuration enables a separate monitor-only listener:

```json
{
  "listen": "127.0.0.1:9450",
  "external_url": "https://recovery.example.org:9450/ops/ready",
  "monitor_workload": "spiffe://example.org/operations/monitor",
  "certificate": "/etc/kedgeflow/recovery/monitor-server.pem",
  "private_key": "/etc/kedgeflow/recovery/monitor-server-key.pem",
  "workload_ca": "/etc/kedgeflow/recovery/monitor-ca.pem"
}
```

For supervision this object lives under `recovery.operations` and additionally
requires a `collector` object with `url`, `ca`, `certificate` and `private_key`
for the collector's enrolled monitoring endpoint. Its origin must match the
configured delivery collector. Standalone recovery refuses that extra collector
selection. Monitor identity must differ from the recovery source identity.
Present null, malformed or unknown configuration fields refuse decoding.
All new files use the retained protected root. `--check` loads material without
listening or making requests; `--once` also creates no monitor listener.

Recovery checks its actual query client using a random, valid attempt ID and
the existing query-only protocol. The qualified SQL path authenticates its
service identity/token and reads through its query role. An exact, authenticated
missing-outcome reply establishes query availability for this probe only. It
never means that an original attempt had no effect: normal recovery's unknown
handling is unchanged, and the probe creates no candidate, receipt or outcome.
Query bearer tokens and client TLS retain their configured startup snapshots;
the probe tests that running client. Rotate them with a qualified restart
procedure rather than assuming file replacement changes an existing client.
Unsupported query providers report `unverified`. SQL executor withdrawal makes
new execution unready while the query role can remain available for recovery.
Supervision's `delivery_material` check reloads the configured token/proof source;
it proves current material custody/shape, not bearer-token acceptance by the
collector. Actual delivery and original-receipt lookup retain their full checks.

Read-only checks do not test write permissions or complete network/workload
behavior. Metrics/alerts and Linux-installed monitoring remain open. Service certificate/CA rollout, monitor revocation,
full topology and capacity qualification remain deployment gates in
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md).
