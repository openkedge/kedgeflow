# Service readiness monitoring

Control, broker, governance and receipt-collector services support an opt-in
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

Read-only checks do not test write permissions or complete network/workload
behavior. This increment does not yet cover gateway upstream dependencies, SQL
target catalogs through this endpoint, recovery worker status, metrics/alerts or
Linux-installed monitoring. Service certificate/CA rollout, monitor revocation,
full topology and capacity qualification remain deployment gates in
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md).
