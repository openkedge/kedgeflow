# Run the draft administrative control service

`kf-governance` implements the signed publication, registration, installation,
acknowledgement, revocation and query contract in [RFC 0007](rfcs/0007-enforcement-control-http.md).
It runs on a separate fixed administrative URL with independent permissions.
Agent admission and issuance remain on `kf-control`.

[governance.example.json](../config/governance.example.json) contains public
software fixture enrollment and an operator registration. It includes the
existing control configuration to compute Cedar/rule pins; it does not read its
admission or issuer private-key files. Provision actual workload/subject roles,
role-separated signing keys, pinned TLS material and namespace-scoped etcd RBAC.
The sample workload assignments and public keys are test data. Its registration
and the generic gateway template must be aligned deliberately; they do not form
a working deployment by copying URLs.

```sh
cargo build --locked --bin kf-governance
cargo run --locked --bin kf-governance -- \
  --config config/governance.example.json --print-registration
cargo run --locked --bin kf-governance -- \
  --config /etc/kedgeflow/governance.json --check
cargo run --locked --bin kf-governance -- \
  --config /etc/kedgeflow/governance.json
```

`--print-registration` validates public policy/rule/role configuration and prints
the approved registration without private-file reads or network calls. `--check`
also validates TLS/client material and the etcd token file, but probes no remote
state and publishes nothing. Administrative signing keys belong to the assigned
clients; this service only holds their public verification keys.

Use a fresh managed authority namespace and qualified target population for the
first deployment. Both [control](../config/control.example.json) and
[gateway](../config/gateway.example.json) set `require_control: true`, so a missing
installation refuses authority. Unmanaged mode is retained for historical fixtures;
an installed managed marker always enforces control regardless of that setting.
The service never deletes this marker, old roots, nonces, deduplication keys,
fence allocations or revocations. Existing target fences, imported authority and
stale restores need separately authorized qualification before cutover.

The activation sequence is:

1. The assigned Policy Authority signs/publishes the exact approved Cedar
   definition and registration.
2. The registry administrator signs/registers the approved signed CTD and same
   registration. The service verifies the CTD's separate frozen-record role.
3. The coordinator signs/installs those exact publication digests with the next
   revision and expected current revision. Publication alone does not activate it.
4. The enrolled native gateway verifies the installation signer and its actual
   tool/verifier configuration, then signs a bounded acknowledgement. The control
   service checks the verified gateway workload and signature before persistence.
5. Admission/issuance and execution compare the exact installation and current
   acknowledgement, plus revocation absence, in their authority transactions.

Configure the gateway's `enforcement` object with the fixed administrative URL/CA,
coordinator public keys, enrolled component/workload and protected base64-encoded
32-byte acknowledgement seed file. A managed gateway also requires an etcd token
file. `kf-proxy --check` reads/validates local acknowledgement material and contacts
no service. A running gateway acknowledges before accepting calls and renews the
record. Expired or changed unsupported installations block new transitions;
they do not restore consumed allowances or retract already possible dispatches.

Each administrative request uses the separate draft profile and an `apply`
envelope containing the signed record string, or a query-only `query` envelope.
Publication/install/revoke/query clients use mTLS plus access token/DPoP and their
assigned scope. Gateway acknowledgement uses its enrolled mTLS identity and
record signature. See RFC 0007 and its schema for exact signed fields, domains,
closed failures and unchanged retry rules.

Revocation targets a domain, root or grant and records a permanent signed
tombstone. It blocks transitions that serialize after it. A dispatch authorized
first may already send; a timeout or revoke response does not prove no effect.
Retain attempts and resolve outcomes through the declared recovery path.

The [verification record](../results/verification/rfc-m2-control-2026-10-11/README.md)
includes native TLS, actual etcd, acknowledgement renewal and race cases. The
bounded [M3a adapter/status increment](rfcs/0008-agent-replay-and-status.md) now
provides live acquisition/carriage and original-attempt resolution.
[M3b](rfcs/0009-operation-status.md) adds signed-proposal status without a local
grant and bounded client fault qualification. M4 signed outcomes/recovery is next.
Enterprise enrollment/RBAC, full writer coverage, restore and a real target remain
later release gates.

[M4b3 history](CONTROL_HISTORY.md) now appends an immutable governance event in
each successful mutation transaction. Exact current-record retries append nothing;
a history-head conflict requires an unchanged retry. Existing managed domains
without history genesis refuse new mutations/export until an approved migration
contract is supplied. A separately registered observer can attest a retained
prefix for offline reconstruction; operation-bound control state remains unproven.
