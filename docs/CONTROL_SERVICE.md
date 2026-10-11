# Run the draft admission and issuer service

`kf-control` exposes the two authenticated leaf operations in
[RFC 0006](rfcs/0006-leaf-control-http.md). It verifies signed input chains,
evaluates the pinned Cedar policy, retains certificates and evidence atomically,
and issues one durable grant per operation with authority-owned identifiers and
resource fences. The executable scope is the existing single-resource mock
action with `node` and `expected_version`, `version_eq`, `FencingToken` and
`dispatch_bound` completion.

Start from [control.example.json](../config/control.example.json). Its public
keys, identities, descriptor and evidence rules are software fixtures. Provision
trusted production registrations and independently signed, fresh matching records
before using a deployed service. The sample contains paths to required private
material, not private keys or working deployment credentials.

The operator supplies the HTTPS listener certificate/key, workload CA, pinned
authorization-server key, allowed subjects/workload, distinct `kf.admit`,
`kf.issue` and action scopes, and role-separated proposal/registry/manifest/
provider keys. Admission and issuer seed files contain base64-encoded 32-byte
Ed25519 seeds. Protect these files and the configuration from agent writes and
reads of private material. The service and etcd client use separate TLS
certificate/key paths. etcd requires a pinned CA and namespace-authorized token
file; this binary has no unauthenticated production store mode.

```sh
cargo build --locked --bin kf-control
cargo run --locked --bin kf-control -- \
  --config config/control.example.json --print-pins
cargo run --locked --bin kf-control -- \
  --config /etc/kedgeflow/control.json --check
cargo run --locked --bin kf-control -- \
  --config /etc/kedgeflow/control.json
```

`--print-pins` validates public registration, schemas and Cedar source and prints
the computed policy, evidence-rule, descriptor and ownership pins. It reads no
private key files, contacts no remote service and installs nothing. `--check`
also loads signing and TLS material and checks service-role consistency. It does
not listen, probe etcd availability/RBAC or certify installed authority.

Before requests can succeed, a trusted authority caller must install matching
policy and ownership state in the selected ledger namespace and conflict domain.
The existing library publication port is not an agent API. Authorized policy/
registry/install/revoke endpoints and acknowledgements are the next M2c increment.
Static operator descriptor/provider pins are not a live control-ingestion protocol.
Neither starting the service nor printing pins installs or bootstraps counters.

Clients POST the closed draft `admit` or `issue` envelope as `application/json`
to the exact configured URL using a verified workload certificate, access token
and fresh DPoP proof. The shared `delegation_audience` binds the same delegation
across these two paths; proof `htu` binds each exact path. `gateway_audience`
separately limits the grant. Changing the bound token, signed proposal or
certificate requires following the operation conflict rules, not merely a new
request ID. See RFC 0006 for sizes, errors, retry and retention behavior.

Retain certificate/chain, issuance, allocation and counter records. Retries after
restart load and reverify raw signed evidence. Old admissions missing a chain
refuse issuance. Expiry never permits deleting a deduplication key or replenishing
consumed authority. Fences cover one ledger namespace and tenant/resource/
incarnation; a fresh counter starts at one. Existing target fences need an
authorized bootstrap and restore barrier before target cutover. The allocator
does not enroll legacy or external writers.

The [fresh verification record](../results/verification/rfc-m2-service-2026-10-11/README.md)
records real TLS/etcd tests. A live Agent Adapter → control → gateway → target
workflow, shared DPoP replay state, enterprise enrollment, target bootstrap and
writer coverage remain later gates in the [plan](IMPLEMENTATION_ROADMAP.md).
