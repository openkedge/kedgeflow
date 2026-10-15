# Run the draft admission and issuer service

`kf-control` exposes the two authenticated leaf operations in
[RFC 0006](rfcs/0006-leaf-control-http.md), with optional historical status under
[RFC 0009](rfcs/0009-operation-status.md). It verifies signed input chains,
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

Before managed requests can succeed, the
[administrative service](GOVERNANCE_SERVICE.md) must publish/register/install the
matching scope and the enrolled gateway must acknowledge it. Production examples
set `require_control: true`. Admission and issuance compare installed scope/trust,
fresh acknowledgement and revocations in their authority transactions. Operator
policy/provider pins still require an approved configuration change before new
definitions can be accepted. Starting the service or printing pins installs nothing.

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

The [fresh lifecycle verification record](../results/verification/rfc-m2-control-2026-10-11/README.md)
records real TLS/etcd tests. The [Agent Adapter](AGENT_ADAPTER.md) now supplies a
live admission/issuance → gateway → guarded mock workflow using the official
client; gateway `delegation_audience` must match the control registration.
Shared DPoP replay state, enterprise enrollment, target
bootstrap and writer coverage remain gates in the [plan](IMPLEMENTATION_ROADMAP.md).

The optional [RFC 0009 status endpoint](rfcs/0009-operation-status.md) requires
paired `status_url`/`status_scope`, a distinct fixed path on the same origin and
current disclosure permission. It authenticates the signed proposal and resolves
historical operation state after expiry without issuing or returning a grant.

The optional [M7c static lease endpoint](STATIC_ADMISSION_LEASES.md) uses a separate
profile and scope at `/leases`, with fixed-subject operator membership commands.
Existing no-lease request shapes stay unchanged. When configured, membership
withdrawal also blocks ordinary full-evidence admission and issuance, including
retries. Historical status stays query-only.

The optional [M8c1 A2A root-reference resolver](A2A_ROOT_RESOLUTION.md) uses the
separate activated draft endpoint `/a2a/root:resolve`. Protected `a2a` configuration
and explicit create-only reader ACL enrollment are required. Operator commands
print an extension fragment, enroll the ACL or permanently withdraw it. Resolution
authenticates current readers and returns narrowed reservation views with no
execution authority; it does not implement core A2A messaging or child issuance.

The explicit [M8c2 hierarchical leaf profile](HIERARCHICAL_LEAF_AUTHORITY.md) uses
the same protected `reservation` configuration and enrollment/stop commands, with
signed static nonexecutable composites and identity-to-parent assignments. Fresh
leaf admission remains mandatory; native issuance atomically binds child cost and
the separately signed hierarchical supplement. No HTTP parent/cost selection or
dynamic delegation endpoint is added.
