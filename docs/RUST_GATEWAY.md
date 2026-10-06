# Rust reference gateway and adopter responsibilities

The Rust integration ports the bounded Go execution prototype from the whitepaper
repository's `acp/prototype` at commit `517dc9d`. It preserves the target repository's
v0.9 contracts/fixtures at `8c07a55` and its earlier Python demo. The nine role names
and six interfaces are proposed vocabulary, not an adopted standard.

## Interfaces implementers bring

| Rust port / contract | Required behavior |
|---|---|
| `Authenticator` | Return independently verified subject, workload, proof key, delegation digest and scopes; request-supplied identity headers are insufficient |
| `AuthorityLedger` | Atomically conserve policy/ownership, active root generation, fence, nonce, attempt and outbox; no local fallback after store failure |
| `CredentialBroker` | Exchange after claim; preserve signed grant/attempt and subject/actor bindings; return narrowly scoped target authority within signed validity |
| `ResourceAdapter` | Use a fixed registered mapping and trusted client; enforce actual guard/effect semantics and return correlated completion or uncertainty |
| `GrantResolver` | Optionally retrieve one immutable complete envelope under gateway/requester authorization; references confer no authority |
| `OutcomeQuerier` | Query an existing attempt, validate target evidence/correlation, and never redispatch |
| `Clock` | Supply trusted verifier time; deployment must bound clock uncertainty |

These library ports support the architectural interfaces; they are not a complete
network protocol or permission grant to arbitrary callers. Authority and outcome
services must protect their administrative ports separately.

## Configuration and transport

The command-line interface (CLI) accepts strict JSON with no duplicate/unknown keys.
One pinned HTTPS etcd member endpoint is required. Replicas can use different members of the same
cluster and namespace; this client does not retry an ambiguous mutation against
another member. Account for the endpoint's availability. The etcd v3 HTTP JSON
gateway must be enabled and access must be independently protected.

The JSON gateway does not map a TLS certificate Common Name to an etcd access
control user. With etcd role-based access control (RBAC) enabled, configure
`etcd_token_file` containing a separately acquired namespace-scoped etcd token.
The CLI loads that token at startup; token renewal/replacement requires an operator
restart. Expired or rejected credentials fail closed. Do not disable authorization
to work around this profile's lifecycle limit. See the [official gateway authentication
contract](https://etcd.io/docs/v3.6/dev-guide/api_grpc_gateway/#authentication).

Inbound workload enrollment uses the configured workload certificate authority
(CA). Every peer completes verified TLS 1.3 and supplies exactly one valid Secure
Production Identity Framework for Everyone (SPIFFE) URI. The external Host/path
is pinned before authentication; browser Origin headers are refused. The native
server uses HTTP/1.1; notifications, batches,
streaming, HTTP/2, TLS offload and session resumption profiles are absent. The
gateway certificate needs the intended server/client key usages for the native
listener and separate outbound authenticated channels.

Subject authentication uses a pinned issuer Ed25519 key and Demonstrating Proof
of Possession (DPoP)-bound `at+jwt` access tokens, not OpenID Connect login tokens.
DPoP binds the token, POST method and exact external URL. Its bounded replay cache
fails closed when full; enterprise
issuer discovery, rotation, workload authorization and shared replay/nonce state
across replicas need integration.

The CLI's actor assertion file is bound to one `actor_workload`, which must match
the authenticated agent workload in the grant; it is not inferred from the
gateway's outbound client certificate. The authorization server separately
authenticates the gateway transport identity. Use separate configured gateways
or an explicitly trusted `WorkloadAssertion` implementation for several actors.

Broker, target and optional resolver clients accept only constructors configuring
pinned CA roots, client credentials, TLS 1.3, bounded timeouts, no environment proxy
and no redirects. Each client reuses its connection pool. The gateway builds a new
target request; caller authorization, DPoP, cookies, grants and capability/routing
metadata are not relayed.

## Four rollout frictions

1. **Native workstation paths.** Model Context Protocol (MCP) routing cannot govern
   built-in shell access
   to cloud credentials, a Docker socket or protected files. Apply independently
   administered filesystem, socket and network restrictions. A same-privilege
   daemon is not an independent boundary. This repository installs no OS sandbox.
2. **Identity-provider latency.** Assertion acquisition and exchange share a
   five-second budget capped by parent/grant validity. Token usability starts
   conservatively at exchange start; the receipt-time expiry upper bound must
   fit the grant. Expiry is rechecked after exchange and final ledger authorization.
   Measure tail latency; never extend consumed grants or clamp overbroad tokens.
3. **Uncertain legacy effects.** Lost responses after possible dispatch record
   unknown and retain consumption. Query-only reconciliation requires authoritative
   correlation. Legacy targets without lookup/fencing need bounded polling, an
   escalation deadline and an accountable resource owner. This implementation
   neither automates saga compensation nor refunds allowance.
4. **Header budgets.** Inline `Mcp-KedgeFlow-Grant` is capped at 6 KiB. An optional
   64-character lowercase digest reference resolves within two seconds to at most
   64 KiB of the original envelope. The resolver receives requester identity scope,
   never caller credentials. Signature, caller/action binding and the same claim
   apply after retrieval. Qualify intermediary budgets and store-side controls.

## Start with one protected action

Inventory every equivalent writer and credential path. Register one exact action,
resource incarnation, parameter schema, predicate and completion contract. Attach
an Agent Adapter that understands remediation and grant carriage; ordinary MCP
support alone does not provide that flow. Connect admission, authority and evidence
services, then qualify the target adapter, unknown-outcome recovery and on-call owner.

Run required-mode tests and target/provider fault tests before enabling protected
dispatch. Measure workflow interruption, evidence age, admission/exchange latency
and operator recovery cost. A descriptor label, passing mock test or incident
acknowledgment cannot establish a production target effect.
