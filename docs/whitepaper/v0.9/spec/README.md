# KedgeFlow v0.9 proposed wire profile

This directory specifies **KF-JSON-0.2**, a proposed normative profile for the
v0.9 paper. KedgeFlow and CTD v1.0 are proposals, not adopted industry standards.
The profile provides implementable record boundaries. A conforming deployment
also needs trusted identity, policy, evidence, ledger, and resource adapters.

`kedgeflow.schema.json` is the complete JSON Schema Draft 2020-12 definition.
`schema-paper.json` is an automatically generated, compact presentation of the
**same JSON object**, including annotations; `validate.py` checks equality.
`build_schema.py` generates both. All defined protocol objects are closed:
unknown fields fail validation. `Parameters` and `JsonValue` are the declared
application-data extension boundary and must also pass the registered, closed
action/result JSON Schema. They do not permit arbitrary authority fields.

| Envelope kind | Complete payload definition | Required issuing role |
|---|---|---|
| `proposal` | `Proposal` | Agent Adapter |
| `certificate` | `AdmissionCertificate` | Admission Controller |
| `grant` | `ExecutionGrant` | Grant Authority |
| `ctd` | `ConsequentialToolDescriptor` | Resource Registry |
| `hitl_witness`, `evidence` | `HitlWitness`, `Evidence` | Evidence Provider |
| `manifest`, `lease` | `WitnessManifest`, `AdmissionLease` | Admission Controller |
| `saga_root` | `SagaExecutionRoot` | Grant Authority |
| `remediation` | `RemediationContract` | Execution Gateway |
| `receipt` | `Receipt` (attempt/outcome receipt) | Execution Gateway, Resource Adapter, or Outcome Service, according to event |
| `delegation` | `DelegationRequest` | Authenticated Agent Adapter/delegator |
| `token_exchange` | `TokenExchangeBinding` | Execution Gateway |

The named components remain the paper's nine roles. These records bind the six
programmable interfaces; they do not introduce a seventh public interface or a
new control-plane role. Receipt status is an authoritative observation, not an
agent's assertion that its action succeeded. The fixture signer-role table is
restricted to the actual fixture producer, rather than a complete production
authorization matrix.

## Exact bytes, digests, and signatures

Each signed envelope has exactly `profile`, `kind`, `schema`, `key_id`, `payload`,
and `signature`. `profile` is `KF-JSON-0.2`; `schema` is the schema URI followed
by `#/$defs/` and the payload definition name. Registry key lookup is by
authenticated issuer role, tenant, and `key_id`. A request-supplied public key
does not establish trust.

Let `JCS(x)` be RFC 8785 canonical UTF-8 JSON, `NUL` the single byte `0x00`,
`D(k)` the UTF-8 bytes `KedgeFlow/KF-JSON-0.2/` followed by the exact kind `k`,
and `E` a signed envelope. All signatures use Ed25519:

```
signature = base64url_no_padding(
  Ed25519Sign(sk, UTF8("KedgeFlow/KF-JSON-0.2") || NUL || JCS(E without signature)))
H(q) = lowercase_hex(SHA256(D("proposal") || NUL || JCS({schema:E.schema,payload:E.payload})))
H(E) = lowercase_hex(SHA256(D(E.kind) || NUL || JCS(E)))  # every kind except proposal
H(parameters) = lowercase_hex(SHA256(D("parameters") || NUL || JCS(parameters)))
H(delegation) = lowercase_hex(SHA256(D("delegation") || NUL || JCS(Proposal.delegation)))
H(constraints) = lowercase_hex(SHA256(D("constraints") || NUL || JCS(Certificate.constraints)))
H(parameter_schema) = lowercase_hex(SHA256(D("parameter-schema") || NUL || JCS(parameter_schema)))
```

`H(q)` excludes the actor envelope's signature/key metadata so actor-key rotation
does not change the frozen proposal. Other signed-record hashes include their
complete envelope. Signed references cannot silently substitute payload hashes.
Raw access-token digests, template/rendered-byte digests, assertion-record
digests, and the WebAuthn challenge digest use ordinary SHA-256 of their exact
declared bytes, without a KedgeFlow prefix. `dpop_jkt` is the unpadded base64url
SHA-256 JWK thumbprint, not a hexadecimal digest or hash of a key label.

Digests are 64 lowercase hexadecimal characters. Ed25519 signatures are 86
unpadded base64url characters. `Time` is UTC **Unix milliseconds** as an exact
safe integer, not RFC 3339 text. Epochs, fences, quantities, and monetary micros
are safe integers; decimals use registered canonical string representations.
The validity interval is `[valid_from, expires_at)`, interpreted conservatively
under the deployment's bounded clock error.

Parse with duplicate-key rejection, reject invalid Unicode/lone surrogates,
nonfinite numbers, fractional numbers, and integers outside ±(2^53−1). Preserve
Unicode exactly; do not normalize. Sort object properties by UTF-16 code units,
as JCS requires. Set-valued arrays must have canonical ordering and unique
domain identities; schema `uniqueItems` alone does not establish identity
uniqueness. Resolve aliases/defaults before freezing a proposal. The supplied
`profile.py` implements only this explicitly restricted integer-number JCS
domain, rather than general floating-point JCS.

## Identity, human review, and temporal admission

The human subject is the OIDC `(iss, sub)` pair. The workload is an authenticated
SPIFFE ID. The proposal contains an **OAuth user-delegation access-token**
binding with issuer/audience/scopes/expiry and the validated DPoP proof-key
thumbprint. An OIDC ID token is not executable delegation authority. DPoP binds
HTTP method/URI and the access token; the KedgeFlow envelope separately binds
the exact body. The gateway must validate the live OAuth/DPoP/SVID context,
including replay/nonce/clock checks, and compare it to grant/proposal bindings.

`AdmissionLease` has `execution_authority:false`. It prevalidates static
obligations under pinned identity/policy/descriptor/ownership context. JIT
state witnesses still require final verification; a lease never reserves
resource capacity or permits mutation. The certificate carries realized
discharges, exact constraints, and the witness manifest. Unknown, absent, and
violated obligations cannot become `satisfied` because a JSON document says so.

The Resource Registry pins an immutable deterministic rendering template and
parameter schema. The approved rendering uses only the exact validated proposal
parameters, with safe escaping for the declared media type. `ApprovalPayload`
includes `H(q)`, active policy epoch, reviewer `(iss,sub)`, template digest,
rendered-byte digest, parameters digest, verdict, review/expiry times, RP ID,
and unique server nonce. The WebAuthn challenge is:

```
challenge = base64url_no_padding(SHA256(JCS(ApprovalPayload)))
```

WebAuthn authenticators sign `authenticatorData || SHA256(clientDataJSON)`;
they do **not** directly sign arbitrary JSON. The provider verifies the
challenge, RP ID, exact approved origin, UP/UV, credential enrollment, assertion
signature, replay, and the configured approved-authenticator policy. Hardware
binding requires independently trusted enrollment/attestation policy; UV alone
does not establish it. `W_hitl` is the **provider-signed verified assertion
record**, not a self-asserted approval or a fake hardware signature. Its subject
must equal the challenge's reviewer, and policy must authorize that reviewer.
The reviewer can differ from the initiating user when policy permits it.

The offline `hitl_witness.json` fixture deliberately identifies a software
emulator with hardware/attestation requirements false. It illustrates shape,
provider signing, and digest bindings. It cannot satisfy a hardware-required
production policy; the negative test checks that boundary. It is not a claim
that a real human approved this example or a physical authenticator was tested.

## Grants, saga budgets, and receipts

The grant binds the certificate/proposal/delegation, both identities, proof key,
ownership/policy epochs, exact action/resources/parameter digest, predicate
descriptor, evidence/constraint digests, adapter contract, root generation,
nonce, monotonic fence, audience, and time window. It must be claimed in the
authoritative ledger before dispatch. The ledger verifies the active grant,
current generation/epochs, unused nonce/allowance, and any saga allocation in
one atomic transaction. Resource fencing must reject stale execution after
claim; ledger serialization alone cannot prevent an uncontrolled target writer.

`SagaExecutionRoot` owns a composite forward limit and compensation reserve.
Each DAG node has one allocation and a distinct child effect root. Grants debit
the existing allocation using `saga_budget`, which binds parent ID/generation,
allocation, phase, and units. Allocation totals and consumption cannot exceed
the parent limits. Single-action delegation transfers/attenuates the one
allowance; saga delegation consumes an explicit allocation. Neither clones
authority. Budget accounting is transactional state, not a signed snapshot's
assertion. Schema cannot prove acyclicity, sum budgets, or conserve transitions.

Compensation is nullable with a declared impossibility reason. A descriptor
registers a separately admitted/preauthorized compensating action and deadline;
it does not establish a mathematical inverse or physical rollback. Outcomes
must be authoritatively reconciled before compensating an `unknown` forward
effect. Uncertain attempts retain their charge and must not be retried with a
new root. `fenced_no_effect` requires authoritative evidence that neither an
effect nor a delayed effect can occur. A timeout or cancel acknowledgement
alone is insufficient. Failure/refusal receipts use not_dispatched, failed, or compensation_failed with a non-null diagnostic. These states never assert zero effects or refund authority; only fenced_no_effect supplies that resolution contract. Composite root status also distinguishes compensated, compensation_failed and unresolved. Receipt chains append history; they never erase a
confirmed commit or turn unknown into unused budget without fenced resolution.

`TokenExchangeBinding` is an auditable typed binding of RFC 8693 inputs and
outputs. Actual wire requests are form-urlencoded and contain tokens resolved
inside the gateway from protected credentials. The STS must enforce the exact
grant attenuation through configured local policy. RFC 8693 does not make any
grant JSON universally recognizable to AWS, a database, or a SaaS provider;
those targets require compatible STS/broker integrations. Target credentials
are minted after claim, bounded to the attempt/action/grant validity, injected
only inside the gateway, and never returned to the Agent Plane.

## CTD mapping to existing tool interfaces

CTD v1.0 labels consequences and declares independent guard, completion,
idempotency, concurrency, coverage, rendering, and compensation contracts.
`ReadOnly`/`IdempotentWrite`/`StateMutating`/`Irreversible` are classification
labels, not proofs of safety. Level A describes atomicity over the **declared
scope**, not every subsequent operation. A SQL capacity reservation can be
Level A while an asynchronously dispatched Kubernetes drain remains Level C.

| Existing surface | Proposed mapping | Enforcement requirement |
|---|---|---|
| MCP `Tool.name` and `inputSchema` | Admin-registered mapping to CTD `action`, `version`, `parameter_schema`, and pinned descriptor digest | Validate exact `tools/call.arguments` against the registered closed schema; freeze canonical parameters before admission. |
| MCP tool annotations | Discovery hints that may suggest a candidate CTD tier | Do not infer authority, true read-only behavior, or guard coverage from untrusted hints. Registry validation and target-side restrictions determine coverage. |
| MCP tool `_meta["io.kedgeflow/ctd"]` | Optional `{id,version,digest,schema}` descriptor reference | This key is a proposed application convention. Resolve it through the trusted registry; the advertised reference cannot authorize execution. |
| OpenAPI Operation Object `operationId` | Admin-registered action identity and target method/path/server binding | Pin the actual deployment/server and schema version. Method names and `operationId` alone do not determine consequences. |
| OpenAPI `x-kedgeflow-ctd` | Optional `{id,version,digest,schema}` extension on the operation | This is a proposed OpenAPI extension, not an adopted OpenAPI/KedgeFlow standard. Verify its reference through the Resource Registry. |
| OpenAPI path/query/header/body parameters | Registry-configured deterministic projection into one canonical typed parameter object | Declare coercion, defaults, serialization, aliases, and excluded transport credentials before freezing `q`. Reject ambiguous/unknown fields. |
| A2A v1.0 `DataPart.data` | Closed `A2ARootReference`; advertise the extension in AgentCard capabilities | It is a non-bearer reference to authenticated ledger data. The receiver needs fresh admission and attenuated child authority. |

The gateway owns the mapping from a registered action to the upstream tool or
HTTP operation. Agents cannot choose another upstream, rewrite an action name,
or supply target credentials. Fence/idempotency injection uses registered,
protected adapter fields and cannot override the frozen business parameters.
Publish the mapping inventory alongside CTDs and declare bypass/uncoordinated
writers. A tool without a complete trusted mapping remains unclassified or
unsupported; admission must expose that gap rather than inventing a guarantee.

For a consequential MCP call without authority, return JSON-RPC error code
`-32001`, message `NEEDS_EVIDENCE`, and `RemediationContract` in `error.data`.
Its typed obligations specify provider classes, question references, static/JIT
stage, freshness, and admission endpoint. A signed remediation envelope can be
carried instead when the deployment authenticates errors at record level.
`Mcp-KedgeFlow-Grant` is a **proposed deployment header**, not an MCP-standard
extension. An opaque handle must be resolved in an authenticated ledger and
verified exactly like a full signed grant. Read-only proxying still requires
correct target classification and structured telemetry.

The optional [KF-GRANT-REF-0.1 transport](GRANT_REFERENCE_PROFILE.md) now specifies
the full-envelope digest, separate negotiation, pinned authenticated lookup,
bounds and unchanged claim rules. Its reference client is implemented in the
Go proxy. The signed schema and fixtures remain unchanged; a production
authorized grant-store service and complete network-route qualification are
external deployment requirements.

## Validation and semantic limits

From the repository root, with the listed dependencies installed:

```
python3 acp/spec/build_schema.py
python3 acp/spec/generate_fixtures.py
python3 acp/spec/validate.py
python3 -m unittest discover -s acp/spec/tests -v
node acp/spec/tests/cross_language.mjs
```

The delivered fixtures include complete signed envelope shapes, public offline
test keys, deterministic digest vectors, a CTD YAML representation equal to its
signed JSON payload, a rendered review, and an A2A reference. JWT fixtures use
public deterministic test keys and a fixed fixture clock; they are never valid
deployment credentials. Regenerating test fixtures cannot create actual target
authority. External policy/provider references describe the test scenario and
must be resolved by a real authenticated registry in deployment.

JSON Schema validates shape, field closure, enums, some local implications, and
safe ranges. It cannot establish canonical input bytes, signatures, issuer
trust, credential validity, truth/coverage of evidence, policy completeness,
cross-record digest equality, clocks, temporal ordering, budget sums, DAG
acyclicity, root/nonce atomicity, target fencing, compensation success, or
actual human/hardware approval. `validate.py` checks the delivered vectors and
specified cross-record fixture relationships. It is not a production admission
controller or security boundary; it does not simulate unavailable live trust.

Normative foundations: [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core),
[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785),
[RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032),
[RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449),
[RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693),
[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html),
[SPIFFE identities](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/),
and [WebAuthn](https://www.w3.org/TR/webauthn-3/).
