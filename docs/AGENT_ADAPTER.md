# Use the draft Node leaf Agent Adapter

The [reference adapter](../sdk/node/agent-adapter.mjs) connects an unmodified
official MCP client 2.3.0 to live admission/issuance and the protected gateway.
[RFC 0008](rfcs/0008-agent-replay-and-status.md) defines this bounded increment.
It supports one mock resource/action or the explicitly named
[RFC 0025 PostgreSQL reservation action](rfcs/0025-postgres-leaf-binding.md), inline
grants and query-only retained execution status. The SQL path requires exact
signed CTD schema/version and negotiated SQL discovery. Its native integration
tests use real PostgreSQL with generated identity/evidence; enterprise deployment
and enrolled Evidence services remain acceptance work.

The integrating application supplies:

- The official SDK `Client` and `StreamableHTTPClientTransport` constructors.
- Fixed HTTPS gateway/admission/issuer URLs, shared delegation audience, tenant,
  subject/workload, tool name, exact signed descriptor/digest and role public keys.
- An enrolled proposal signing key, PoP signing key and current access-token
  provider. The adapter verifies the pinned token signature and identity binding.
- A configured evidence source with `prepareProposal(context)` and
  `collect({proposal, proposal_digest})`. Sources obtain current baseline state
  and return signed manifest/witness records from approved providers. They must
  not receive authority/issuer keys or target mutation credentials.
- A protected durable operation store, and a pinned mTLS `fetch` implementation.
  [transport.mjs](../sdk/node/transport.mjs) supplies an HTTPS/TLS 1.3/HTTP 1.1
  implementation with an explicit URL allowlist, deadlines and response bounds.

Applications may import the ESM files directly. The module receives SDK
constructors from the application so it uses the application's pinned package;
it does not load or modify the test harness's installed SDK.

```js
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { AgentAdapter } from '../sdk/node/agent-adapter.mjs';
import { FileOperationStore } from '../sdk/node/store.mjs';

const agent = new AgentAdapter({
  Client, StreamableHTTPClientTransport,
  config, fetch: pinnedFetch, tokenProvider,
  proposalKey, dpopKey, evidenceSource,
  store: new FileOperationStore('/protected/application/kedgeflow-operations')
});
await agent.connect();
const result = await agent.execute({
  qid: stableOperationId,
  arguments: { node: registeredResourceId, expected_version: observedVersion }
});
const status = await agent.status(stableOperationId);
await agent.close();
```

`config` uses the exact fields shown in the constructor: `gatewayUrl`,
`admissionUrl`, `issuanceUrl`, optional `statusUrl`, `delegationAudience`, `tenant`, `workloadId`,
`subject`, `toolName`, `descriptor`, `descriptorDigest`, `registryKeys`,
`proposalKeys`, `manifestKeys`, `evidenceKeys`, `admissionKeys`, `issuerKeys`,
`proposalKeyId` and `authorizationKey`. Public-key maps and `authorizationKey`
use unpadded base64url Ed25519 public bytes. Signing arguments are Node KeyObjects.
The optional clock override is a trusted test boundary; production uses UTC now.

Set gateway `delegation_audience` equal to the control service's approved value;
the gateway grant audience remains its exact external URL. Set a consequential
tool's distinct `status_scope`, such as `kf.status`, and grant that permission
explicitly. Empty scope disables status. Align the CTD and installed gateway
configuration deliberately; sample configurations are not a complete deployment.

The adapter pins discovery, rejects substituted/expired remediation, signs a
frozen exact proposal, verifies returned role signatures/bindings, and persists
the grant before execution. Every HTTP request receives a fresh DPoP proof.
Changed parameters under a retained qid conflict. Use a new operation identity
and fresh admission for an intentionally different action.

Repeated `execute` on legacy records or any operation that may have begun admission
resolves status, even if unissued or unclaimed. Opt-in [lease preparation](AGENT_STATIC_LEASES.md)
can resume only before its permanent authority-start marker; it never resumes
a possibly authorizing send.
After a possible send, query errors remain unavailable/unknown. The adapter does
not automatically dispatch again, renew a grant or refund authority. A local
record without a grant uses RFC 0009 signed-proposal lookup when `statusUrl` is
configured. Pin this exact URL and permit it in `mtlsFetch.allowedUrls`; configure
paired control `status_url`/`status_scope` with a separate disclosure permission.
`unissued` is a linearizable absence snapshot and never permission to retry; an
in-flight issuer task can still commit. Without the endpoint or authorized
current identity, the client preserves ambiguity as unavailable.

For recovery under a renewed status-only token, use
`await agent.connect({queryOnly: true})`, then `status(qid)`. The subject,
workload and PoP key must still match and the tool must remain registered. Grant
expiry or domain revocation does not by itself prevent authorized history queries.
Current workload/token/scope revocation can prevent disclosure.

Provision protected application storage/key custody under the deployment
identity and retention policy. Store operations take an
exclusive lock; a process crash retains it until explicitly recovered. Status can
read without the execution lock. Do not expire a lock or infer no effect from its
age. Failed grant-store writes are tested to prevent dispatch; lock recovery, power
loss, key history and stale backup qualification remain open. A committed status alone contains no retained
target receipt body; outcome evidence/recovery is M4 work.

The [verification record](../results/verification/rfc-m3-agent-2026-10-11/README.md)
contains real native TLS/etcd tests with fresh software evidence, ordinary client
process restart, lost replies and expired/revoked grant status. Software provider,
credential broker and guarded target fixtures do not establish enterprise trust
or real-target writer coverage.

See [RFC 0009](rfcs/0009-operation-status.md) and its [fresh operation-status evidence](../results/verification/rfc-m3-operation-2026-10-11/README.md) for the bounded M3b implementation.

[RFC 0037](AGENT_STATIC_LEASES.md) adds optional `config.leases`, static/JIT provider
interfaces, non-authorizing `prevalidate`, durable static cache reuse and fresh
JIT admission. Without that registration the original flow and saved records
remain unchanged.
