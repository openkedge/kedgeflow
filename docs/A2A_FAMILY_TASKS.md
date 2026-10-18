# A2A family coordination peer

[RFC 0053](rfcs/0053-family-coordination-tasks.md) implements core A2A v1 task
exchange for signed RFC 0052 family commands. A completed task records delegation,
attachment or stop; each child still needs fresh native admission and execution.

Enroll and attach the protected family as described in
[FAMILY_AUTHORITY.md](FAMILY_AUTHORITY.md). The peer's closed configuration has:

- `authority`: the exact existing `kf-family` configuration, including registration,
  namespace, etcd mTLS/token files and any required restore gate.
- `listen`, `external_url`: the bound socket and fixed HTTPS JSON-RPC endpoint.
- `certificate`, `private_key`, `workload_ca`: protected server mTLS material.
- `oidc_issuer`, `oidc_public_key_base64`, `delegation_audience`: approved independent
  subject-token verification pins; tokens must bind their DPoP key.
- Optional `shared_auth`: the existing durable replay registration/capacity profile.
  Use it for replicas/restarts; omitting it leaves process-local replay protection.

Every RPC identity must have `kf.family.coordinate` and match an approved family
signer principal's subject and verified SPIFFE workload. A mutation must also be
signed by that same principal. The peer cannot enroll a family, create a catalog
entry, mint a native grant or execute a target.

```sh
kf-family-peer --config /protected/family-peer.json --check
kf-family-peer --config /protected/family-peer.json
```

`--check` validates protected local material without querying etcd or listening.
Normal startup exposes mTLS card discovery at `/.well-known/agent-card.json` and
RPC at the exact configured path. Requests must activate the required extension
and version `1.0`. Streaming, push, extended cards, URL/file parts, arbitrary
contexts, notifications and batch requests are unsupported.

Use the actual A2A JavaScript client with its documented fetch injection:

```js
import { ClientFactory, JsonRpcTransportFactory, DefaultAgentCardResolver }
  from '@a2a-js/sdk/client';
import { familyTaskFetch } from './sdk/node/family-task-transport.mjs';
import { FamilyTaskAdapter, signFamilyCommand }
  from './sdk/node/family-tasks.mjs';

const fetch = familyTaskFetch({ tls, endpoint, tokenProvider, dpopKey });
const factory = new ClientFactory({
  transports: [new JsonRpcTransportFactory({ fetchImpl: fetch })],
  cardResolver: new DefaultAgentCardResolver({ fetchImpl: fetch }),
});
const client = await factory.createFromUrl(new URL(endpoint).origin);
const family = new FamilyTaskAdapter({ client, registration });
const status = await family.status();
const command = signFamilyCommand({
  registration, operationKey: stableOperationKey,
  expectedHead: status.familyHead,
  action: { operation: 'attach', parent: approvedParent, child_id: approvedChild },
  issuedAt, expiresAt, keyId, key: familySigningKey,
});
// Persist this exact signed command before sending.
const task = await family.apply(command);
```

The host supplies protected TLS/key/token material; none is placed in an A2A
DataPart. The helper fixes both URLs, bounds requests/replies, refuses redirects
and proxies and makes a fresh DPoP proof for every RPC. The test dependency pins
`@a2a-js/sdk` 1.0.1; the host controls its own dependency/runtime installation.

If a reply is lost, query `family.queryOriginal(command)` under its stable derived
task ID, or replay that exact signed command. Do not generate another operation
key, sign a changed command automatically, infer no allocation from silence, or
use a task ID as a child grant. Stop and expiration preserve historical reads and
all held allowances. `cancelOriginal` returns TaskNotCancelable for a completed
coordination task; stop requires its own signed family command.

The bounded peer and official SDK client establish core software interoperability.
An independently implemented authority server, complete multi-contract saga and
physical Kubernetes drain remain separately qualified work. Task artifacts are
coordination records, not complete execution evidence or deployment acceptance.
