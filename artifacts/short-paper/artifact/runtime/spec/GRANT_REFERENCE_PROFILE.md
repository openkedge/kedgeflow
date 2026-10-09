# KF-GRANT-REF-0.1 — optional governed MCP grant transport

Status: proposed, bounded reference implementation. This transport supplements
KF-MCP-0.1. It changes neither KF-JSON-0.2 signed records nor the remediation
schema's `grant_carriage: Mcp-KedgeFlow-Grant`. It is not a core MCP feature.

## Advertisement and activation

An authenticated gateway configured with a resolver advertises
`io.kedgeflow/grant-reference` in its discovery `capabilities.extensions`:

```json
{
  "profile": "KF-GRANT-REF-0.1",
  "header": "Mcp-KedgeFlow-Grant-Ref",
  "max_resolved_grant_bytes": 65536
}
```

The caller activates the same extension on each protected call through the
existing `io.modelcontextprotocol/clientCapabilities` metadata:

```json
{"extensions": {
  "io.kedgeflow/governed-mcp": {"profile": "KF-MCP-0.1"},
  "io.kedgeflow/grant-reference": {"profile": "KF-GRANT-REF-0.1"}
}}
```

Activation requires the base governed MCP profile as well. The gateway advertises
its inline value cap, currently 6144 bytes, under the base extension as
`max_inline_grant_header_bytes`. Each deployment must verify its smallest field
and aggregate header budgets, including authentication and intermediary-added
fields. These reference limits do not promise compatibility with every route.

## Reference identity and unchanged authority

Exactly one `Mcp-KedgeFlow-Grant-Ref` value contains exactly 64 lowercase
hexadecimal characters. They encode the existing grant digest:

```
SHA-256(UTF8("KedgeFlow/KF-JSON-0.2/grant") || 0x00 ||
        JCS(complete signed grant envelope))
```

The envelope includes its signature, key ID, schema and payload. Proposal digest,
grant ID and signature-stripped payload digest cannot substitute. The reference
is an opaque store key, never a caller-provided URL, redirect or nested reference.
Exactly one carriage is permitted: inline or reference. Duplicate/mixed headers
are refused. Read-only calls accept neither carriage.

After caller authentication, registered-tool authorization and activation, the
gateway resolves the digest through a trusted resolver. It bounds response size
and time, verifies the original signed envelope with its independently enrolled
issuer key and pinned schema, compares the full-envelope digest, binds the exact
caller/action, and performs the unchanged atomic ledger claim. Final validity,
policy, ownership and generation checks remain required before dispatch.

Reference retrieval grants no authority. Usability ends at signed grant expiry;
shorter store retention is permitted but can only make lookup unavailable.
Missing, denied, unavailable, malformed, oversized, expired or mismatched
retrieval does not create a claim, target credential or effect. Cached immutable
envelopes require the same current checks on every execution. Deleting a grant
from the store cannot refund consumption. Changing carriage or RPC ID cannot
permit a second claim.

## Pinned HTTPS resolver contract

The reference client implements a POST to one operator-configured HTTPS endpoint
with TLS 1.3, verified server trust and gateway client authentication. It sends a
closed `GrantReferenceQuery` containing:

| Field | Meaning |
| --- | --- |
| `grant_digest` | Immutable full-envelope digest |
| `subject` | Authenticated `{iss, sub}` human subject |
| `workload_id` | Authenticated requesting workload |
| `dpop_jkt` | Bound proof-key thumbprint |
| `delegation_digest` | Validated delegation-context digest |

The service authenticates and authorizes the gateway, then applies retrieval
policy for the stated subject/workload/delegation scope. Those fields are trusted
context from an authorized gateway, not credentials that arbitrary clients can
self-assert. The gateway relays no caller token, DPoP proof, cookie or target
credential. The service returns the original signed envelope as the response
body with HTTP 200; every other status refuses retrieval. Error bodies are not
passed to the caller. The client rejects redirects and compressed responses,
bounds raw envelopes at 64 KiB, and limits lookup to two seconds or the shorter
parent deadline. An envelope exceeding the cap requires a different explicitly
versioned profile; it is not truncated or exempted from verification.

Endpoint/CA configuration is outside agent authority. Network policy must pin
the permitted resolver destination and protect DNS/routing trust. Deployments
must implement store-side retrieval ACLs, immutable storage, authorized grant
publication, rate/concurrency bounds, retention and audit controls. The supplied
client and scoped tests do not implement that production service.

## Client handling

Choose supported carriage before execution. A proxy header rejection is not a
KedgeFlow `NEEDS_EVIDENCE` result and cannot justify a fresh grant. If delivery
may have occurred, query the existing attempt/root. The same unchanged grant may
be submitted through supported reference carriage; the shared claim ensures
that an already consumed grant cannot dispatch again. Never fall back to direct
target invocation. Admission and grant publication to the trusted store remain
the deployment's authenticated control-plane work.

The prototype CLI accepts the optional trusted pair `grant_resolver_endpoint`
and `grant_resolver_ca`; omitted fields leave reference transport disabled.
The existing gateway client certificate authenticates to the resolver. An
independent store/client interoperability exercise and real intermediary-route
tests remain deployment gates.
