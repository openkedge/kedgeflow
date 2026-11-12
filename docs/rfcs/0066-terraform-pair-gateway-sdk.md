# RFC 0066: Explicit two-resource Terraform gateway and SDK

Status: draft; N2f3 bounded software binding. Deployment acceptance remains open.

## Contract

The protected gateway explicitly selects the N2f2 native pair runner under
`KF-TERRAFORM-PAIR-GATEWAY-0.1-draft`. Discovery uses only
`io.kedgeflow/terraform-pair-apply` with the pair runner profile, Level C and
`target_atomic:false`. It carries the manifest, aggregate effect and inspection
hashes. One exact protected tool, named action/scope, native authenticated
ledger and enforced control installation are required before listening.

The original gateway owns claim, credential exchange, dispatch and ordinary
publication. The native runner owns its one-shot intent before writer access.
The whole protected saved plan executes once. Single-resource and pair profiles
are distinct selections; generic HTTP transport cannot infer either adapter.

The Node adapter requires an independently provisioned `terraformPair`
registration, containing plan pins, compound resource/incarnation and ordered
member UIDs. It checks the signed descriptor, arguments, original grant,
discovery and direct successful result. The pair observation summary must hash
to the retained digest and bind both exact desired members with observation
times after initiation. Both successful tool completion and backend progress
are mandatory. Existing single-resource registration and wire shape remain frozen.

Partial application is not an ordinary terminal success. It retains the N2f2
per-member intent and publishes ordinary `unknown`. SDK status preserves that
history and adds the Level C/non-atomic label. Lost responses and cold restarts
query the original authority; no new tool dispatch or compensation is inferred.

## Validation and limits

Contract negatives cover crossed profiles, generic fallback, changed schema,
identity/member order, malformed observation and partial-to-committed promotion.
Real qualification uses the shipping gateway/broker and official MCP SDK,
ordered successful/denied Kubernetes audit events, backend bytes and get-only
target observations. Cold queries follow expiry/revocation with writer absent,
broker stopped and restored second-member permission. Native counters, intent,
backend and target-write audit events must remain unchanged.

This is generated local software evidence. Privileged writers and control-plane
changes can race Level C execution. It does not establish target atomicity,
independent administration or production credential/service custody. See the
[operator guide](../TERRAFORM_PAIR_GATEWAY.md) and
[N2f2 limits](../TERRAFORM_PAIR_APPLY.md).
