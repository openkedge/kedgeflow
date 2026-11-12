# Two-resource Terraform gateway and SDK (N2f3)

The shipping `kf-proxy` and `kf-broker` can explicitly select the
[native two-resource runner](TERRAFORM_PAIR_APPLY.md). The separate
`KF-TERRAFORM-PAIR-GATEWAY-0.1-draft` profile and
`io.kedgeflow/terraform-pair-apply` extension bind discovery and the Node
`AgentAdapter` to one protected compound plan. This remains Level C with
`target_atomic:false`.

Select `terraform_adapter.profile: KF-TERRAFORM-PAIR-GATEWAY-0.1-draft`,
`pins.profile: KF-TERRAFORM-PAIR-APPLY-0.1-draft`, action
`terraform.configmap.annotation.pair.apply` v1.0 and scope
`terraform:pair-apply`. The remaining protected pins and service custody are
identical in shape to the [single-resource gateway](TERRAFORM_GATEWAY.md).
Exactly one pinned pair tool is allowed. The runner inspects the full protected
capsule at startup and verifies the logical resource/incarnation derived from
both members. Generic HTTP fallback, crossed single/pair profiles and mixed
tool sets refuse. Existing single-resource contracts retain their profile,
extension, schema and report shape.

The independently provisioned SDK configuration uses `terraformPair`:

```js
terraformPair: {
  profile: 'KF-TERRAFORM-PAIR-GATEWAY-0.1-draft',
  manifestDigest: '<64 lowercase hex>',
  effectDigest: '<64 lowercase hex>',
  inspectionSha256: '<64 lowercase hex>',
  resource: {
    id: 'terraform-pair:<manifestDigest>',
    incarnation: '<compound resource incarnation digest>'
  },
  members: [
    { id: 'first', target_uid: '<first pinned UID>' },
    { id: 'second', target_uid: '<second pinned UID>' }
  ]
}
```

The registration must come from the trusted protected-plan enrollment, including
both exact member UIDs. Server discovery is checked against these pins and does
not supply a replacement enrollment. The
[draft schema](../spec/drafts/terraform-pair-gateway-v0.1.schema.json) defines
capabilities, metadata and client registration; runtime validation additionally
requires the resource ID to match the manifest and distinct member UIDs.

A direct successful response carries the native pair report under
`structuredContent.kedgeflow_terraform_report`, the pinned gateway metadata and
an ordinary terminal receipt. The SDK verifies the original grant/attempt/root,
resource/fence, manifest/effect, exact closed per-member observations and their
summary digest. Successful tool exit, backend progress and both exact desired
members are required. Wrong identities, member order, missing observations,
failed tools and historical partial outcomes cannot become direct completion.

A partial/unknown runner outcome causes an ordinary gateway `unknown` result.
Detailed member observations remain in the protected native intent; status does
not infer them from current targets. Lost replies resolve through the original
retained operation and status endpoint. Repeated execution, cold SDK restart,
expired/revoked grants and unavailable broker/writer do not obtain another
claim, permit, dispatch or apply. Restoring a denied permission does not repair
historical partial results. No automatic compensation, release or refund is added.

[RFC 0066](rfcs/0066-terraform-pair-gateway-sdk.md) records this separate binding.
Real gateway/SDK qualification is recorded in the dated verification bundle once
its success, lost-reply, partial and partial-lost cases complete. Production
credential custody, service isolation, active-child termination, broader graphs,
remote backends and independently administered deployment acceptance remain open.
