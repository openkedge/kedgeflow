# Gateway SIGKILL with active Terraform children (N2h)

The [verification record](../results/verification/terraform-gateway-death-2026-11-11/README.md)
contains both whole-death cases and compatibility evidence.

This qualifies the existing Level C runner's whole-process death boundary.
`SIGKILL` does not run the gateway's Rust cleanup handlers. A private Unix
process group helps when the runner future returns or is cancelled; it does
not establish a lifetime binding between the group and a dead gateway.

The owned real-target fixture reuses the pinned API gate from
[N2g](TERRAFORM_ACTIVE_CHILD_QUALIFICATION.md). It observes a started original
intent and actual live gateway → Terraform → provider chain while the original
provider PATCH is held. It kills the gateway, verifies its reaped exit signal 9,
and separately observes both live descendants after that death.

Two cases retain the original `dispatch_authorized` phase and started intent:

- Drop: explicit fixture administration stops the owned orphan group, then drops
  the captured request after original grant expiry. The target stays original.
- Late: the gate forwards the captured original request only after gateway death
  and grant expiry. Kubernetes can still commit that request. The fixture records
  orphan liveness at expiry and any explicit cleanup needed after the response.

These cases issue one original claim, permit, dispatch and intent, with zero
intent outcomes or ordinary terminal publications from the dead gateway.
Matching target state or backend progress cannot silently turn that retained
phase into committed, no-effect or released authority. Cold gateway/SDK status
queries after expiry/revocation, broker shutdown and writer removal return the
original phase without another apply or admission/issuance cycle.

The first SDK process can report unavailable because its gateway has died;
that availability observation is separate from the native retained phase.
Provider/target/backend observations are retained independently. Fixture process
cleanup is identified explicitly and is not a production supervisor or proof
that the dead gateway contained its children.

[RFC 0068](rfcs/0068-terraform-gateway-death-qualification.md) records this bounded
qualification without changing any accepted action, grant, SDK or wire schema.
Linux cgroup/service containment, production credential custody, provider escape
and a target-side late-effect barrier remain open. No retry, repair, release,
refund, force-unlock or inverse is introduced. The complete N2 deployment exit
remains open.

Replay the public local record without authority:

```sh
node scripts/verify-terraform-gateway-death.mjs results/verification/terraform-gateway-death-2026-11-11
```

In the recorded late case, both descendants were observed immediately after
gateway death but had ended by the expiry snapshot. The queued original request
still committed afterward. This records liveness at each boundary; it does not
claim the descendants ran through expiry or that their termination was a
qualified production containment mechanism.
