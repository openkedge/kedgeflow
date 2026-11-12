# RFC 0067: Active Terraform/provider failure boundaries

Status: draft; N2g bounded lifecycle increment. No wire-profile change.

The shared protected Terraform subprocess boundary kills remaining members of
its process group immediately when Terraform exits. It then drains bounded
output and retains the existing sanitized failure path. Timeout and future
cancellation still kill the group. No new CLI flags, caller-selected executable,
environment fallback or authority path is introduced.

Qualification observes a real provider mutation held at a pinned test-only
loopback Kubernetes gate, after the native original intent is retained. A live
provider kill, live Terraform kill and expiry-driven cancellation must preserve
ordinary unknown, with the actual parent/process-group chain and local cleanup
recorded. The Terraform-kill case must finish promptly despite inherited pipes.

The cancellation case forwards the captured request after ordinary unknown and
local group cleanup. Its possible real target effect proves the absence of a
local process is not a no-effect barrier. Backend nonprogress and a matching
current target cannot resolve or release the original held allowance. Cold
original status queries never issue another apply, claim, permit or dispatch.

This is generated same-host software evidence with a fixture-administered API
and audit policy. The test gate is outside the production runner. Malicious
process-group escape, gateway SIGKILL while children are active, Linux cgroups,
service/credential custody and target-side late-effect barriers remain open.
See the [qualification guide](../TERRAFORM_ACTIVE_CHILD_QUALIFICATION.md).
