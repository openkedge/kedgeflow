# RFC 0061: Protected Terraform gateway and SDK binding

- Status: Draft; explicit local gateway and Agent Adapter integration
- Profile: `KF-TERRAFORM-GATEWAY-0.1-draft`
- MCP extension: `io.kedgeflow/terraform-apply`
- Prerequisites: RFC 0059/0060 and `KF-TERRAFORM-PLAN-0.2-draft`
- Action/version: `terraform.configmap.annotation.apply` / `1.0`

The [draft schema](../../spec/drafts/terraform-gateway-v0.1.schema.json) defines
closed capability, tool metadata and SDK registration shapes.

## Selection

Protected `terraform_adapter` configuration requires one exact native tool,
plan/inspection/effect pins, custody roots, certificate gateway role, broker
issuer and independent target keys. Generic fallback, explicit null, unknown
fields and mixed tool/adapter/family/inverse selection refuse. Discovery cannot
enroll a plan; the client registration is independently pinned.

Capabilities contain exactly `profile`, `runner_profile`, `guard_level: Level_C`
and `target_atomic: false`. Tool metadata adds `manifest_digest`, `effect_digest`
and `inspection_sha256`. The closed tool schema binds those plan/effect constants,
resource ID and synthetic capsule version 1. SDK registration uses `profile`,
`manifestDigest`, `effectDigest`, `inspectionSha256` and `resource`.

## Authority and outcome

Existing admission/issuance bind the exact signed CTD and parameters. The gateway
claims the original attempt, exchanges its credential and authorizes dispatch.
The runner receives that original signed grant/attempt/parameters/credential and
performs RFC 0060's current control/native intent CAS before reading the writer.
Its internal gateway entry point returns a report without publishing an ordinary
outcome; the gateway publishes once. The public CLI retains its original behavior.
No new unauthenticated execution listener is introduced.

A committed result includes the standard correlated terminal receipt,
`kedgeflow_terraform_report` (RFC 0060's closed local report) and
`kedgeflow_terraform_binding` (exact tool metadata). SDK validation requires an
applied original intent, matching grant/root/attempt/plan/effect, bounded initiation
time, backend transition hashes and independent observation digest. No target
atomicity, fence enforcement or portable target signature is inferred.

Unknown dispatch uses the existing native unknown response/status. The SDK never
repeats a possibly sent call. Retained-grant status correlates the original
operation under current disclosure scope after execution expiry/revocation; it
does not re-observe the target or repair unknown. The gateway budget is 30 seconds
clipped by grant expiry, and subprocess execution remains bounded at 20 seconds.
Timeout after intent can leave started/unknown and cannot release authority.

See [the guide](../TERRAFORM_GATEWAY.md) and its verification record for setup,
measured results and remaining deployment/failure gates. Frozen v0.9 schemas and
old artifact versions remain unchanged.
