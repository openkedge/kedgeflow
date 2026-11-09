// Exact protected saved-plan selection. Level C; local observed effect only.
import { digest, exact, same } from './records.mjs';
export const TERRAFORM_ACTION = 'terraform.configmap.annotation.apply';
export const TERRAFORM_PROFILE = 'KF-TERRAFORM-GATEWAY-0.1-draft';
export const TERRAFORM_RUNNER = 'KF-TERRAFORM-APPLY-0.1-draft';
export const TERRAFORM_EXTENSION = 'io.kedgeflow/terraform-apply';
export const TERRAFORM_CAPABILITIES = { profile: TERRAFORM_PROFILE, runner_profile: TERRAFORM_RUNNER, guard_level: 'Level_C', target_atomic: false };
export const TERRAFORM_ADAPTER = { level: 'Level_C', guard_primitive: 'None', fence_parameter: null, guard_scope: [], completion_mode: 'dispatch_bound', commit_point: `${TERRAFORM_RUNNER}:original-native-intent-before-apply`, idempotency: { mode: 'resource_key', parameter: 'attempt_id', retention_ms: 86400000 } };
const reference = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
export function terraformSchema(r) {
  exact(r, ['profile', 'manifestDigest', 'effectDigest', 'inspectionSha256', 'resource']);
  exact(r.resource, ['id', 'incarnation']);
  if (r.profile !== TERRAFORM_PROFILE || ![r.manifestDigest, r.effectDigest, r.inspectionSha256].every(reference) || typeof r.resource.id !== 'string' || !r.resource.id || typeof r.resource.incarnation !== 'string' || !r.resource.incarnation) throw new Error('Terraform protected registration binding mismatch');
  return { type: 'object', additionalProperties: false, required: ['node', 'expected_version', 'manifest_digest', 'effect_digest'], properties: { node: { type: 'string', const: r.resource.id }, expected_version: { type: 'integer', const: 1 }, manifest_digest: { type: 'string', const: r.manifestDigest }, effect_digest: { type: 'string', const: r.effectDigest } } };
}
export function terraformMetadata(r) {
  terraformSchema(r);
  return { ...TERRAFORM_CAPABILITIES, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest, inspection_sha256: r.inspectionSha256 };
}
export function validateTerraformDescriptor(d, r) {
  if (d.action !== TERRAFORM_ACTION) {
    if (r !== undefined) throw new Error('Terraform registration requires named Terraform action');
    return;
  }
  const schema = terraformSchema(r);
  const coverage = { coordinated_writers: ['protected-terraform-runner'], uncoordinated_writers: ['privileged-administrators', 'kubernetes-control-plane'] };
  coverage.inventory_digest = digest('coverage-inventory', coverage);
  const p = d.concurrency?.predicate_descriptor;
  if (d.version !== '1.0' || !same(d.parameter_schema, schema) || d.parameter_schema_digest !== digest('parameter-schema', schema) || d.rendering?.parameter_schema_digest !== d.parameter_schema_digest || !same(d.adapter_contract, TERRAFORM_ADAPTER) || !same(d.concurrency?.coverage, coverage) || !Array.isArray(p?.clauses) || p.clauses.length !== 1 || !same(p.clauses[0], { kind: 'version_eq', resource: r.resource, expected_version: '1' })) throw new Error('Terraform descriptor/plan binding mismatch');
}
export function validateTerraformArguments(d, args, r) {
  if (d.action !== TERRAFORM_ACTION) return;
  validateTerraformDescriptor(d, r);
  if (!same(args, { node: r.resource.id, expected_version: 1, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest })) throw new Error('Terraform original plan binding conflict');
}
export function validateTerraformGrant(d, g, args, r) {
  if (d.action !== TERRAFORM_ACTION) return;
  validateTerraformArguments(d, args, r);
  if (g.action.id !== TERRAFORM_ACTION || g.action.version !== '1.0' || g.parameters_digest !== digest('parameters', args) || !same(g.resources, [r.resource]) || !same(g.adapter_contract, TERRAFORM_ADAPTER) || g.completion_mode !== 'dispatch_bound' || g.parent_grant_digest !== null || g.saga_budget !== null) throw new Error('Terraform grant/plan binding mismatch');
}
export function validateTerraformResult(d, result, envelope, receipt, r) {
  if (d.action !== TERRAFORM_ACTION) return;
  const c = result.structuredContent, report = c?.kedgeflow_terraform_report, i = report?.intent, g = envelope.payload;
  exact(receipt, ['attempt_id', 'grant_digest', 'resource', 'fence', 'status']);
  exact(report, ['profile', 'status', 'intent', 'replayed', 'observed_postcondition']);
  exact(i, ['profile', 'manifest_digest', 'effect_digest', 'grant_digest', 'root_id', 'attempt_id', 'state', 'initiated_at', 'backend_before_sha256', 'backend_after_sha256', 'observed_after_digest', 'last_error']);
  if (!same(c.kedgeflow_terraform_binding, terraformMetadata(r)) || report.profile !== TERRAFORM_RUNNER || report.status !== 'committed' || report.replayed !== false || report.observed_postcondition !== true || i.profile !== TERRAFORM_RUNNER || i.state !== 'applied' || i.last_error !== null || receipt.status !== 'committed' || i.grant_digest !== receipt.grant_digest || i.attempt_id !== receipt.attempt_id || i.root_id !== g.root_id || i.manifest_digest !== r.manifestDigest || i.effect_digest !== r.effectDigest || !Number.isSafeInteger(i.initiated_at) || i.initiated_at < g.valid_from || i.initiated_at >= g.expires_at || ![i.backend_before_sha256, i.backend_after_sha256, i.observed_after_digest].every(reference) || i.backend_before_sha256 === i.backend_after_sha256) throw new Error('Terraform original outcome correlation mismatch');
}
export function terraformNativeStatus(d, native) {
  return d.action === TERRAFORM_ACTION ? { ...native, guard_level: 'Level_C', target_atomic: false } : native;
}
