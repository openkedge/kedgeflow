// Exact protected saved-plan selection. Level C; local observed effect only.
import { digest, exact, same } from './records.mjs';
export const TERRAFORM_PAIR_ACTION = 'terraform.configmap.annotation.pair.apply';
export const TERRAFORM_PAIR_PROFILE = 'KF-TERRAFORM-PAIR-GATEWAY-0.1-draft';
export const TERRAFORM_PAIR_RUNNER = 'KF-TERRAFORM-PAIR-APPLY-0.1-draft';
export const TERRAFORM_PAIR_EXTENSION = 'io.kedgeflow/terraform-pair-apply';
export const TERRAFORM_PAIR_CAPABILITIES = { profile: TERRAFORM_PAIR_PROFILE, runner_profile: TERRAFORM_PAIR_RUNNER, guard_level: 'Level_C', target_atomic: false };
export const TERRAFORM_PAIR_ADAPTER = { level: 'Level_C', guard_primitive: 'None', fence_parameter: null, guard_scope: [], completion_mode: 'dispatch_bound', commit_point: `${TERRAFORM_PAIR_RUNNER}:original-native-intent-before-apply`, idempotency: { mode: 'resource_key', parameter: 'attempt_id', retention_ms: 86400000 } };
const reference = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
export function terraformPairSchema(r) {
  exact(r, ['profile', 'manifestDigest', 'effectDigest', 'inspectionSha256', 'resource', 'members']);
  exact(r.resource, ['id', 'incarnation']);
  if (r.profile !== TERRAFORM_PAIR_PROFILE || ![r.manifestDigest, r.effectDigest, r.inspectionSha256].every(reference) || typeof r.resource.id !== 'string' || !r.resource.id || typeof r.resource.incarnation !== 'string' || !r.resource.incarnation) throw new Error('Terraform pair protected registration binding mismatch');
  if (r.resource.id !== `terraform-pair:${r.manifestDigest}` || !reference(r.resource.incarnation) || !Array.isArray(r.members) || r.members.length !== 2) throw new Error('Terraform pair member registration mismatch');
  for (const [index, member] of r.members.entries()) {
    exact(member, ['id', 'target_uid']);
    if (member.id !== ['first', 'second'][index] || typeof member.target_uid !== 'string' || !member.target_uid || member.target_uid.length > 1024) throw new Error('Terraform pair member identity mismatch');
  }
  if (r.members[0].target_uid === r.members[1].target_uid) throw new Error('Terraform pair duplicate target identity');
  return { type: 'object', additionalProperties: false, required: ['node', 'expected_version', 'manifest_digest', 'effect_digest'], properties: { node: { type: 'string', const: r.resource.id }, expected_version: { type: 'integer', const: 1 }, manifest_digest: { type: 'string', const: r.manifestDigest }, effect_digest: { type: 'string', const: r.effectDigest } } };
}
export function terraformPairMetadata(r) {
  terraformPairSchema(r);
  return { ...TERRAFORM_PAIR_CAPABILITIES, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest, inspection_sha256: r.inspectionSha256 };
}
export function validateTerraformPairDescriptor(d, r) {
  if (d.action !== TERRAFORM_PAIR_ACTION) {
    if (r !== undefined) throw new Error('Terraform pair registration requires named Terraform pair action');
    return;
  }
  const schema = terraformPairSchema(r);
  const coverage = { coordinated_writers: ['protected-terraform-runner'], uncoordinated_writers: ['privileged-administrators', 'kubernetes-control-plane'] };
  coverage.inventory_digest = digest('coverage-inventory', coverage);
  const p = d.concurrency?.predicate_descriptor;
  if (d.version !== '1.0' || !same(d.parameter_schema, schema) || d.parameter_schema_digest !== digest('parameter-schema', schema) || d.rendering?.parameter_schema_digest !== d.parameter_schema_digest || !same(d.adapter_contract, TERRAFORM_PAIR_ADAPTER) || !same(d.concurrency?.coverage, coverage) || !Array.isArray(p?.clauses) || p.clauses.length !== 1 || !same(p.clauses[0], { kind: 'version_eq', resource: r.resource, expected_version: '1' })) throw new Error('Terraform pair descriptor/plan binding mismatch');
}
export function validateTerraformPairArguments(d, args, r) {
  if (d.action !== TERRAFORM_PAIR_ACTION) return;
  validateTerraformPairDescriptor(d, r);
  if (!same(args, { node: r.resource.id, expected_version: 1, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest })) throw new Error('Terraform pair original plan binding conflict');
}
export function validateTerraformPairGrant(d, g, args, r) {
  if (d.action !== TERRAFORM_PAIR_ACTION) return;
  validateTerraformPairArguments(d, args, r);
  if (g.action.id !== TERRAFORM_PAIR_ACTION || g.action.version !== '1.0' || g.parameters_digest !== digest('parameters', args) || !same(g.resources, [r.resource]) || !same(g.adapter_contract, TERRAFORM_PAIR_ADAPTER) || g.completion_mode !== 'dispatch_bound' || g.parent_grant_digest !== null || g.saga_budget !== null) throw new Error('Terraform pair grant/plan binding mismatch');
}
export function validateTerraformPairResult(d, result, envelope, receipt, r) {
  if (d.action !== TERRAFORM_PAIR_ACTION) return;
  const c = result.structuredContent, report = c?.kedgeflow_terraform_report, i = report?.intent, g = envelope.payload;
  exact(receipt, ['attempt_id', 'grant_digest', 'resource', 'fence', 'status']);
  exact(report, ['profile', 'status', 'intent', 'replayed', 'observed_postcondition']);
  exact(i, ['profile', 'manifest_digest', 'effect_digest', 'grant_digest', 'root_id', 'attempt_id', 'state', 'initiated_at', 'backend_before_sha256', 'backend_after_sha256', 'observed_after_digest', 'last_error', 'pair']);
  validateTerraformPairDescriptor(d, r);
  exact(i.pair, ['tool_succeeded', 'backend_progress', 'members']);
  if (i.pair.tool_succeeded !== true || i.pair.backend_progress !== true || !Array.isArray(i.pair.members) || i.pair.members.length !== 2) throw new Error('Terraform pair incomplete physical outcome');
  for (const [index, member] of i.pair.members.entries()) {
    exact(member, ['id', 'target_uid', 'state', 'observation_digest', 'observed_at']);
    if (member.id !== r.members[index].id || member.target_uid !== r.members[index].target_uid || member.state !== 'desired' || !reference(member.observation_digest) || !Number.isSafeInteger(member.observed_at) || member.observed_at < i.initiated_at) throw new Error('Terraform pair member outcome mismatch');
  }
  if (i.observed_after_digest !== digest('terraform-pair-observation', i.pair) || !same(receipt.resource, r.resource) || receipt.fence !== g.fence) throw new Error('Terraform pair observation correlation mismatch');
  if (!same(c.kedgeflow_terraform_binding, terraformPairMetadata(r)) || report.profile !== TERRAFORM_PAIR_RUNNER || report.status !== 'committed' || report.replayed !== false || report.observed_postcondition !== true || i.profile !== TERRAFORM_PAIR_RUNNER || i.state !== 'applied' || i.last_error !== null || receipt.status !== 'committed' || i.grant_digest !== receipt.grant_digest || i.attempt_id !== receipt.attempt_id || i.root_id !== g.root_id || i.manifest_digest !== r.manifestDigest || i.effect_digest !== r.effectDigest || !Number.isSafeInteger(i.initiated_at) || i.initiated_at < g.valid_from || i.initiated_at >= g.expires_at || ![i.backend_before_sha256, i.backend_after_sha256, i.observed_after_digest].every(reference) || i.backend_before_sha256 === i.backend_after_sha256) throw new Error('Terraform pair original outcome correlation mismatch');
}
export function terraformPairNativeStatus(d, native) {
  return d.action === TERRAFORM_PAIR_ACTION ? { ...native, guard_level: 'Level_C', target_atomic: false } : native;
}
