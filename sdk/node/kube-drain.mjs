// RFC 0055: explicit protected Level C selection, never inherited SQL fencing.
// These client bindings do not verify physical completion or grant authority.
import { digest, exact, same, strictJson } from './records.mjs';
export const DRAIN_ACTION = 'kubernetes.node.drain';
export const DRAIN_PROFILE = 'KF-KUBE-DRAIN-0.1-draft';
export const DRAIN_EXTENSION = 'io.kedgeflow/kubernetes-drain';
export const DRAIN_ADAPTER = {
  level: 'Level_C', guard_primitive: 'None', fence_parameter: null, guard_scope: [],
  completion_mode: 'dispatch_bound', commit_point: `${DRAIN_PROFILE}:durable-controller-acceptance`,
  idempotency: { mode: 'resource_key', parameter: 'attempt_id', retention_ms: 86400000 },
};
const reference = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const name = x => typeof x === 'string' && x.length <= 253 && x.split('.').every(s => /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/.test(s));
export function drainRegistration(contract) {
  if (contract.profile !== DRAIN_PROFILE) throw new Error('protected physical catalog profile mismatch');
  return { profile: DRAIN_PROFILE, contractDigest: digest('kube-drain-contract', contract),
    node: contract.node.name, generation: contract.generation,
    resource: { id: contract.node.name, incarnation: digest('kube-drain-incarnation', { cluster_uid: contract.cluster_uid, node_uid: contract.node.uid }) } };
}
export function drainSchema(r) {
  exact(r, ['profile', 'contractDigest', 'node', 'generation', 'resource']);
  exact(r.resource, ['id', 'incarnation']);
  if (r.profile !== DRAIN_PROFILE || !reference(r.contractDigest) || !name(r.node) ||
      !Number.isSafeInteger(r.generation) || r.generation < 1 || r.resource.id !== r.node || !reference(r.resource.incarnation)) throw new Error('protected drain registration mismatch');
  return { $comment: `${DRAIN_PROFILE} contract=${r.contractDigest}`, type: 'object',
    properties: { node: { type: 'string', const: r.node }, expected_version: { type: 'integer', const: r.generation } },
    required: ['node', 'expected_version'], additionalProperties: false };
}
export function validateDrainDescriptor(d, r) {
  if (d.action !== DRAIN_ACTION) {
    if (r !== undefined || d.adapter_contract?.level === 'Level_C') throw new Error('drain registration requires named physical action');
    return;
  }
  const schema = drainSchema(r);
  const coverage = { coordinated_writers: ['kedgeflow-drain-controller'], uncoordinated_writers: ['kubernetes-control-plane', 'node-runtime', 'privileged-administrators'] };
  coverage.inventory_digest = digest('coverage-inventory', coverage);
  const clauses = d.concurrency?.predicate_descriptor?.clauses;
  if (d.version !== '1.0' || !same(d.parameter_schema, schema) ||
      d.parameter_schema_digest !== digest('parameter-schema', schema) || d.rendering?.parameter_schema_digest !== d.parameter_schema_digest ||
      !same(d.adapter_contract, DRAIN_ADAPTER) || !same(d.concurrency?.coverage, coverage) ||
      !Array.isArray(clauses) || clauses.length !== 1 || clauses[0].kind !== 'version_eq' ||
      !same(clauses[0].resource, r.resource) || clauses[0].expected_version !== String(r.generation)) throw new Error('drain descriptor/contract binding mismatch');
}
export function validateDrainArguments(d, args, r) {
  if (d.action !== DRAIN_ACTION) return;
  validateDrainDescriptor(d, r);
  exact(args, ['node', 'expected_version']);
  if (args.node !== r.node || args.expected_version !== r.generation) throw new Error('drain arguments differ from protected contract');
}
export function validateDrainGrant(d, g, args, r) {
  if (d.action !== DRAIN_ACTION) return;
  validateDrainArguments(d, args, r);
  if (g.action.id !== DRAIN_ACTION || g.action.version !== '1.0' ||
      g.parameters_digest !== digest('parameters', args) || !same(g.resources, [r.resource]) ||
      !same(g.adapter_contract, DRAIN_ADAPTER) || g.completion_mode !== 'dispatch_bound') throw new Error('drain grant contract mismatch');
}
export function validateDrainResult(d, result, grant, receipt, r) {
  if (d.action !== DRAIN_ACTION) return;
  const content = result.structuredContent;
  const acceptance = content?.kedgeflow_drain_acceptance;
  // The pinned native gateway verifies the controller signature. The SDK only
  // correlates its accepted result; it never treats this as physical evidence.
  if (receipt.status !== 'committed' || content.commit_point !== 'controller_acceptance' || content.physical_status !== 'unresolved' ||
      acceptance?.profile !== DRAIN_PROFILE || acceptance.kind !== 'controller_state' ||
      acceptance.body?.accepted?.contract_digest !== r.contractDigest ||
      acceptance.body.accepted.grant_digest !== receipt.grant_digest || acceptance.body.accepted.attempt_id !== receipt.attempt_id ||
      !same(strictJson(acceptance.body.accepted.signed_grant), grant)) throw new Error('drain acceptance correlation mismatch');
}
export function drainNativeStatus(d, native) {
  if (d.action !== DRAIN_ACTION) return native;
  return { ...native, native_state: native.state, state: native.state === 'committed' ? 'accepted' : native.state,
    commit_point: 'controller_acceptance', physical_status: 'unresolved' };
}
