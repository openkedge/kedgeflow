// RFC 0057: explicit protected managed selection. Native verification owns the
// complete signature/source replay; SDK correlation never proves physical effect.
import { digest, exact, same, strictJson } from './records.mjs';
import { fixedHttps } from './transport.mjs';
import { DRAIN_ADAPTER, drainRegistration, drainSchema } from './kube-drain.mjs';
export const MANAGED_DRAIN_ACTION = 'kubernetes.node.drain.managed';
export const MANAGED_DRAIN_PROFILE = 'KF-MANAGED-KUBE-DRAIN-0.2-draft';
export const MANAGED_DRAIN_EXTENSION = 'io.kedgeflow/managed-kubernetes-drain';
export const ACCEPTANCE_PROFILE = 'KF-MANAGED-DRAIN-ACCEPTANCE-0.1-draft';
export const MANAGED_DRAIN_ADAPTER = { ...DRAIN_ADAPTER,
  commit_point: `${MANAGED_DRAIN_PROFILE}:durable-controller-acceptance` };
const reference = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function managedDrainRegistration(selection) {
  const registration = { profile: MANAGED_DRAIN_PROFILE, selection: structuredClone(selection) };
  managedDrainBindings(registration);
  return registration;
}
export function managedDrainBindings(r) {
  exact(r, ['profile', 'selection']); exact(r.selection, ['registration', 'child_id']);
  const family = r.selection.registration;
  if (r.profile !== MANAGED_DRAIN_PROFILE || family?.profile !== 'KF-FAMILY-SAGA-0.1-draft' ||
      family.composition?.profile !== 'KF-FAMILY-SAGA-0.1-draft' || !Array.isArray(family.composition?.nodes) || !Array.isArray(family.children)) throw new Error('protected managed family selection required');
  const nodes = family.composition.nodes.filter(n => n.child_id === r.selection.child_id);
  const children = family.children.filter(c => c.id === r.selection.child_id);
  if (nodes.length !== 1 || children.length !== 1) throw new Error('managed selected child is missing or ambiguous');
  const n = nodes[0], child = children[0], e = n.physical?.operating, c = n.physical?.contract;
  exact(e, ['profile', 'namespace', 'child_id', 'operation_key', 'mechanical_contract_digest',
    'target_audience', 'target_scope', 'controller_workload', 'supervisor_workload', 'evidence_workload',
    'operating_observer', 'policy', 'current_sql', 'clock_uncertainty_ms', 'maximum_authorization_to_send_ms']);
  const mechanical = drainRegistration(c);
  drainSchema(mechanical);
  if (e.profile !== MANAGED_DRAIN_PROFILE || e.namespace !== family.namespace || e.child_id !== r.selection.child_id ||
      e.operation_key !== n.operation_key || !reference(e.operation_key) || e.mechanical_contract_digest !== mechanical.contractDigest ||
      child.reservation?.scope?.action?.id !== MANAGED_DRAIN_ACTION || child.reservation.scope.action.version !== '1.1' ||
      !same(child.reservation.scope.resource, mechanical.resource) || !same(child.reservation.scope.adapter_contract, MANAGED_DRAIN_ADAPTER) ||
      !same(n.depends_on, [e.current_sql.forward_child_id]) || e.current_sql.profile !== 'KF-CURRENT-SQL-RESERVATION-0.2-draft' ||
      new Set([e.controller_workload,e.supervisor_workload,e.evidence_workload]).size !== 3 ||
      ![e.controller_workload,e.supervisor_workload,e.evidence_workload].every(v => typeof v === 'string' && v.startsWith('spiffe://')) ||
      !Number.isSafeInteger(e.clock_uncertainty_ms) || e.clock_uncertainty_ms < 0 || e.clock_uncertainty_ms > 1000 ||
      !Number.isSafeInteger(e.maximum_authorization_to_send_ms) || e.maximum_authorization_to_send_ms < 1 || e.maximum_authorization_to_send_ms > 1000) throw new Error('managed enrollment/contract/role binding mismatch');
  fixedHttps(e.target_audience); fixedHttps(e.current_sql.endpoint); fixedHttps(e.current_sql.evidence_endpoint);
  return { ...mechanical, profile: MANAGED_DRAIN_PROFILE, enrollmentDigest: digest('managed-kube-drain-enrollment', e),
    policyDigest: digest('physical-operating-policy', e.policy), familyRegistrationDigest: digest('family-registration', family),
    childId: e.child_id, operationKey: e.operation_key, targetAudience: e.target_audience, targetScope: e.target_scope,
    action: child.reservation.scope.action, conflictDomain: child.reservation.scope.conflict_domain, gatewayAudience: child.reservation.scope.audience, predicate: child.reservation.scope.predicate_descriptor };
}
export function managedDrainSchema(r) {
  const b = managedDrainBindings(r);
  return { $comment: `${MANAGED_DRAIN_PROFILE} enrollment=${b.enrollmentDigest} mechanical=${b.contractDigest}`,
    type: 'object', properties: { node: { type: 'string', const: b.node }, expected_version: { type: 'integer', const: b.generation } },
    required: ['node','expected_version'], additionalProperties: false };
}
export function managedDrainMetadata(r) {
  const b = managedDrainBindings(r);
  return { profile: MANAGED_DRAIN_PROFILE, acceptance_proof_profile: ACCEPTANCE_PROFILE,
    enrollment_digest: b.enrollmentDigest, policy_digest: b.policyDigest,
    family_registration_digest: b.familyRegistrationDigest, child_id: b.childId, operation_key: b.operationKey,
    contract_digest: b.contractDigest, commit_point: 'controller_acceptance', physical_completion: 'separate_observation' };
}
export function validateManagedDrainDescriptor(d, r) {
  if (d.action !== MANAGED_DRAIN_ACTION) {
    if (r !== undefined) throw new Error('managed registration requires named managed action');
    return;
  }
  const b = managedDrainBindings(r), schema = managedDrainSchema(r);
  const coverage = { coordinated_writers: ['kedgeflow-managed-drain-controller'], uncoordinated_writers: ['kubernetes-control-plane','node-runtime','privileged-administrators'] };
  coverage.inventory_digest = digest('coverage-inventory', coverage);
  const clauses = d.concurrency?.predicate_descriptor?.clauses;
  if (d.concurrency?.conflict_domain !== b.conflictDomain || d.gateway_audience !== b.gatewayAudience || !same(d.concurrency?.predicate_descriptor, b.predicate) || d.version !== '1.1' || !same(d.parameter_schema, schema) || d.parameter_schema_digest !== digest('parameter-schema', schema) ||
      d.rendering?.parameter_schema_digest !== d.parameter_schema_digest || !same(d.adapter_contract, MANAGED_DRAIN_ADAPTER) ||
      !same(d.concurrency?.coverage, coverage) || !Array.isArray(clauses) || clauses.length !== 1 ||
      clauses[0].kind !== 'version_eq' || !same(clauses[0].resource, b.resource) || clauses[0].expected_version !== String(b.generation)) throw new Error('managed descriptor/schema binding mismatch');
}
export function validateManagedDrainArguments(d, args, r) {
  if (d.action !== MANAGED_DRAIN_ACTION) return;
  validateManagedDrainDescriptor(d, r); exact(args, ['node','expected_version']);
  const b = managedDrainBindings(r);
  if (args.node !== b.node || args.expected_version !== b.generation) throw new Error('managed arguments differ from protected contract');
}
export function validateManagedDrainGrant(d, g, args, r) {
  if (d.action !== MANAGED_DRAIN_ACTION) return;
  validateManagedDrainArguments(d, args, r); const b = managedDrainBindings(r);
  if (!same(g.action, b.action) || g.audience !== b.gatewayAudience || g.conflict_domain !== b.conflictDomain || !same(g.predicate_descriptor, b.predicate) || g.parameters_digest !== digest('parameters', args) ||
      !same(g.resources, [b.resource]) || !same(g.adapter_contract, MANAGED_DRAIN_ADAPTER) || g.completion_mode !== 'dispatch_bound') throw new Error('managed grant contract mismatch');
}
export function validateManagedDrainResult(d, result, grant, receipt, r) {
  if (d.action !== MANAGED_DRAIN_ACTION) return;
  const b = managedDrainBindings(r), content = result.structuredContent, proof = content?.kedgeflow_managed_drain_acceptance;
  exact(proof, ['profile','enrollment_digest','authorization','acceptance','sources']);
  const a = proof.acceptance, mechanical = content.kedgeflow_drain_acceptance;
  // The protected native gateway verifies complete admission/source/controller
  // signatures and actual native reads. The client correlates its original result.
  if (receipt.status !== 'committed' || content.commit_point !== 'controller_acceptance' || content.physical_status !== 'unresolved' ||
      proof.profile !== ACCEPTANCE_PROFILE || proof.enrollment_digest !== b.enrollmentDigest ||
      a?.profile !== MANAGED_DRAIN_PROFILE || a.enrollment_digest !== b.enrollmentDigest ||
      !same(a.controller, mechanical) || mechanical?.kind !== 'controller_state' ||
      mechanical.body?.accepted?.contract_digest !== b.contractDigest ||
      mechanical.body.accepted.grant_digest !== receipt.grant_digest || mechanical.body.accepted.attempt_id !== receipt.attempt_id ||
      !same(strictJson(mechanical.body.accepted.signed_grant), grant) || !same(a.origin, proof.sources.origin) ||
      !same(a.events, proof.sources.events) || !same(strictJson(proof.authorization.issuance.signed_grant), grant) ||
      !Array.isArray(mechanical.body.steps) || mechanical.body.steps.length !== 0 || mechanical.body.closed !== null) throw new Error('managed acceptance/source correlation mismatch');
}
export function managedDrainNativeStatus(d, native) {
  if (d.action !== MANAGED_DRAIN_ACTION) return native;
  return { ...native, native_state: native.state, state: native.state === 'committed' ? 'accepted' : native.state,
    commit_point: 'controller_acceptance', physical_status: 'unresolved' };
}
