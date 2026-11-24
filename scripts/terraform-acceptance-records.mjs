// Offline administrative records only; existing Terraform wire semantics are unchanged.
import { exact } from '../sdk/node/records.mjs';
import { acceptanceProfile } from './acceptance-records.mjs';
export {sha256} from './acceptance-records.mjs';

export const PROFILE = 'KF-TERRAFORM-DEPLOYMENT-ACCEPTANCE-0.1-draft';
export const GATES = Object.freeze({
  identity_credentials: { role: 'identity_security', checks: ['subject_workload_binding', 'credential_rotation_withdrawal', 'original_claim_bound_broker'] },
  service_custody: { role: 'deployment', checks: ['installed_source_bundle_configuration', 'separate_agent_service_uids', 'protected_files_sockets_egress', 'upgrade_preserves_consumed_history'] },
  writer_coverage: { role: 'resource', checks: ['complete_writer_break_glass_inventory', 'agent_descendant_bypass_refusal', 'exact_runner_provider_boundary'] },
  storage_restore: { role: 'storage', checks: ['least_privilege_native_roles', 'independent_witness_head_floor', 'physical_stale_restore_refusal', 'original_consumed_attempt_preserved'] },
  audit_retention: { role: 'audit', checks: ['independent_collector_custody', 'target_effect_correlation', 'retained_trace_reconstruction'] },
  operations_recovery: { role: 'sre', checks: ['workload_capacity_latency_budgets', 'refusal_unresolved_age_alerts', 'query_only_recovery', 'incident_abort_on_call_rehearsal'] },
  release_reproduction: { role: 'independent_reproducer', checks: ['pinned_source_release', 'dependency_security_license_review', 'supported_platform_upgrade_policy', 'independent_reproduction'] },
});
const HEX = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,191}$/;
const identifier = value => typeof value === 'string' && ID.test(value);
const fail = reason => { throw new Error(reason); };
const need = (condition, reason) => { if (!condition) fail(reason); };
const integer = n => Number.isSafeInteger(n) && n >= 0;
export function validateDeployment(d) {
  exact(d, ['profile','deployment_id','source_commit','bundle_sha256','configuration_sha256','writer_inventory_sha256','scope','not_before','expires_at']);
  need(d.profile === PROFILE && identifier(d.deployment_id), 'deployment_profile_or_identity');
  need(typeof d.source_commit === 'string' && /^[a-f0-9]{40}$/.test(d.source_commit), 'source_pin');
  for (const key of ['bundle_sha256','configuration_sha256','writer_inventory_sha256']) need(typeof d[key] === 'string' && HEX.test(d[key]), 'deployment_pin');
  exact(d.scope, ['profile','resource','manifest_digest','effect_digest','guard_level','target_atomic']);
  need(['KF-TERRAFORM-GATEWAY-0.1-draft','KF-TERRAFORM-PAIR-GATEWAY-0.1-draft'].includes(d.scope.profile), 'unsupported_action_profile');
  exact(d.scope.resource, ['id','incarnation']);
  need(identifier(d.scope.resource.id) && identifier(d.scope.resource.incarnation), 'resource_binding');
  const pair = d.scope.profile === 'KF-TERRAFORM-PAIR-GATEWAY-0.1-draft';
  need(d.scope.resource.id === `${pair ? 'terraform-pair' : 'terraform'}:${d.scope.manifest_digest}`, 'registered_resource_binding');
  if (pair) need(HEX.test(d.scope.resource.incarnation), 'pair_incarnation_binding');
  need(HEX.test(d.scope.manifest_digest) && HEX.test(d.scope.effect_digest), 'plan_effect_binding');
  need(d.scope.guard_level === 'Level_C' && d.scope.target_atomic === false, 'unsupported_enforcement_claim');
  need(integer(d.not_before) && integer(d.expires_at) && d.not_before < d.expires_at, 'deployment_lifetime');
  return d;
}

export const {deploymentDigest, signatureInput, readRegular, evaluate, prepareRequest} = acceptanceProfile({profile:PROFILE,gates:GATES,validateDeployment});
