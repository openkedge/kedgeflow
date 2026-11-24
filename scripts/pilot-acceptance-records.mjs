// Closed SQL pilot contract. Administrative acceptance never grants runtime authority.
import { join } from 'node:path';
import { canonical, exact, strictJson } from '../sdk/node/records.mjs';
import { acceptanceProfile, sha256 } from './acceptance-records.mjs';
import { GATES as terraformGates } from './terraform-acceptance-records.mjs';
import { verifyCI } from './release-ci.mjs';
export {sha256} from './acceptance-records.mjs';

export const PROFILE = 'KF-SQL-PILOT-ACCEPTANCE-0.1-draft';
export const GATES = Object.freeze({
  ...terraformGates,
  writer_coverage: {role:'resource', checks:[
    'complete_writer_break_glass_inventory', 'agent_descendant_bypass_refusal',
    'exact_sql_transaction_guard_query_contract', 'lost_commit_reply_no_duplicate_effect',
  ]},
  storage_restore: {role:'storage', checks:[
    ...terraformGates.storage_restore.checks, 'ledger_and_target_cold_restore',
    'upgrade_rollback_fences_nonces_attempts_outbox',
  ]},
  release_reproduction: {role:'independent_reproducer', checks:[
    ...terraformGates.release_reproduction.checks, 'required_ci_same_source_no_skips',
    'signed_bundle_sbom_vulnerability_license_triage',
  ]},
});
const need = (ok, reason) => {if (!ok) throw new Error(reason);};
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const label = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,191}$/.test(value);
const integer = n => Number.isSafeInteger(n) && n >= 0;

export function validateDeployment(d) {
  exact(d,['profile','deployment_id','source_commit','bundle_sha256','configuration_sha256',
    'writer_inventory_sha256','capabilities_sha256','scope','not_before','expires_at']);
  need(d.profile === PROFILE && label(d.deployment_id), 'deployment_profile_or_identity');
  need(typeof d.source_commit === 'string' && /^[a-f0-9]{40}$/.test(d.source_commit), 'source_pin');
  for (const key of ['bundle_sha256','configuration_sha256','writer_inventory_sha256','capabilities_sha256']) {
    need(hex(d[key]), 'deployment_pin');
  }
  exact(d.scope,['profile','action','action_version','resource','ctd_sha256','parameter_schema_sha256',
    'guard_level','target_atomic','guard','guard_primitive','completion_mode','review','delegation','tenancy','platform']);
  const s = d.scope;
  need(s.profile === 'KF-POSTGRES-LEAF-0.1-draft' && s.action === 'postgres.reservation.set.v1'
    && s.action_version === '1.0', 'unsupported_action_profile');
  exact(s.resource,['id','incarnation']);
  need(label(s.resource.id) && label(s.resource.incarnation), 'resource_binding');
  need(hex(s.ctd_sha256) && hex(s.parameter_schema_sha256), 'action_schema_binding');
  need(s.guard_level === 'Level_A' && s.target_atomic === true && s.guard === 'version_eq'
    && s.guard_primitive === 'FencingToken' && s.completion_mode === 'dispatch_bound',
    'unsupported_enforcement_claim');
  need(s.review === 'none' && s.delegation === false && s.tenancy === 'single_organization_isolated'
    && s.platform === 'linux_systemd', 'unsupported_pilot_scope');
  need(integer(d.not_before) && integer(d.expires_at) && d.not_before < d.expires_at,
    'deployment_lifetime');
  return d;
}

const profile = acceptanceProfile({profile:PROFILE,gates:GATES,validateDeployment,
  deploymentArtifacts:['writer_inventory_sha256','capabilities_sha256']});
export const {deploymentDigest, signatureInput, readRegular, prepareRequest} = profile;
export async function evaluate(directory, options) {
  const report = await profile.evaluate(directory, options);
  if (report.state !== 'owner_records_verified') return report;
  try {
    const deployment = validateDeployment(strictJson((await readRegular(join(directory,'deployment.json'))).toString('utf8')));
    need(deploymentDigest(deployment) === report.deployment_digest, 'deployment_digest_mismatch');
    const evidence = strictJson((await readRegular(join(directory,'evidence.json'))).toString('utf8'));
    const observation = evidence.gates.find(g=>g.id === 'release_reproduction');
    const approved = report.gates.find(g=>g.gate === 'release_reproduction');
    need(sha256(canonical(observation)) === approved.observation_sha256, 'approval_evidence_binding');
    const check = observation.checks.find(c=>c.id === 'required_ci_same_source_no_skips');
    const bytes = await readRegular(join(directory,'artifacts',check.artifact_sha256),4<<20);
    need(sha256(bytes) === check.artifact_sha256, 'artifact_digest_mismatch');
    for (const reason of verifyCI(strictJson(bytes.toString('utf8')),deployment.source_commit)) {
      report.gaps.push({gate:'release_reproduction',reason});
    }
  } catch {
    report.gaps.push({gate:'release_reproduction',reason:'invalid_ci_evidence'});
  }
  if (report.gaps.length) {report.state='blocked'; delete report.valid_until;}
  return report;
}
