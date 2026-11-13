// Offline administrative records only. This module never grants execution authority.
import { verify } from 'node:crypto';
import { constants } from 'node:fs';
import { open, lstat } from 'node:fs/promises';
import { resolve, join, parse } from 'node:path';
import { canonical, exact, hash, publicKey, strictJson } from '../sdk/node/records.mjs';

const HEX = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,191}$/;
const identifier = value => typeof value === 'string' && ID.test(value);
const fail = reason => { throw new Error(reason); };
const need = (condition, reason) => { if (!condition) fail(reason); };
const integer = n => Number.isSafeInteger(n) && n >= 0;

const sha256 = bytes => hash(bytes).toString('hex');

export function acceptanceProfile({profile: PROFILE, gates: GATES, validateDeployment,
  deploymentArtifacts = ['writer_inventory_sha256']}) {
const deploymentDigest = deployment => sha256(`KedgeFlow/${PROFILE}/deployment\0${canonical(deployment)}`);
const signatureInput = unsigned => Buffer.from(`KedgeFlow/${PROFILE}/owner\0${canonical(unsigned)}`);


function validateTrust(t, expected, now) {
  exact(t, ['profile','deployment_digest','not_before','expires_at','owners']);
  need(t.profile === PROFILE && t.deployment_digest === expected, 'trust_deployment_binding');
  need(integer(t.not_before) && integer(t.expires_at) && t.not_before <= now && now < t.expires_at, 'trust_lifetime');
  need(Array.isArray(t.owners) && t.owners.length === Object.keys(GATES).length, 'owner_inventory');
  const roles = Object.values(GATES).map(x => x.role);
  const owners = new Map();
  for (const o of t.owners) {
    exact(o, ['id','role','administration_domain','key_id','public_key','minimum_sequence','not_before','expires_at']);
    need(identifier(o.id) && identifier(o.key_id) && identifier(o.administration_domain) && roles.includes(o.role), 'owner_identity');
    need(!owners.has(o.role), 'duplicate_owner_role');
    need(integer(o.minimum_sequence) && integer(o.not_before) && integer(o.expires_at) && o.not_before >= t.not_before && o.expires_at <= t.expires_at && o.not_before <= now && now < o.expires_at, 'owner_lifetime_or_floor');
    publicKey(o.public_key);
    owners.set(o.role, o);
  }
  for (const key of ['id','key_id','public_key']) need(new Set(t.owners.map(o => o[key])).size === t.owners.length, 'owner_key_or_principal_reuse');
  const independent = ['deployment','storage','audit','independent_reproducer'].map(role => owners.get(role).administration_domain);
  need(new Set(independent).size === independent.length, 'independent_administration_required');
  return owners;
}

// Do not traverse a symlink, special file, or unbounded input. Hashes are checked
// on the same opened descriptor used for reading. Paths never come from records.
async function readRegular(path, bound = 1 << 20, budget = bound) {
  const absolute = resolve(path), root = parse(absolute).root;
  let parent = root;
  const parts = absolute.slice(root.length).split('/');
  for (const part of parts.slice(0,-1)) {
    parent = join(parent,part);
    const s = await lstat(parent);
    need(s.isDirectory() && !s.isSymbolicLink(), 'unsafe_input_parent');
  }
  const file = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    need(stat.isFile() && stat.nlink === 1, 'unsafe_input_file');
    need(stat.size <= bound, 'input_bound');
    need(stat.size <= budget, 'evidence_size_bound');
    const bytes = Buffer.alloc(Math.min(bound,budget) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const {bytesRead} = await file.read(bytes,offset,bytes.length-offset,null);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    need(offset <= bound, 'input_bound');
    need(offset <= budget, 'evidence_size_bound');
    return bytes.subarray(0,offset);
  } finally { await file.close(); }
}
const json = async path => strictJson((await readRegular(path)).toString('utf8'));

async function evaluate(directory, {trustFile, trustSha256, expectedDeployment, now = Date.now()} = {}) {
  const report = {profile:PROFILE,state:'blocked',deployment_digest:null,trust_sha256:null,checked_at:now,execution_authority:false,production_qualified:false,gates:[],gaps:[]};
  const gap = (gate,reason) => report.gaps.push({gate,reason});
  try {
    need(integer(now) && HEX.test(trustSha256) && HEX.test(expectedDeployment), 'externally_pinned_inputs_required');
    const trustBytes = await readRegular(trustFile);
    need(sha256(trustBytes) === trustSha256, 'trust_digest_mismatch');
    report.trust_sha256 = trustSha256;
    const d = validateDeployment(await json(join(directory,'deployment.json')));
    const dd = deploymentDigest(d);
    need(dd === expectedDeployment, 'deployment_digest_mismatch');
    report.deployment_digest = dd;
    need(d.not_before <= now && now < d.expires_at, 'deployment_expired_or_not_active');
    const owners = validateTrust(strictJson(trustBytes.toString('utf8')),dd,now);
    const e = await json(join(directory,'evidence.json'));
    exact(e, ['profile','deployment_digest','gates']);
    need(e.profile === PROFILE && e.deployment_digest === dd && Array.isArray(e.gates) && e.gates.length <= 7, 'evidence_inventory');
    const records = await json(join(directory,'approvals.json'));
    exact(records, ['profile','deployment_digest','approvals']);
    need(records.profile === PROFILE && records.deployment_digest === dd && Array.isArray(records.approvals) && records.approvals.length <= 7, 'approval_inventory');
    const knownGates = Object.keys(GATES);
    need(e.gates.every(g=>knownGates.includes(g.id)) && new Set(e.gates.map(g=>g.id)).size===e.gates.length, 'unknown_or_duplicate_evidence_gate');
    need(records.approvals.every(a=>knownGates.includes(a.payload?.gate)) && new Set(records.approvals.map(a=>a.payload.gate)).size===records.approvals.length, 'unknown_or_duplicate_approval_gate');
    const artifacts = new Map();
    let total = 0;
    const artifact = async digest => {
      need(typeof digest === 'string' && HEX.test(digest), 'artifact_digest_required');
      if (!artifacts.has(digest)) {
        need(artifacts.size < 64 && total < 64 << 20, 'evidence_size_bound');
        const bytes = await readRegular(join(directory,'artifacts',digest),4 << 20,(64 << 20)-total);
        total += bytes.length;
        need(total <= 64 << 20 && artifacts.size < 64, 'evidence_size_bound');
        need(sha256(bytes) === digest, 'artifact_digest_mismatch');
        artifacts.set(digest,true);
      }
    };
    for (const field of deploymentArtifacts) await artifact(d[field]);
    for (const [gate,definition] of Object.entries(GATES)) {
      try {
        const observation = e.gates.find(x=>x.id===gate);
        need(observation,'missing_deployed_observation');
        exact(observation,['id','deployment_digest','scope','observed_at','valid_until','checks']);
        need(observation.deployment_digest === dd && observation.scope === 'deployed', 'deployed_observation_required');
        need(integer(observation.observed_at) && integer(observation.valid_until) && d.not_before <= observation.observed_at && observation.observed_at <= now && now < observation.valid_until && observation.valid_until <= d.expires_at, 'observation_freshness');
        need(Array.isArray(observation.checks) && observation.checks.length===definition.checks.length, 'check_inventory');
        need(new Set(observation.checks.map(x=>x.id)).size===definition.checks.length, 'duplicate_check');
        for (const c of observation.checks) {
          exact(c,['id','result','artifact_sha256']);
          need(definition.checks.includes(c.id) && c.result === 'pass', 'required_check_not_passed');
          await artifact(c.artifact_sha256);
        }
        const a = records.approvals.find(a=>a.payload?.gate===gate);
        need(a,'missing_owner_approval');
        exact(a,['profile','owner_id','role','key_id','payload','signature']);
        const owner = owners.get(definition.role);
        need(a.profile === PROFILE && a.owner_id === owner.id && a.role === owner.role && a.key_id === owner.key_id, 'owner_role_binding');
        exact(a.payload,['deployment_digest','gate','observation_sha256','decision','issued_at','expires_at','sequence']);
        const p = a.payload;
        need(p.deployment_digest === dd && p.gate === gate && p.observation_sha256 === sha256(canonical(observation)), 'approval_evidence_binding');
        need(p.decision === 'accept', 'owner_did_not_accept');
        need(integer(p.sequence) && p.sequence >= owner.minimum_sequence, 'owner_sequence_floor');
        need(integer(p.issued_at) && integer(p.expires_at) && p.issued_at >= owner.not_before && p.issued_at >= observation.observed_at && p.issued_at <= now && now < p.expires_at && p.expires_at <= owner.expires_at && p.expires_at <= observation.valid_until, 'approval_freshness');
        need(typeof a.signature === 'string','signature_required');
        const sig = Buffer.from(a.signature,'base64url');
        const {signature,...unsigned} = a;
        need(sig.length === 64 && sig.toString('base64url') === signature && verify(null,signatureInput(unsigned),publicKey(owner.public_key),sig), 'owner_signature_invalid');
        report.gates.push({gate,role:owner.role,owner_id:owner.id,key_id:owner.key_id,observation_sha256:p.observation_sha256,sequence:p.sequence,valid_until:p.expires_at});
      } catch(error) { gap(gate, error.code === 'ENOENT' ? 'missing_evidence_file' : safeReason(error)); }
    }
    report.artifacts_verified = artifacts.size;
    if (report.gaps.length === 0) {
      report.state = 'owner_records_verified';
      report.valid_until = Math.min(d.expires_at,...report.gates.map(g=>g.valid_until));
    }
  } catch(error) { gap('deployment', error.code === 'ENOENT' ? 'missing_required_file' : safeReason(error)); }
  return report;
}
function safeReason(error) {
  // Runtime errors can contain local paths. Do not echo their message or content.
  return /^[a-z][a-z0-9_]{1,80}$/.test(error.message) ? error.message : 'invalid_or_unsafe_record';
}

function prepareRequest(deployment) {
  const d = validateDeployment(deployment), dd = deploymentDigest(d);
  return {profile:PROFILE,state:'awaiting_deployed_evidence_and_owners',deployment_digest:dd,
    evidence:{profile:PROFILE,deployment_digest:dd,gates:Object.entries(GATES).map(([id,g])=>({id,deployment_digest:dd,scope:'unqualified',observed_at:null,valid_until:null,checks:g.checks.map(id=>({id,result:'unknown',artifact_sha256:null}))}))},
    approvals:{profile:PROFILE,deployment_digest:dd,approvals:[]},
    required_owner_roles:Object.values(GATES).map(g=>g.role),execution_authority:false,production_qualified:false};
}

return {deploymentDigest, signatureInput, readRegular, evaluate, prepareRequest};
}

export {sha256};
