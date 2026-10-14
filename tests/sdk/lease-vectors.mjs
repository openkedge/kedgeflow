import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { canonical, digest, privateSeed, publicBytes, recordDigest, signedRecord, strictJson, verifyRecord } from '../../sdk/node/records.mjs';
import { AgentAdapter } from '../../sdk/node/agent-adapter.mjs';
import { LEASE_STATE_PROFILE, leaseRegistration, leaseConfigDigest, verifyLeaseEvidence, verifyLease, verifyJit, verifyLeaseCertificate } from '../../sdk/node/leases.mjs';
const t = 1_800_000_000_000;
const copy = v => strictJson(canonical(v));
const role = n => ({ [`key-${n}`]: publicBytes(privateSeed(Buffer.alloc(32, n))).toString('base64url') });
const sign = (kind, p, n) => signedRecord(kind, p, `key-${n}`, privateSeed(Buffer.alloc(32, n)));
const p = (strictJson(await readFile(new URL('../../fixtures/proposal.json', import.meta.url), 'utf8'))).payload;
p.workflow = null; p.requested_completion = 'dispatch_bound';
p.created_at = t - 10; p.delegation.expires_at = t + 10000; p.baseline_state[0].observed_at = t - 12; p.baseline_state[0].expires_at = t + 10000;
const proposal = verifyRecord(sign('proposal', p, 1), 'proposal', role(1));
const policy = { id: 'policy', epoch: 7, digest: 'a'.repeat(64) };
const config = { tenant: p.tenant, subject: p.subject, workloadId: p.workload_id, descriptorDigest: p.action.digest, action: p.action, gatewayUrl: 'https://gateway.test/mcp', admissionUrl: 'https://control.test/admit', issuanceUrl: 'https://control.test/issue', statusUrl: 'https://control.test/status', delegationAudience: p.delegation.token_audience, proposalKeys: role(1), registryKeys: role(2), manifestKeys: role(3), admissionKeys: role(6), issuerKeys: role(5), leases: {
  url: 'https://control.test/leases', scope: 'kf.lease', policy, ownershipEpoch: 5, maxLifetimeMs: 4000, jitMaxAgeMs: 2000, maxProposalAgeMs: 60000,
  obligations: { eligibility: { stage: 'static', predicate_digest: 'c'.repeat(64), execution_relevant: true, provider_id: 'provider:eligibility', provider_version: '1.0', keys: role(30), max_age_ms: 8000 }, capacity: { stage: 'jit', predicate_digest: 'd'.repeat(64), execution_relevant: true, provider_id: 'provider:capacity', provider_version: '1.0', keys: role(4), max_age_ms: 4000 } }
} };
const example = strictJson(await readFile(new URL('../../config/agent-leases.example.json', import.meta.url), 'utf8'));
const exampleConfig = { ...config, admissionUrl: 'https://control.example.org/admit', issuanceUrl: 'https://control.example.org/issue', statusUrl: 'https://control.example.org/status', leases: example };
const source = { collectStatic() {}, collectJit() {} };
const r = leaseRegistration(config, source);
assert.equal(leaseRegistration(exampleConfig, source).obligations.eligibility.stage, 'static');
assert.equal(leaseRegistration({ ...config, leases: undefined }, {}), null);
for (const field of ['url', 'scope', 'policy', 'ownershipEpoch', 'maxLifetimeMs', 'jitMaxAgeMs', 'maxProposalAgeMs', 'obligations', 'extra', 'overlap', 'stage', 'provider', 'keys']) {
  const c = copy(config);
  if (field === 'extra') c.leases.extra = true;
  else if (field === 'overlap') c.leases.obligations.eligibility.keys = role(6);
  else if (field === 'stage') c.leases.obligations.eligibility.stage = 'jit';
  else if (field === 'provider') c.leases.obligations.capacity.provider_id = '';
  else if (field === 'keys') c.leases.obligations.capacity.keys = {};
  else delete c.leases[field];
  assert.throws(() => leaseRegistration(c, source), undefined, field);
}
for (const url of ['https://control.test/admit', 'https://other.test/leases', 'https://control.test/leases?alias=1', 'https://control.test/leases/']) assert.throws(() => leaseRegistration({ ...config, leases: { ...config.leases, url } }, source));
assert.throws(() => leaseRegistration(config, {}));
assert.notEqual(leaseConfigDigest(config, r), leaseConfigDigest({ ...config, manifestKeys: role(31) }, r));
const adapter = Object.create(AgentAdapter.prototype);
adapter.config = config; adapter.leases = r; adapter.leaseRegistrationDigest = leaseConfigDigest(config, r);
const prepared = { lease_preparation: { profile: LEASE_STATE_PROFILE, registration_digest: adapter.leaseRegistrationDigest, phase: 'ready' }, static_packet: {}, lease: 'retained' };
adapter.leasePreparation(prepared);
for (const marker of [{ profile: 'unknown' }, { phase: 'authority_started' }, { phase: 'unknown' }, { registration_digest: 'f'.repeat(64) }, { extra: true }]) assert.throws(() => adapter.leasePreparation({ ...prepared, lease_preparation: { ...prepared.lease_preparation, ...marker } }));
for (const change of [{ packet: {} }, { certificate: 'retained' }, { grant: 'retained' }, { static_packet: null }, { lease: null }]) assert.throws(() => adapter.leasePreparation({ ...prepared, ...change }));
adapter.config = { ...config, manifestKeys: role(31) };
assert.throws(() => adapter.leasePreparation(prepared));
adapter.config = config;
// Correlation and cache metadata apply to failures as well as signed successes.
adapter.headers = async () => new Headers();
let responseChange = {};
adapter.fetch = async (url, init) => ({ url, ok: true, headers: new Headers({ 'cache-control': 'no-store', 'content-type': 'application/json' }), text: async () => canonical({ profile: 'KF-STATIC-LEASE-HTTP-0.1-draft', operation: 'prevalidated', request_id: strictJson(init.body).request_id, lease: 'signed', ...responseChange }) });
await adapter.control(r.url, { request_id: 'id' }, 'prevalidated', 'KF-STATIC-LEASE-HTTP-0.1-draft');
for (responseChange of [{ request_id: 'different' }, { profile: 'KF-LEAF-CONTROL-0.1-draft' }, { operation: 'issued' }, { grant: 'extra' }]) await assert.rejects(adapter.control(r.url, { request_id: 'id' }, 'prevalidated', 'KF-STATIC-LEASE-HTTP-0.1-draft'));
const template = (strictJson(await readFile(new URL('../../fixtures/evidence.json', import.meta.url), 'utf8'))).payload;
function witness(oid, observed, extra = {}) {
  const o = r.obligations[oid];
  const e = { ...copy(template), wid: `w:${oid}`, proposal_digest: recordDigest(proposal), provider_id: o.provider_id, provider_version: o.provider_version, observed_at: observed, expires_at: t + (oid === 'eligibility' ? 8000 : 6000), ...extra };
  return sign('evidence', e, oid === 'eligibility' ? 30 : 4);
}
const originalStatic = witness('eligibility', t - 1);
const jit = witness('capacity', t + 100);
function packet(witnesses, ids, assembled = t + 100) {
  const entries = witnesses.map((raw, i) => { const e = strictJson(raw); return { witness: { id: e.payload.wid, schema: e.schema, digest: recordDigest(e) }, obligation_id: ids[i], execution_relevant: true, expires_at: e.payload.expires_at }; });
  return { manifest: sign('manifest', { mid: 'manifest', proposal_digest: recordDigest(proposal), policy, witnesses: entries, assembled_at: assembled }, 3), witnesses };
}
const staticPacket = packet([originalStatic], ['eligibility'], t);
const staticInputs = verifyLeaseEvidence(staticPacket, proposal, config, r, t, { staticOnly: true });
for (const change of [{ workflow: {} }, { requested_completion: 'commit_bound' }, { tenant: 'other' }, { workload_id: 'spiffe://other/agent' }]) {
  const bad = verifyRecord(sign('proposal', { ...p, ...change }, 1), 'proposal', role(1));
  assert.throws(() => verifyLeaseEvidence(staticPacket, bad, config, r, t, { staticOnly: true }), /context\/profile/);
}
const leasePayload = { lid: `kf-lease:${'e'.repeat(64)}`, proposal_digest: recordDigest(proposal), delegation_digest: digest('delegation', p.delegation), subject: p.subject, workload_id: p.workload_id, policy, descriptor_digest: config.descriptorDigest, ownership_epoch: 5, static_discharges: staticInputs.discharges, pending_jit_obligations: ['capacity'], issued_at: t, expires_at: t + 4000, execution_authority: false };
const rawLease = sign('lease', leasePayload, 6);
const lease = verifyLease(rawLease, proposal, staticPacket, config, r, t + 100);
for (const change of [{ extra: true }, { lid: 'lease:other' }, { proposal_digest: 'f'.repeat(64) }, { delegation_digest: 'f'.repeat(64) }, { subject: { ...p.subject, sub: 'other' } }, { workload_id: 'spiffe://other/workload' }, { policy: { ...policy, epoch: 8 } }, { descriptor_digest: 'f'.repeat(64) }, { ownership_epoch: 6 }, { static_discharges: [] }, { pending_jit_obligations: [] }, { pending_jit_obligations: ['capacity', 'capacity'] }, { execution_authority: true }, { issued_at: t + 101 }, { expires_at: t + 100 }, { expires_at: t + 4001 }]) assert.throws(() => verifyLease(sign('lease', { ...leasePayload, ...change }, 6), proposal, staticPacket, config, r, t + 100));
assert.throws(() => verifyLease(sign('lease', leasePayload, 5), proposal, staticPacket, config, r, t + 100));
assert.throws(() => verifyLease(rawLease, proposal, staticPacket, config, r, t + 4000));
const full = packet([originalStatic, jit], ['eligibility', 'capacity']);
const inputs = verifyJit(full, proposal, staticPacket, lease, config, r, t + 100);
assert.equal(inputs.validUntil, t + 2100);
for (const [w, ids] of [[[jit], ['capacity']], [[originalStatic, jit], ['eligibility', 'eligibility']], [[originalStatic, originalStatic], ['eligibility', 'capacity']], [[witness('eligibility', t - 1, { result: { substituted: true } }), jit], ['eligibility', 'capacity']], [[originalStatic, witness('capacity', t - 1)], ['eligibility', 'capacity']], [[originalStatic, witness('capacity', t + 101)], ['eligibility', 'capacity']], [[originalStatic, witness('capacity', t - 2000)], ['eligibility', 'capacity']], [[originalStatic, witness('capacity', t + 100, { provider_id: 'wrong' })], ['eligibility', 'capacity']]]) assert.throws(() => verifyJit(packet(w, ids), proposal, staticPacket, lease, config, r, t + 100));
const pretty = { manifest: JSON.stringify(strictJson(full.manifest), null, 2), witnesses: full.witnesses.map(raw => JSON.stringify(strictJson(raw), null, 2)) };
verifyJit(pretty, proposal, staticPacket, lease, config, r, t + 100);
const c = { lease_digest: recordDigest(lease), policy, ownership_epoch: 5, discharges: inputs.discharges, admitted_at: t + 100, expires_at: t + 2100 };
verifyLeaseCertificate(c, lease, inputs, r, t + 100);
for (const change of [{ lease_digest: null }, { lease_digest: 'f'.repeat(64) }, { policy: { ...policy, epoch: 8 } }, { ownership_epoch: 6 }, { discharges: [] }, { admitted_at: t - 1 }, { admitted_at: t + 101 }, { expires_at: t + 2101 }, { expires_at: t + 100 }]) assert.throws(() => verifyLeaseCertificate({ ...c, ...change }, lease, inputs, r, t + 100));
console.log(JSON.stringify({ status: 'PASS', vectors: ['closed pinned lease registration', 'role-bound signed lease and exact discharges/JIT IDs', 'full static/JIT manifest coverage and provider signatures', 'original canonical static evidence', 'proposal/delegation/static/JIT/lease freshness', 'certificate lease/policy/ownership/expiry links'] }));
