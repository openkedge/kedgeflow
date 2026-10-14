import { canonical, digest, exact, publicKey, recordDigest, same, strictJson, verifyRecord } from './records.mjs';
import { fixedHttps } from './transport.mjs';

export const LEASE_PROFILE = 'KF-STATIC-LEASE-HTTP-0.1-draft';
export const LEASE_STATE_PROFILE = 'KF-AGENT-LEASE-STATE-0.1-draft';
const pin = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const id = v => typeof v === 'string' && v.length > 0 && v.length <= 1024;
const time = v => Number.isSafeInteger(v) && v >= 0;
const lifetime = v => Number.isSafeInteger(v) && v >= 1 && v <= 300000;
const ordered = map => Object.keys(map).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
function keys(map) {
  if (!map || Array.isArray(map) || !Object.keys(map).length || Object.keys(map).length > 64) throw new Error('lease role keys required');
  for (const [keyId, raw] of Object.entries(map)) { if (!id(keyId)) throw new Error('lease key ID'); publicKey(raw); }
  return Object.values(map);
}
export function leaseRegistration(config, source) {
  if (config.leases === undefined) return null;
  const r = strictJson(canonical(config.leases));
  exact(r, ['url', 'scope', 'policy', 'ownershipEpoch', 'maxLifetimeMs', 'jitMaxAgeMs', 'maxProposalAgeMs', 'obligations']);
  fixedHttps(r.url);
  if (new URL(r.url).pathname !== '/leases' || !config.statusUrl || [config.gatewayUrl, config.admissionUrl, config.issuanceUrl, config.statusUrl].includes(r.url) || new URL(r.url).origin !== new URL(config.admissionUrl).origin || !id(r.scope) || /\s/.test(r.scope) || !lifetime(r.maxLifetimeMs) || !lifetime(r.jitMaxAgeMs) || !lifetime(r.maxProposalAgeMs) || !time(r.ownershipEpoch) || r.ownershipEpoch < 1 || typeof source?.collectStatic !== 'function' || typeof source?.collectJit !== 'function') throw new Error('incomplete or aliased lease registration');
  exact(r.policy, ['id', 'epoch', 'digest']);
  if (!id(r.policy.id) || !time(r.policy.epoch) || r.policy.epoch < 1 || !pin(r.policy.digest)) throw new Error('lease policy pin');
  if (!r.obligations || Array.isArray(r.obligations) || !Object.keys(r.obligations).length || Object.keys(r.obligations).length > 64) throw new Error('lease obligations required');
  const admission = keys(config.admissionKeys);
  const other = [config.proposalKeys, config.registryKeys, config.manifestKeys, config.issuerKeys].flatMap(keys);
  for (const [oid, o] of Object.entries(r.obligations)) {
    exact(o, ['stage', 'predicate_digest', 'execution_relevant', 'provider_id', 'provider_version', 'keys', 'max_age_ms']);
    if (!id(oid) || !['static', 'jit'].includes(o.stage) || !pin(o.predicate_digest) || typeof o.execution_relevant !== 'boolean' || !id(o.provider_id) || !id(o.provider_version) || !lifetime(o.max_age_ms)) throw new Error('invalid lease obligation');
    other.push(...keys(o.keys));
  }
  if (admission.some(key => other.includes(key)) || !Object.values(r.obligations).some(o => o.stage === 'static') || !Object.values(r.obligations).some(o => o.stage === 'jit')) throw new Error('lease signer overlap or missing stages');
  return r;
}
export function leaseConfigDigest(config, registration) {
  return digest('agent-lease-registration', { registration, tenant: config.tenant, subject: config.subject, workload: config.workloadId, descriptor: config.descriptorDigest, gateway: config.gatewayUrl, admission: config.admissionUrl, issuance: config.issuanceUrl, status: config.statusUrl, delegationAudience: config.delegationAudience, proposalKeys: config.proposalKeys, registryKeys: config.registryKeys, manifestKeys: config.manifestKeys, admissionKeys: config.admissionKeys, issuerKeys: config.issuerKeys });
}
function reference(r) {
  exact(r, ['id', 'schema', 'digest']);
  if (!id(r.id) || !id(r.schema) || !pin(r.digest)) throw new Error('invalid lease witness reference');
}
export function verifyLeaseEvidence(packet, proposal, config, r, now, { staticOnly = false, issuedAt = null } = {}) {
  exact(packet, ['manifest', 'witnesses']);
  const m = verifyRecord(packet.manifest, 'manifest', config.manifestKeys).payload;
  exact(m, ['mid', 'proposal_digest', 'policy', 'witnesses', 'assembled_at']);
  const p = proposal.payload; const pd = recordDigest(proposal);
  if (p.tenant !== config.tenant || !same(p.subject, config.subject) || p.workload_id !== config.workloadId || !same(p.action, config.action) || p.action.digest !== config.descriptorDigest || p.delegation.authorization_server !== config.subject.iss || p.delegation.token_audience !== config.delegationAudience || p.workflow !== null || p.requested_completion !== 'dispatch_bound' || !Array.isArray(p.resources) || p.resources.length !== 1) throw new Error('lease proposal context/profile mismatch');
  const expected = ordered(r.obligations).filter(oid => !staticOnly || r.obligations[oid].stage === 'static');
  if (!time(now) || !time(p.created_at) || p.created_at > now || now - p.created_at >= r.maxProposalAgeMs || !time(p.delegation.expires_at) || now >= p.delegation.expires_at || !id(m.mid) || m.proposal_digest !== pd || !same(m.policy, r.policy) || !time(m.assembled_at) || m.assembled_at < p.created_at || m.assembled_at > now || !Array.isArray(m.witnesses) || m.witnesses.length !== expected.length || !Array.isArray(packet.witnesses) || packet.witnesses.length !== expected.length) throw new Error('lease evidence coverage/context/time');
  let validUntil = Math.min(p.created_at + r.maxProposalAgeMs, p.delegation.expires_at);
  if (!Array.isArray(p.baseline_state) || p.baseline_state.length !== 1 || !same(p.baseline_state[0].resource, p.resources[0])) throw new Error('lease baseline missing');
  for (const b of p.baseline_state) { if (!time(b.observed_at) || b.observed_at > now || !time(b.expires_at) || b.expires_at <= now) throw new Error('lease baseline expired'); validUntil = Math.min(validUntil, b.expires_at); }
  const rawByDigest = new Map();
  for (const raw of packet.witnesses) {
    const e = strictJson(raw);
    const key = recordDigest(e);
    if (rawByDigest.has(key)) throw new Error('duplicate lease witness');
    rawByDigest.set(key, raw);
  }
  const seen = new Map();
  for (const entry of m.witnesses) {
    exact(entry, ['witness', 'obligation_id', 'execution_relevant', 'expires_at']); reference(entry.witness);
    const o = r.obligations[entry.obligation_id]; const raw = rawByDigest.get(entry.witness.digest);
    if (!expected.includes(entry.obligation_id) || seen.has(entry.obligation_id) || !o || !raw) throw new Error('missing/rebound lease witness');
    rawByDigest.delete(entry.witness.digest);
    const w = verifyRecord(raw, 'evidence', o.keys); const e = w.payload;
    exact(e, ['wid', 'provider_id', 'provider_version', 'question_ref', 'proposal_digest', 'state_scope', 'state_digest', 'result_schema', 'result', 'observed_at', 'expires_at', 'provenance_refs', 'exposure_domains']);
    reference(e.question_ref); reference(e.result_schema);
    if (!same(entry.witness, { id: e.wid, schema: w.schema, digest: recordDigest(w) }) || e.proposal_digest !== pd || !same(e.state_scope, p.resources) || e.state_digest !== p.baseline_state[0].state_digest || !pin(e.state_digest) || !Array.isArray(e.provenance_refs) || e.provenance_refs.length || !Array.isArray(e.exposure_domains) || !e.exposure_domains.length || !e.exposure_domains.every(id) || !e.result || Array.isArray(e.result) || typeof e.result !== 'object' || e.provider_id !== o.provider_id || e.provider_version !== o.provider_version || entry.execution_relevant !== o.execution_relevant || entry.expires_at !== e.expires_at || !time(e.observed_at) || e.observed_at > now || e.observed_at > m.assembled_at || !time(e.expires_at) || e.expires_at <= now || e.expires_at <= e.observed_at || now - e.observed_at >= o.max_age_ms || (o.stage === 'jit' && (now - e.observed_at >= r.jitMaxAgeMs || issuedAt !== null && e.observed_at < issuedAt))) throw new Error('lease witness signature/context/freshness');
    validUntil = Math.min(validUntil, e.expires_at, e.observed_at + o.max_age_ms, o.stage === 'jit' ? e.observed_at + r.jitMaxAgeMs : Number.MAX_SAFE_INTEGER);
    seen.set(entry.obligation_id, { raw, discharge: { obligation_id: entry.obligation_id, predicate_digest: o.predicate_digest, witness_refs: [entry.witness], result: 'satisfied', stage: o.stage, execution_relevant: o.execution_relevant, observed_at: e.observed_at, expires_at: e.expires_at } });
  }
  return { validUntil, witnesses: seen, discharges: expected.map(oid => seen.get(oid).discharge) };
}
export function verifyLease(raw, proposal, packet, config, r, now) {
  const inputs = verifyLeaseEvidence(packet, proposal, config, r, now, { staticOnly: true });
  const e = verifyRecord(raw, 'lease', config.admissionKeys); const l = e.payload; const p = proposal.payload;
  exact(l, ['lid', 'proposal_digest', 'delegation_digest', 'subject', 'workload_id', 'policy', 'descriptor_digest', 'ownership_epoch', 'static_discharges', 'pending_jit_obligations', 'issued_at', 'expires_at', 'execution_authority']);
  const pending = ordered(r.obligations).filter(oid => r.obligations[oid].stage === 'jit');
  if (typeof l.lid !== 'string' || !/^kf-lease:[a-f0-9]{64}$/.test(l.lid) || l.execution_authority !== false || l.proposal_digest !== recordDigest(proposal) || l.delegation_digest !== digest('delegation', p.delegation) || !same(l.subject, config.subject) || l.workload_id !== config.workloadId || !same(l.policy, r.policy) || l.descriptor_digest !== config.descriptorDigest || l.ownership_epoch !== r.ownershipEpoch || !same(l.static_discharges, inputs.discharges) || !same(l.pending_jit_obligations, pending) || !time(l.issued_at) || l.issued_at < p.created_at || l.issued_at > now || !time(l.expires_at) || l.expires_at <= now || l.expires_at <= l.issued_at || l.expires_at > inputs.validUntil || l.expires_at - l.issued_at > r.maxLifetimeMs) throw new Error('lease signature/binding/authority/freshness');
  return e;
}
export function verifyJit(packet, proposal, staticPacket, lease, config, r, now) {
  const original = verifyLeaseEvidence(staticPacket, proposal, config, r, now, { staticOnly: true });
  const inputs = verifyLeaseEvidence(packet, proposal, config, r, now, { issuedAt: lease.payload.issued_at });
  for (const [oid, w] of original.witnesses) {
    if (!same(strictJson(w.raw), strictJson(inputs.witnesses.get(oid).raw))) throw new Error('JIT source substituted original static evidence');
  }
  return inputs;
}
export function verifyLeaseCertificate(c, lease, inputs, r, now) {
  if (c.lease_digest !== recordDigest(lease) || !same(c.policy, r.policy) || c.ownership_epoch !== r.ownershipEpoch || !same(c.discharges, inputs.discharges) || !time(c.admitted_at) || c.admitted_at < lease.payload.issued_at || c.admitted_at > now || !time(c.expires_at) || c.expires_at <= now || c.expires_at > Math.min(lease.payload.expires_at, inputs.validUntil)) throw new Error('certificate lease binding mismatch');
}
