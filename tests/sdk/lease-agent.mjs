import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { AgentAdapter } from '../../sdk/node/agent-adapter.mjs';
import { privateSeed, strictJson, recordDigest } from '../../sdk/node/records.mjs';
import { mtlsFetch } from '../../sdk/node/transport.mjs';
import { FileOperationStore } from '../../sdk/node/store.mjs';
const f = strictJson(await readFile(process.argv[2], 'utf8'));
const wire = []; let lost = false; let lostLease = null;
const pinned = mtlsFetch({ ...f.tls, allowedUrls: [f.config.gatewayUrl, f.config.admissionUrl, f.config.issuanceUrl, f.config.statusUrl, f.config.leases.url, f.evidenceUrl] });
const fetch = async (url, init) => {
  const request = strictJson(init.body); const h = new Headers(init.headers);
  wire.push({ endpoint: String(url), method: request.method ?? request.operation ?? 'evidence', grant: h.has('Mcp-KedgeFlow-Grant'), jti: strictJson(Buffer.from(h.get('DPoP').split('.')[1], 'base64url').toString()).jti });
  const response = await pinned(url, init);
  if (!lost && (f.fault === 'lost-prevalidate' && request.operation === 'prevalidate' || f.fault === 'lost-jit' && request.operation === 'jit' || f.fault === 'lost-admit' && request.operation === 'admit' || f.fault === 'lost-issue' && request.operation === 'issue')) {
    assert(response.ok, 'fault must follow a successful native response'); const raw = Buffer.from(await response.arrayBuffer()).toString(); if (request.operation === 'prevalidate') lostLease = recordDigest(strictJson(strictJson(raw).lease)); lost = true; throw new Error('simulated lost lease workflow reply');
  }
  return response;
};
const store = new FileOperationStore(f.storeDirectory); const put = store.put.bind(store);
store.put = async (qid, value) => { if (f.fault === 'boundary-persistence-lost' && value.lease_preparation?.phase === 'authority_started' && !value.grant && !lost) { lost = true; throw new Error('simulated admission marker persistence failure'); } if (f.fault === 'persistence-lost' && value.grant && !lost) { lost = true; throw new Error('simulated grant persistence failure'); } return put(qid, value); };
let agent;
const collect = async body => { const response = await fetch(f.evidenceUrl, { method: 'POST', headers: await agent.headers(f.evidenceUrl, { 'Content-Type': 'application/json' }), body: JSON.stringify(body) }); assert.equal(response.status, 200); return strictJson(await response.text()); };
agent = new AgentAdapter({ Client, StreamableHTTPClientTransport, config: f.config, fetch, tokenProvider: async () => f.token, proposalKey: privateSeed(Buffer.alloc(32, 1)), dpopKey: privateSeed(Buffer.alloc(32, 8)), store, now: () => f.now,
  evidenceSource: { prepareProposal: async context => { const baseline = await collect({ operation: 'baseline', parameters: context.call.arguments }); return { ...f.proposalTemplate, qid: context.qid, parameters: context.call.arguments, action: context.action, delegation: context.delegation, created_at: context.now, baseline_state: [baseline] }; }, collectStatic: body => collect({ operation: 'static', ...body }), collectJit: body => collect({ operation: 'jit', ...body }) }
});
try {
  await agent.connect({ queryOnly: f.phase === 'query' });
  const call = { qid: 'sdk:lease-operation', arguments: f.proposalTemplate.parameters };
  let result;
  if (f.phase === 'prepare') {
    try { result = await agent.prevalidate(call); } catch (e) { if (f.fault !== 'lost-prevalidate') throw e; result = { state: 'unavailable' }; }
    assert.equal(wire.filter(w => ['admit', 'issue'].includes(w.method) || w.grant).length, 0);
    if (result.state === 'prevalidated') await assert.rejects(agent.prevalidate({ ...call, arguments: { ...call.arguments, expected_version: call.arguments.expected_version + 1 } }), /binding conflict/);
  } else if (f.phase === 'query') { result = await agent.status(call.qid); } else { result = await agent.execute(call); }
  const record = await store.get(call.qid);
  assert.equal(new Set(wire.map(w => w.jti)).size, wire.length);
  if (result.state === 'committed') { assert(record.grant && record.certificate); assert.equal(strictJson(record.certificate).payload.lease_digest, recordDigest(strictJson(record.lease))); }
  console.log(JSON.stringify({ status: 'PASS', state: result.state, retained_phase: record.lease_preparation.phase, lease: record.lease ? recordDigest(strictJson(record.lease)) : null, lost_lease: lostLease, lease_issued_at: record.lease ? strictJson(record.lease).payload.issued_at : null, lease_expires_at: record.lease ? strictJson(record.lease).payload.expires_at : null, admissions: wire.filter(w => w.method === 'admit').length, issues: wire.filter(w => w.method === 'issue').length, dispatches: wire.filter(w => w.method === 'tools/call' && w.grant).length, wire }));
} finally { await agent.close(); }
