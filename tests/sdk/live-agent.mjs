import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { AgentAdapter } from '../../sdk/node/agent-adapter.mjs';
import { privateSeed, strictJson } from '../../sdk/node/records.mjs';
import { mtlsFetch } from '../../sdk/node/transport.mjs';
import { FileOperationStore } from '../../sdk/node/store.mjs';

const f = strictJson(await readFile(process.argv[2], 'utf8'));
const wire = [];
let lost = false;
const pinned = mtlsFetch({ ...f.tls, allowedUrls: [f.config.gatewayUrl, f.config.admissionUrl, f.config.issuanceUrl, f.config.statusUrl, f.evidenceUrl] });
const fetch = async (url, init) => {
  const request = strictJson(init.body);
  const headers = new Headers(init.headers);
  const proof = headers.get('DPoP');
  wire.push({ endpoint: String(url), method: request.method ?? request.operation ?? 'evidence', grantPresent: headers.has('Mcp-KedgeFlow-Grant'), jti: proof ? strictJson(Buffer.from(proof.split('.')[1], 'base64url').toString()).jti : null });
  const response = await pinned(url, init);
  if ((f.mode === 'issuer-lost' && request.operation === 'issue' || f.mode === 'provider-lost' && String(url) === f.evidenceUrl && request.proposal) && !lost) {
    await response.arrayBuffer(); lost = true; throw new Error('simulated lost authority/provider reply');
  }
  if (f.mode === 'lost' && request.method === 'tools/call' && headers.has('Mcp-KedgeFlow-Grant') && !lost) {
    await response.arrayBuffer(); lost = true;
    throw new Error('simulated lost committed execution reply');
  }
  return response;
};
const store = new FileOperationStore(f.storeDirectory);
const put = store.put.bind(store);
store.put = async (qid, record) => {
  if (f.mode === 'persistence-lost' && record.grant && !lost) { lost = true; throw new Error('simulated grant persistence failure'); }
  return put(qid, record);
};
let agent;
agent = new AgentAdapter({ Client, StreamableHTTPClientTransport, config: f.config, fetch,
  tokenProvider: async () => f.token, proposalKey: privateSeed(Buffer.alloc(32, 1)), dpopKey: privateSeed(Buffer.alloc(32, 8)), store,
  now: f.realtime ? Date.now : () => f.now,
  evidenceSource: {
    prepareProposal: async context => {
      const response = await fetch(f.evidenceUrl, { method: 'POST', headers: await agent.headers(f.evidenceUrl, { 'Content-Type': 'application/json' }), body: JSON.stringify({ operation: 'baseline', parameters: context.call.arguments }) });
      assert.equal(response.status, 200);
      const baseline = strictJson(await response.text());
      return { ...f.proposalTemplate, qid: context.qid, parameters: context.call.arguments, action: context.action, delegation: context.delegation, created_at: context.now, baseline_state: [baseline] };
    },
    collect: async body => {
      const response = await fetch(f.evidenceUrl, { method: 'POST', headers: await agent.headers(f.evidenceUrl, { 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
      assert.equal(response.status, 200);
      return strictJson(await response.text());
    }
  }
});
try {
  await agent.connect({ queryOnly: f.mode === 'resume' });
  const call = { qid: f.qid ?? 'sdk:live-operation', arguments: f.proposalTemplate.parameters };
  const result = await agent.execute(call);
  const retained = await store.get(call.qid);
  if (f.executeOnly) {
    assert(retained.grant && retained.certificate);
    assert.equal(wire.filter(w => w.method === 'tools/call' && w.grantPresent).length, 1);
    assert.equal(wire.filter(w => w.method === 'admit').length, 1);
    assert.equal(wire.filter(w => w.method === 'issue').length, 1);
    console.log(JSON.stringify({ status: 'PASS', state: result.state, attempt_id: result.attempt_id, grant_digest: result.grant_digest, wire }));
  } else {
    assert.equal(result.state, f.expectedState);
    if (['committed', 'unknown', 'not_dispatched'].includes(f.expectedState)) assert(result.attempt_id); else assert.equal(result.attempt_id, null);
    if (['committed', 'unknown', 'not_dispatched'].includes(f.expectedState)) {
      assert(retained.grant && retained.certificate);
      assert.equal(f.config.gatewayUrl, strictJson(retained.grant).payload.audience);
    } else { assert.equal(retained.grant, undefined); }
    for (let i = 0; i < 3; i++) {
      const status = await agent.status(call.qid);
      assert.equal(status.state, f.expectedState);
      assert.equal(status.attempt_id, result.attempt_id);
      assert.equal(status.grant_digest, result.grant_digest);
    }
    const unchanged = await agent.execute(call);
    assert.equal(unchanged.attempt_id, result.attempt_id);
    await assert.rejects(agent.execute({ ...call, arguments: { ...call.arguments, expected_version: call.arguments.expected_version + 1 } }), f.config.compensation ? /inverse original parameter binding mismatch/ : /binding conflict/);
    assert.equal(wire.filter(w => w.method === 'tools/call' && w.grantPresent).length, f.mode === 'resume' || !['committed', 'unknown', 'not_dispatched'].includes(f.expectedState) ? 0 : 1);
    assert.equal(wire.filter(w => w.method === 'admit').length, f.mode === 'resume' || f.mode === 'provider-lost' ? 0 : 1);
    assert.equal(wire.filter(w => w.method === 'issue').length, f.mode === 'resume' || f.mode === 'provider-lost' ? 0 : 1);
    assert.equal(new Set(wire.map(w => w.jti)).size, wire.length);
    assert(wire.filter(w => w.method === 'kedgeflow/status').every(w => !w.grantPresent));
    if (f.mode !== 'normal' && f.mode !== 'resume') assert(lost);
    console.log(JSON.stringify({ status: 'PASS', mode: f.mode, sdk: '@modelcontextprotocol/client', version: '2.3.0', node: process.version, state: result.state, attempt_id: result.attempt_id, grant_digest: result.grant_digest, wire }, null, 2));
  }
} finally { await agent.close(); }
