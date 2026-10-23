// Official SDK over actual native services. The host owns SQL/phase transitions;
// native committed controller acceptance never becomes physical completion here.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { AgentAdapter } from '../../sdk/node/agent-adapter.mjs';
import { FamilySagaRunner } from '../../sdk/node/family-saga.mjs';
import { FileOperationStore } from '../../sdk/node/store.mjs';
import { canonical, privateSeed, strictJson } from '../../sdk/node/records.mjs';
import { mtlsFetch } from '../../sdk/node/transport.mjs';
const f = strictJson(await readFile(process.argv[2], 'utf8'));
const wire = [];
const agents = [];
function member(cfg) {
  const pinned = mtlsFetch({ ...cfg.tls, allowedUrls: [cfg.config.gatewayUrl, cfg.config.admissionUrl, cfg.config.issuanceUrl, cfg.config.statusUrl, cfg.evidenceUrl] });
  let adapter;
  const fetch = async (url, init) => {
    const request = strictJson(init.body);
    const headers = new Headers(init.headers);
    const proof = headers.get('DPoP');
    const entry = { method: request.method ?? request.operation ?? 'evidence', grantPresent: headers.has('Mcp-KedgeFlow-Grant'),
      jti: proof ? strictJson(Buffer.from(proof.split('.')[1], 'base64url').toString()).jti : null };
    wire.push(entry);
    const response = await pinned(url, init);
    entry.status = response.status;
    if (!response.ok) entry.failure = await response.clone().text();
    return response;
  };
  adapter = new AgentAdapter({ Client, StreamableHTTPClientTransport, config: cfg.config, fetch,
    tokenProvider: async () => cfg.token, proposalKey: privateSeed(Buffer.alloc(32, 1)), dpopKey: privateSeed(Buffer.alloc(32, 8)),
    store: new FileOperationStore(cfg.storeDirectory),
    evidenceSource: {
      prepareProposal: async context => {
        const response = await fetch(cfg.evidenceUrl, { method: 'POST', headers: await adapter.headers(cfg.evidenceUrl, { 'Content-Type': 'application/json' }), body: canonical({ operation: 'baseline', parameters: context.call.arguments }) });
        assert.equal(response.status, 200);
        return { ...cfg.proposalTemplate, qid: context.qid, parameters: context.call.arguments, action: context.action, delegation: context.delegation,
          created_at: context.now, baseline_state: [strictJson(await response.text())] };
      },
      collect: async body => {
        const response = await fetch(cfg.evidenceUrl, { method: 'POST', headers: await adapter.headers(cfg.evidenceUrl, { 'Content-Type': 'application/json' }), body: canonical(body) });
        assert.equal(response.status, 200); return strictJson(await response.text());
      },
    },
  });
  agents.push(adapter);
  return { adapter, qid: cfg.proposalTemplate.qid, arguments: cfg.proposalTemplate.parameters };
}
const physical = member(f.physical);
// The predecessor is already committed by the actual Rust/SQL host. This
// adapter is constructed only to bind the complete protected runner catalog.
const predecessor = member(f.predecessor);
const predecessorInverse = member(f.predecessorInverse);
const unavailable = async () => { throw new Error('owner commands belong to the host in this fixture'); };
const runner = new FamilySagaRunner({ registration: f.registration,
  members: { 'child-0': { forward: predecessor, inverse: predecessorInverse }, 'child-1': { forward: physical } },
  local: { status: async () => f.state, stage: unavailable, apply: unavailable, lookup: unavailable },
  store: new FileOperationStore(f.runnerStoreDirectory), directory: f.preparedDirectory,
});
try {
  await physical.adapter.connect({ queryOnly: f.mode === 'resume' });
  const result = await runner.execute('child-1');
  assert.equal(result.state, f.expectedState, JSON.stringify({ result, wire }));
  assert.equal(result.physical_status, 'unresolved');
  assert.equal(result.commit_point, 'controller_acceptance');
  assert.equal(result.native_state, f.expectedState === 'accepted' ? 'committed' : 'unknown');
  assert(result.attempt_id); assert.match(result.grant_digest, /^[a-f0-9]{64}$/);
  const replay = await runner.queryOriginal('child-1');
  assert.equal(replay.attempt_id, result.attempt_id); assert.equal(replay.state, result.state);
  assert.equal(wire.filter(w => w.method === 'tools/call' && w.grantPresent).length, f.mode === 'resume' ? 0 : 1);
  assert.equal(wire.filter(w => w.method === 'admit').length, f.mode === 'resume' ? 0 : 1);
  assert.equal(wire.filter(w => w.method === 'issue').length, f.mode === 'resume' ? 0 : 1);
  assert.equal(new Set(wire.map(w => w.jti)).size, wire.length);
  console.log(JSON.stringify({ status: 'PASS', sdk: '@modelcontextprotocol/client', version: '2.3.0', runner: 'FamilySagaRunner', mode: f.mode,
    state: result.state, native_state: result.native_state, physical_status: result.physical_status,
    attempt_id: result.attempt_id, grant_digest: result.grant_digest, wire }));
} finally { await Promise.allSettled(agents.map(a => a.close())); }
