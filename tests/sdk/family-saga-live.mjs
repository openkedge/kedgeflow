// Actual native MCP/AS/broker/SQL fixture. The protected phase hint is supplied
// by the Rust host; native final CAS guards remain authoritative. Owner phase
// commands are exercised by the host, not simulated as completed Node effects.
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
function member(cfg, child, lane) {
  const store = new FileOperationStore(cfg.storeDirectory);
  const pinned = mtlsFetch({ ...cfg.tls, allowedUrls: [cfg.config.gatewayUrl, cfg.config.admissionUrl, cfg.config.issuanceUrl, cfg.config.statusUrl, cfg.evidenceUrl] });
  const fetch = async (url, init) => {
    const request = strictJson(init.body);
    const h = new Headers(init.headers); const proof = h.get('DPoP');
    const entry = { child, lane, method: request.method ?? request.operation ?? 'evidence', grantPresent: h.has('Mcp-KedgeFlow-Grant'), jti: proof ? strictJson(Buffer.from(proof.split('.')[1], 'base64url').toString()).jti : null };
    wire.push(entry);
    const started = Date.now();
    try {
      const response = await pinned(url, init);
      entry.status = response.status;
      if (!response.ok) entry.failure = await response.clone().text();
      if (['tools/call', 'kedgeflow/status'].includes(request.method)) {
        const body = strictJson(await response.clone().text());
        if (body.error) entry.rpc_error = { code: body.error.code, message: body.error.message };
      }
      return response;
    } catch (error) { entry.transport_error = error.message; throw error; }
    finally { entry.elapsed_ms = Date.now() - started; }
  };
  let adapter;
  adapter = new AgentAdapter({ Client, StreamableHTTPClientTransport, config: cfg.config, fetch, store,
    tokenProvider: async () => cfg.token, proposalKey: privateSeed(Buffer.alloc(32, 1)), dpopKey: privateSeed(Buffer.alloc(32, 8)), now: () => cfg.now,
    evidenceSource: {
      prepareProposal: async context => {
        const reply = await fetch(cfg.evidenceUrl, { method: 'POST', headers: await adapter.headers(cfg.evidenceUrl, { 'Content-Type': 'application/json' }), body: canonical({ operation: 'baseline', parameters: context.call.arguments }) });
        assert.equal(reply.status, 200);
        return { ...cfg.proposalTemplate, qid: context.qid, parameters: context.call.arguments, action: context.action, delegation: context.delegation, created_at: context.now, baseline_state: [strictJson(await reply.text())] };
      },
      collect: async body => {
        const reply = await fetch(cfg.evidenceUrl, { method: 'POST', headers: await adapter.headers(cfg.evidenceUrl, { 'Content-Type': 'application/json' }), body: canonical(body) });
        assert.equal(reply.status, 200); return strictJson(await reply.text());
      },
    },
  });
  agents.push(adapter);
  return { adapter, qid: cfg.qid, arguments: cfg.proposalTemplate.parameters };
}
const members = Object.fromEntries(Object.entries(f.members).map(([child, lanes]) => [child, {
  forward: member(lanes.forward, child, 'forward'), inverse: member(lanes.inverse, child, 'inverse'),
}]));
const unavailableOwner = async () => { throw new Error('owner command not selected by this native inverse execution fixture'); };
const runner = new FamilySagaRunner({ registration: f.registration, members,
  local: { status: async () => strictJson(canonical(f.state)), lookup: unavailableOwner, apply: unavailableOwner, stage: unavailableOwner },
  store: new FileOperationStore(f.runnerStoreDirectory), directory: f.preparedDirectory,
});
const selected = members[f.child].inverse.adapter;
try {
  await selected.connect({ queryOnly: f.mode === 'resume' });
  const result = await runner.execute(f.child, 'inverse');
  assert.equal(result.state, f.expectedState, JSON.stringify(wire));
  assert(result.attempt_id); assert.match(result.grant_digest, /^[a-f0-9]{64}$/);
  const replay = await runner.execute(f.child, 'inverse');
  assert.equal(replay.attempt_id, result.attempt_id); assert.equal(replay.grant_digest, result.grant_digest);
  const writes = wire.filter(w => w.method === 'tools/call' && w.grantPresent);
  assert.equal(writes.length, f.mode === 'resume' ? 0 : 1);
  assert.equal(wire.filter(w => w.method === 'admit').length, f.mode === 'resume' ? 0 : 1);
  assert.equal(wire.filter(w => w.method === 'issue').length, f.mode === 'resume' ? 0 : 1);
  assert(wire.every(w => w.child === f.child && w.lane === 'inverse'));
  assert.equal(new Set(wire.map(w => w.jti)).size, wire.length);
  console.log(JSON.stringify({ status: 'PASS', runner: 'FamilySagaRunner', sdk: '@modelcontextprotocol/client', version: '2.3.0', child: f.child, mode: f.mode, state: result.state, attempt_id: result.attempt_id, grant_digest: result.grant_digest, wire }));
} finally { await Promise.allSettled(agents.map(a => a.close())); }
