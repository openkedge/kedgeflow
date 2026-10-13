import assert from 'node:assert/strict';
import { canonical, digest, privateSeed, publicBytes, recordDigest, signedRecord, strictJson, verifyRecord } from '../../sdk/node/records.mjs';
import { fixedHttps, mtlsFetch } from '../../sdk/node/transport.mjs';
import { AgentAdapter, OPERATION_STATUS_PROFILE, validateRemediation } from '../../sdk/node/agent-adapter.mjs';
import { FileOperationStore } from '../../sdk/node/store.mjs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

for (const raw of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '1.0', '1e0', '9007199254740992', '"\\ud800"', '[1,]', '{"a":1,}', '{"x":true} false']) assert.throws(() => strictJson(raw));
assert.equal(canonical(strictJson('{"z":-0,"a":[true,null,"ok"]}')), '{"a":[true,null,"ok"],"z":0}');
assert.throws(() => canonical({ x: undefined }));
const key = privateSeed(Buffer.alloc(32, 1));
const keys = { agent: publicBytes(key).toString('base64url') };
const raw = signedRecord('proposal', { qid: 'operation' }, 'agent', key);
const verified = verifyRecord(raw, 'proposal', keys);
assert.equal(verified.payload.qid, 'operation');
assert.throws(() => verifyRecord(raw, 'grant', keys));
assert.throws(() => verifyRecord(raw, 'proposal', { agent: publicBytes(privateSeed(Buffer.alloc(32, 2))).toString('base64url') }));
assert.throws(() => verifyRecord(raw.replace('operation', 'changed'), 'proposal', keys));
assert.equal(recordDigest(verified), digest('proposal', { schema: verified.schema, payload: verified.payload }));
const call = { name: 'reserve', arguments: { node: 'resource', expected_version: 1 } };
const config = { admissionUrl: 'https://control.test/admit', action: { id: 'reserve', version: '1', digest: 'a'.repeat(64) } };
const remediation = { remediation_id: 'id', code: 'NEEDS_EVIDENCE', proposal_digest: null, action: config.action, parameters_digest: digest('parameters', call.arguments), obligations: [{}], admission_endpoint: config.admissionUrl, profile: 'KF-JSON-0.2', grant_carriage: 'Mcp-KedgeFlow-Grant', expires_at: 2000, retry_after_admission: true };
validateRemediation(remediation, config, call, 1000);
for (const change of [{ admission_endpoint: 'https://evil.test/admit' }, { expires_at: 1000 }, { parameters_digest: 'b'.repeat(64) }, { action: { ...config.action, version: '2' } }, { profile: 'other' }, { grant_carriage: 'Other' }, { extra: true }]) assert.throws(() => validateRemediation({ ...remediation, ...change }, config, call, 1000));
for (const url of ['http://control.test/admit', 'https://user@control.test/admit', 'https://control.test/admit?x=1', 'https://control.test/admit#x']) assert.throws(() => fixedHttps(url));
assert.throws(() => mtlsFetch({ ca: '', cert: '', key: '', allowedUrls: ['https://control.test/admit'] }));
const fetch = mtlsFetch({ ca: 'test', cert: 'test', key: 'test', allowedUrls: ['https://control.test/admit'] });
await assert.rejects(fetch('https://other.test/admit', { method: 'POST', body: '{}' }), /unapproved/);
const directory = await mkdtemp(join(tmpdir(), 'kf-agent-vectors-'));
try {
  const store = new FileOperationStore(directory);
  await store.withLock('qid', async () => {
    await store.put('qid', { fingerprint: 'immutable', grant: 'signed' });
    await assert.rejects(store.withLock('qid', async () => {}), e => e.code === 'EEXIST');
  });
  const restarted = new FileOperationStore(directory);
  assert.equal((await restarted.get('qid')).grant, 'signed');
  assert.equal((await restarted.get('unknown')), null);
  assert.equal(JSON.parse(await readFile(store.path('qid'), 'utf8')).fingerprint, 'immutable');
  await assert.rejects(store.put('qid', { grant: 'x'.repeat(1 << 20) }), /bound/);
  assert.equal((await store.get('qid')).grant, 'signed');
  await restarted.withLock('qid', async () => {});
} finally { await rm(directory, { recursive: true }); }
// Independent reply substitutions: no SDK/session or execution permission is
// needed for this closed read-only client boundary.
const adapter = Object.create(AgentAdapter.prototype);
adapter.config = { statusUrl: 'https://control.test/status', subject: { iss: 'issuer', sub: 'user' }, tenant: 'tenant', workloadId: 'workload', action: config.action, proposalKeys: keys };
adapter.jkt = 'proof-key';
adapter.store = { get: async () => ({ proposal: signedRecord('proposal', { qid: 'qid', tenant: 'tenant', subject: adapter.config.subject, workload_id: 'workload', delegation: { dpop_jkt: adapter.jkt }, action: config.action }, 'agent', key) }) };
adapter.headers = async () => new Headers();
let change = {};
adapter.fetch = async (url, init) => {
  const body = strictJson(init.body);
  assert.equal(body.operation, 'status');
  const result = { profile: OPERATION_STATUS_PROFILE, operation: 'status_result', request_id: body.request_id, state: 'unissued', attempt_id: null, grant_digest: null, ...change };
  return { url, ok: true, text: async () => JSON.stringify(result) };
};
assert.equal((await adapter.status('qid')).state, 'unissued');
for (change of [{ extra: true }, { request_id: 'other' }, { profile: 'other' }, { state: 'unissued', grant_digest: 'a'.repeat(64) }, { state: 'unclaimed', grant_digest: 'a'.repeat(64), attempt_id: 'invented' }, { state: 'claimed', grant_digest: 'a'.repeat(64), attempt_id: null }, { state: 'unclaimed', grant_digest: ['a'.repeat(64)] }]) await assert.rejects(adapter.status('qid'));
change = { state: 'unclaimed', grant_digest: 'a'.repeat(64) };
assert.equal((await adapter.status('qid')).state, 'unclaimed');
await assert.rejects(adapter.status('different-qid'), /correlation/);

// A separately named SQL binding cannot widen a mock CTD or accept injected
// target metadata, floating versions, changed resource, or weakened schemas.
const { SQL_ACTION, SQL_SCHEMA, validateSqlDescriptor, validateSqlArguments } = await import('../../sdk/node/sql-leaf.mjs');
const sql = { action: SQL_ACTION, version: '1.0', parameter_schema: SQL_SCHEMA,
  parameter_schema_digest: digest('parameter-schema', SQL_SCHEMA),
  rendering: { parameter_schema_digest: digest('parameter-schema', SQL_SCHEMA) },
  adapter_contract: { fence_parameter: 'fence' },
  concurrency: { predicate_descriptor: { clauses: [{ kind: 'version_eq', resource: { id: 'resource' } }] } } };
validateSqlDescriptor(sql);
const args = { resource_id: 'resource', expected_version: 241, reservation: 'booking:123' };
validateSqlArguments(sql, args);
for (const change of [{ version: '2' }, { parameter_schema: { ...SQL_SCHEMA, additionalProperties: true } }, { parameter_schema_digest: 'a'.repeat(64) }, { adapter_contract: { fence_parameter: 'node' } }]) assert.throws(() => validateSqlDescriptor({ ...sql, ...change }));
for (const change of [{ node: 'resource' }, { fence: 4 }, { resource_id: 'other' }, { reservation: 'bad space' }, { expected_version: 1.5 }, { expected_version: 9007199254740991 }, { reservation: '' }]) assert.throws(() => validateSqlArguments(sql, { ...args, ...change }));
console.log(JSON.stringify({ status: 'PASS', vectors: ['strict JSON/canonicalization', 'role-bound signatures', 'proposal identity', 'remediation endpoint/expiry/action/parameters', 'fixed transport', 'durable store/restart/single writer', 'operation status closed replies/correlation', 'SQL descriptor/profile/schema and closed application arguments'] }));
