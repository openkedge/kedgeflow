import assert from 'node:assert/strict';
import { canonical, digest, privateSeed, publicBytes, recordDigest, signedRecord, strictJson, verifyRecord } from '../../sdk/node/records.mjs';
import { fixedHttps, mtlsFetch } from '../../sdk/node/transport.mjs';
import { validateRemediation } from '../../sdk/node/agent-adapter.mjs';
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
console.log(JSON.stringify({ status: 'PASS', vectors: ['strict JSON/canonicalization', 'role-bound signatures', 'proposal identity', 'remediation endpoint/expiry/action/parameters', 'fixed transport', 'durable store/restart/single writer'] }));
