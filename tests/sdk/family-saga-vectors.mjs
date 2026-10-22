// Client durability/selection boundaries only. Fake native calls below are not
// evidence of native composition execution or physical SQL/Kubernetes effects.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentAdapter } from '../../sdk/node/agent-adapter.mjs';
import { FamilySagaRunner, LocalSagaClient, SAGA_PROFILE } from '../../sdk/node/family-saga.mjs';
import { FileOperationStore } from '../../sdk/node/store.mjs';
import { canonical, digest } from '../../sdk/node/records.mjs';

assert.throws(() => new LocalSagaClient({ executable: 'relative', config: '/config', ownerKeyId: 'owner', ownerKey: '/owner' }));
const root = await mkdtemp(join(tmpdir(), 'kf-family-saga-vectors-'));
try {
  const action = { id: 'bounded.mock', version: '1', digest: 'a'.repeat(64) };
  const subject = { iss: 'issuer', sub: 'owner' };
  const counts = { native: 0, query: 0, stage: 0, apply: 0, lookup: 0 };
  const adapters = [0, 1].map(() => {
    const a = Object.create(AgentAdapter.prototype);
    a.config = { tenant: 'tenant', subject, workloadId: 'workload', gatewayUrl: 'https://gateway.test/mcp', action, toolName: 'mock' };
    a.descriptor = { payload: { action: action.id } }; a.jkt = 'original-proof';
    a.execute = async () => { counts.native++; throw new Error('lost native reply'); };
    a.status = async () => { counts.query++; return { state: 'unknown', attempt_id: 'original' }; };
    return a;
  });
  const ops = [0, 1].map(n => digest('issuance-key', { tenant: 'tenant', subject, workload_id: 'workload', qid: `fixed-${n}` }));
  const registration = { profile: SAGA_PROFILE, namespace: '/fixture', children: [0, 1].map(n => ({ id: `child-${n}`, reservation: { scope: { audience: 'https://gateway.test/mcp', action } }, inverse: null })),
    composition: { profile: SAGA_PROFILE, nodes: [0, 1].map(n => ({ child_id: `child-${n}`, operation_key: ops[n], depends_on: n ? ['child-0'] : [] })) } };
  const rd = digest('family-registration', registration);
  let state = { profile: SAGA_PROFILE, registration_digest: rd, phase: 'forward', head: 'b'.repeat(64), in_flight: null,
    members: { 'child-0': { forward: 'unissued', inverse: 'absent' }, 'child-1': { forward: 'unissued', inverse: 'absent' } } };
  let original;
  const local = {
    status: async () => structuredClone(state),
    stage: async ({ operationKey, action, path }) => {
      counts.stage++;
      original = canonical({ intent: { profile: SAGA_PROFILE, payload: { family_digest: rd, operation_key: operationKey, action: action.replaceAll('-', '_') } }, capture: null });
      await writeFile(path, original, { flag: 'wx', mode: 0o600 });
    },
    apply: async path => { counts.apply++; assert.equal(await readFile(path, 'utf8'), original); throw new Error('lost owner reply'); },
    lookup: async () => { counts.lookup++; return { state: structuredClone(state), execution_authority: false }; },
  };
  const members = Object.fromEntries(adapters.map((adapter, n) => [`child-${n}`, { forward: { adapter, qid: `fixed-${n}`, arguments: { value: n } } }]));
  const store = new FileOperationStore(join(root, 'store'));
  const options = { registration, members, local, store, directory: join(root, 'prepared') };
  assert.throws(() => new FamilySagaRunner({ ...options, members: { 'child-0': members['child-0'] } }));
  assert.throws(() => new FamilySagaRunner({ ...options, members: { ...members, 'child-1': { forward: { ...members['child-1'].forward, qid: 'replacement' } } } }));
  const runner = new FamilySagaRunner(options);
  await assert.rejects(runner.execute('child-1'), /dependency/);
  assert.equal(counts.native, 0);
  await assert.rejects(runner.execute('child-0'), /lost native/);
  assert.equal((await runner.execute('child-0')).state, 'unknown');
  state.phase = 'quiescing';
  assert.equal((await new FamilySagaRunner(options).execute('child-0')).state, 'unknown');
  assert.equal(counts.native, 1);
  assert.equal(counts.query, 2);
  adapters[0].config.gatewayUrl = 'https://other.test/mcp';
  await assert.rejects(runner.execute('child-0'), /binding changed/);
  adapters[0].config.gatewayUrl = 'https://gateway.test/mcp';
  const operationKey = 'c'.repeat(64);
  await runner.owner({ operationKey, action: 'quiesce' });
  assert.equal(counts.stage, 1); assert.equal(counts.apply, 1); assert.equal(counts.lookup, 1);
  await new FamilySagaRunner(options).owner({ operationKey, action: 'quiesce' });
  assert.equal(counts.stage, 1); assert.equal(counts.apply, 1); assert.equal(counts.lookup, 2);
  await assert.rejects(runner.owner({ operationKey, action: 'prepare-compensation' }), /command differs/);
  await assert.rejects(runner.replayOwner(operationKey), /lost owner/);
  assert.equal(counts.stage, 1); assert.equal(counts.apply, 2);
  const partialKey = 'd'.repeat(64);
  await writeFile(join(options.directory, `${rd}-${partialKey}.json`), '{"intent":');
  await assert.rejects(runner.owner({ operationKey: partialKey, action: 'quiesce' }));
  assert.equal(counts.stage, 1);
} finally { await rm(root, { recursive: true, force: true }); }
console.log(JSON.stringify({ status: 'PASS', vectors: ['fixed member/qid/action bindings', 'dependency refusal before native request', 'durable ambiguity before native admission', 'restart queries original after quiesce', 'owner signed file before submission', 'lost owner reply query without restaging', 'explicit exact replay', 'partial/conflicting original refuses'] }));
