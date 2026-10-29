import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { digest, privateSeed, recordDigest, same, strictJson } from '../../sdk/node/records.mjs';
import { AgentAdapter } from '../../sdk/node/agent-adapter.mjs';
import { FamilySagaRunner } from '../../sdk/node/family-saga.mjs';
import { DRAIN_PROFILE, validateDrainDescriptor } from '../../sdk/node/kube-drain.mjs';
import { MANAGED_DRAIN_ACTION, MANAGED_DRAIN_PROFILE, MANAGED_DRAIN_EXTENSION, ACCEPTANCE_PROFILE,
  managedDrainRegistration, managedDrainBindings, managedDrainSchema, managedDrainMetadata,
  validateManagedDrainDescriptor, validateManagedDrainArguments, validateManagedDrainGrant,
  validateManagedDrainResult, managedDrainNativeStatus } from '../../sdk/node/managed-kube-drain.mjs';

// These are public, previously qualified actual SQL/etcd/Kubernetes sources.
// Historical vectors do not constitute a fresh shipping-agent qualification.
const root = new URL('../../results/verification/rfc-m8-managed-controller-2026-10-27/native-artifacts/managed-controller-completed/', import.meta.url);
const trust = JSON.parse(await readFile(new URL('trust.json', root), 'utf8'));
const bundle = JSON.parse(await readFile(new URL('bundle.json', root), 'utf8'));
const selection = trust.selection, family = selection.registration;
const node = family.composition.nodes.find(n => n.child_id === selection.child_id);
const aggregate = bundle.evidence.materials[bundle.evidence.current_aggregate_digest].record;
const member = aggregate.evidence.current.snapshot.members[selection.child_id];
const authorization = member.authorizations[node.operation_key];
const descriptor = strictJson(authorization.packet.descriptor), d = descriptor.payload;
const grant = strictJson(authorization.issuance.signed_grant), g = grant.payload;
const r = managedDrainRegistration(selection), b = managedDrainBindings(r);
const args = { node: b.node, expected_version: b.generation };
assert.equal(digest('family-registration', family), aggregate.evidence.current.snapshot.registration_digest);
assert.equal(b.enrollmentDigest, bundle.checkpoint.body.enrollment_digest);
assert.equal(b.action.digest, recordDigest(descriptor));
assert(same(managedDrainSchema(r), d.parameter_schema));
validateManagedDrainDescriptor(d, r); validateManagedDrainArguments(d, args, r); validateManagedDrainGrant(d, g, args, r);
assert.throws(() => validateDrainDescriptor(d, r));
assert.throws(() => validateManagedDrainDescriptor(d));
for (const change of [{ profile: DRAIN_PROFILE }, { selection: { ...selection, child_id: 'absent' } }, { extra: true }]) assert.throws(() => managedDrainBindings({ ...r, ...change }));
for (const change of [{ controller_workload: node.physical.operating.supervisor_workload }, { mechanical_contract_digest: 'a'.repeat(64) }, { maximum_authorization_to_send_ms: 1001 }, { profile: DRAIN_PROFILE }, { extra: true }]) {
  const bad = structuredClone(r); Object.assign(bad.selection.registration.composition.nodes.find(n => n.child_id === selection.child_id).physical.operating, change);
  assert.throws(() => managedDrainBindings(bad));
}
for (const change of [{ version: '1.0' }, { gateway_audience: 'https://other.test/execute' }, { parameter_schema: { ...d.parameter_schema, additionalProperties: true } }, { adapter_contract: { ...d.adapter_contract, commit_point: 'physical_completion' } }, { concurrency: { ...d.concurrency, predicate_descriptor: { ...d.concurrency.predicate_descriptor, version: 'other' } } }]) assert.throws(() => validateManagedDrainDescriptor({ ...d, ...change }, r));
for (const change of [{ node: 'other' }, { expected_version: b.generation + 1 }, { fence: 1 }, { source_url: 'https://other.test/query' }]) assert.throws(() => validateManagedDrainArguments(d, { ...args, ...change }, r));
for (const change of [{ action: { ...g.action, digest: 'a'.repeat(64) } }, { audience: 'https://other.test/mcp' }, { predicate_descriptor: { ...g.predicate_descriptor, id: 'other' } }, { action: { ...g.action, version: '1.0' } }, { resources: [] }, { completion_mode: 'effect_bound' }, { parameters_digest: 'a'.repeat(64) }]) assert.throws(() => validateManagedDrainGrant(d, { ...g, ...change }, args, r));

// Recover the original signed initial mechanical state; do not sign new evidence.
const source = structuredClone(bundle.evidence.source);
const [controlKey, control] = Object.entries(source.controls).find(([, p]) => p.body.kind === 'accepted');
const end = source.events.findIndex(e => e.change.kind === 'controller_accepted' && e.change.proof_digest === controlKey) + 1;
assert(end > 0);
source.events = source.events.slice(0, end);
const heads = source.events.map(e => digest('managed-drain-operating-event', e));
source.claims = Object.fromEntries(Object.entries(source.claims).filter(([, c]) => heads.includes(c.operating_head_digest)));
source.controls = { [controlKey]: control };
const mechanical = { ...control.body.mechanical_header, body: { accepted: member.physical.controller.body.accepted, steps: [], closed: null } };
const proof = { profile: ACCEPTANCE_PROFILE, enrollment_digest: b.enrollmentDigest, authorization,
  acceptance: { profile: MANAGED_DRAIN_PROFILE, enrollment_digest: b.enrollmentDigest, origin: source.origin, events: source.events, controller: mechanical, proof: control }, sources: source };
const receipt = { status: 'committed', grant_digest: recordDigest(grant), attempt_id: source.origin.original.attempt_id };
const result = { structuredContent: { commit_point: 'controller_acceptance', physical_status: 'unresolved', kedgeflow_drain_acceptance: mechanical, kedgeflow_managed_drain_acceptance: proof } };
validateManagedDrainResult(d, result, grant, receipt, r);
for (const mutate of [
  x => { x.structuredContent.physical_status = 'completed'; },
  x => { x.structuredContent.kedgeflow_managed_drain_acceptance.extra = true; },
  x => { x.structuredContent.kedgeflow_managed_drain_acceptance.profile = MANAGED_DRAIN_PROFILE; },
  x => { x.structuredContent.kedgeflow_managed_drain_acceptance.enrollment_digest = 'a'.repeat(64); },
  x => { x.structuredContent.kedgeflow_drain_acceptance.body.accepted.attempt_id = 'other'; },
  x => { x.structuredContent.kedgeflow_managed_drain_acceptance.sources.events = []; },
  x => { x.structuredContent.kedgeflow_managed_drain_acceptance.authorization.issuance.signed_grant = '{}'; },
]) {
  const bad = structuredClone(result); mutate(bad);
  assert.throws(() => validateManagedDrainResult(d, bad, grant, receipt, r));
}
for (const state of ['unclaimed', 'claimed', 'dispatch_authorized', 'committed', 'unknown', 'not_dispatched']) {
  const view = managedDrainNativeStatus(d, { state, attempt_id: receipt.attempt_id });
  assert.equal(view.state, state === 'committed' ? 'accepted' : state); assert.equal(view.native_state, state);
  assert.equal(view.physical_status, 'unresolved');
}

// Exercise actual AgentAdapter selection, wire negotiation, and retained-grant
// query-only recovery. No network authority or target dispatch is available here.
const key = privateSeed(Buffer.alloc(32, 201));
const keys = values => Object.fromEntries(Object.entries(values).map(([id, value]) => [id, Buffer.from(value, 'base64').toString('base64url')]));
const config = { gatewayUrl: d.gateway_audience, admissionUrl: 'https://control.test/admit', issuanceUrl: 'https://control.test/issue',
  delegationAudience: 'https://control.test/delegation', workloadId: g.workload_id, tenant: family.tenant, subject: g.subject,
  toolName: 'drain', descriptor: authorization.packet.descriptor, descriptorDigest: recordDigest(descriptor),
  registryKeys: keys(node.forward_trust.lineage.registry_keys), proposalKeys: keys(node.forward_trust.lineage.proposal_keys),
  issuerKeys: keys(node.forward_trust.lineage.grant_keys), managedDrain: r };
const extensions = { 'io.kedgeflow/governed-mcp': { profile: 'KF-MCP-0.1' }, 'io.kedgeflow/execution-status': { profile: 'KF-EXECUTION-STATUS-0.1-draft' },
  [MANAGED_DRAIN_EXTENSION]: { profile: MANAGED_DRAIN_PROFILE, acceptance_proof_profile: ACCEPTANCE_PROFILE, commit_point: 'controller_acceptance', physical_completion: 'separate_observation' } };
let catalog = { tools: [{ name: 'drain', inputSchema: managedDrainSchema(r), _meta: { [MANAGED_DRAIN_EXTENSION]: managedDrainMetadata(r) }, annotations: { readOnlyHint: false } }] };
let requests = 0;
class Client {
  async connect() {} async close() {}
  getNegotiatedProtocolVersion() { return '2026-07-28'; } getServerCapabilities() { return { extensions }; }
  async listTools() { return catalog; }
  async request(request) { requests++; assert.equal(request.method, 'kedgeflow/status'); return { state: 'committed', grant_digest: receipt.grant_digest, attempt_id: receipt.attempt_id }; }
  async callTool() { throw new Error('query-only recovery must never redispatch'); }
}
const original = { proposal: authorization.packet.proposal, grant: authorization.issuance.signed_grant };
const store = { withLock: async (_, fn) => fn(), get: async () => original, put: async () => { throw new Error('query-only recovery must not replace authority'); } };
const create = (override = {}) => new AgentAdapter({ Client, StreamableHTTPClientTransport: class {}, config: { ...config, ...override },
  dpopKey: key, proposalKey: key, store, evidenceSource: {}, fetch: async () => { throw new Error('unexpected authority request'); } });
for (const override of [{ managedDrain: undefined }, { drain: {} }, { managedDrain: { ...r, profile: DRAIN_PROFILE } }]) assert.throws(() => create(override));
const agent = create(); await agent.connect();
const saved = structuredClone(catalog);
catalog.tools[0]._meta[MANAGED_DRAIN_EXTENSION].policy_digest = 'a'.repeat(64);
await assert.rejects(agent.connect()); catalog = saved;
const ext = extensions[MANAGED_DRAIN_EXTENSION]; delete extensions[MANAGED_DRAIN_EXTENSION];
await assert.rejects(agent.connect({ queryOnly: true })); extensions[MANAGED_DRAIN_EXTENSION] = ext;
await agent.connect({ queryOnly: true });
agent.jkt = g.dpop_jkt;
const qid = strictJson(original.proposal).payload.qid;
const view = await agent.status(qid);
assert.equal(requests, 1); assert.equal(view.state, 'accepted'); assert.equal(view.physical_status, 'unresolved');
assert.equal(original.grant, authorization.issuance.signed_grant); await agent.close();
// The host runner must bind the entire managed selection, including the other
// members. Native methods here are deliberately unavailable test doubles.
const runnerFamily = structuredClone(family);
const inverseQid = 'managed-runner-vector-inverse';
const inverse = runnerFamily.children[0].inverse;
inverse.inverse_operation_key = digest('issuance-key', { tenant: family.tenant, subject: g.subject, workload_id: g.workload_id, qid: inverseQid });
const runnerRegistration = managedDrainRegistration({ registration: runnerFamily, child_id: selection.child_id });
let queries = 0;
const makeMember = (scope, qid, registration) => {
  const adapter = Object.create(AgentAdapter.prototype);
  adapter.config = { tenant: family.tenant, subject: g.subject, workloadId: g.workload_id, gatewayUrl: scope.audience, action: scope.action };
  if (registration) adapter.config.managedDrain = registration;
  adapter.operation = () => {};
  adapter.execute = async () => { throw new Error('native execution unavailable in binding vectors'); };
  adapter.status = async () => { queries++; return { state: 'accepted', physical_status: 'unresolved', attempt_id: receipt.attempt_id }; };
  return { adapter, qid, arguments: {} };
};
const predecessorAuth = Object.values(aggregate.evidence.current.snapshot.members['child-0'].authorizations)[0];
const predecessorQid = strictJson(predecessorAuth.packet.proposal).payload.qid;
const members = {
  'child-0': { forward: makeMember(runnerFamily.children[0].reservation.scope, predecessorQid), inverse: makeMember(inverse.inverse_scope, inverseQid) },
  'child-1': { forward: makeMember(runnerFamily.children[1].reservation.scope, qid, runnerRegistration) },
};
const local = { status: async () => { throw new Error('queryOriginal must not obtain new authority'); }, stage: async () => {}, lookup: async () => {}, apply: async () => {} };
const options = { registration: runnerFamily, members, local, store, directory: '/unused-managed-binding-vector' };
const runner = new FamilySagaRunner(options);
assert.equal((await runner.queryOriginal('child-1')).state, 'accepted'); assert.equal(queries, 1);
const selected = members['child-1'].forward.adapter.config;
selected.managedDrain = r;
assert.throws(() => new FamilySagaRunner(options), /managed adapter enrollment/);
selected.managedDrain = runnerRegistration;
delete selected.managedDrain;
assert.throws(() => new FamilySagaRunner(options));
selected.managedDrain = runnerRegistration;
const changed = structuredClone(runnerFamily); changed.children[1].reservation.scope.action.id = 'kubernetes.node.drain';
assert.throws(() => new FamilySagaRunner({ ...options, registration: changed }));
console.log(JSON.stringify({ status: 'PASS', vectors: ['prior actual source/digest/schema interoperability', 'explicit managed registration and legacy refusal', 'scope/role/schema/argument/grant substitutions', 'original acceptance/result correlation', 'managed wire negotiation and exact protected metadata', 'retained original query-only accepted/unresolved status', 'whole-family managed runner binding and original query'], scope: 'historical SDK vectors; no fresh native or physical qualification' }));
