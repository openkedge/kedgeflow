import assert from 'node:assert/strict';
import { digest, privateSeed, publicBytes, recordDigest, signedRecord, strictJson } from '../../sdk/node/records.mjs';
import { AgentAdapter, STATUS_EXTENSION, STATUS_PROFILE } from '../../sdk/node/agent-adapter.mjs';
import { TERRAFORM_PAIR_ACTION, TERRAFORM_PAIR_PROFILE, TERRAFORM_PAIR_RUNNER, TERRAFORM_PAIR_EXTENSION, TERRAFORM_PAIR_CAPABILITIES, TERRAFORM_PAIR_ADAPTER, terraformPairSchema, terraformPairMetadata, validateTerraformPairDescriptor, validateTerraformPairArguments, validateTerraformPairGrant, validateTerraformPairResult } from '../../sdk/node/terraform-pair.mjs';
let checks = 0;
const pass = f => { f(); checks++; };
const refuse = f => { assert.throws(f); checks++; };
const copy = x => structuredClone(x);
const r = { profile: TERRAFORM_PAIR_PROFILE, manifestDigest: 'a'.repeat(64), effectDigest: 'b'.repeat(64), inspectionSha256: 'c'.repeat(64), resource: { id: `terraform-pair:${'a'.repeat(64)}`, incarnation: '9'.repeat(64) }, members: [{ id: 'first', target_uid: 'uid-first' }, { id: 'second', target_uid: 'uid-second' }] };
const schema = terraformPairSchema(r);
const coverage = { coordinated_writers: ['protected-terraform-runner'], uncoordinated_writers: ['privileged-administrators', 'kubernetes-control-plane'] };
coverage.inventory_digest = digest('coverage-inventory', coverage);
const d = { action: TERRAFORM_PAIR_ACTION, version: '1.0', gateway_audience: 'https://gateway.test/mcp', parameter_schema: schema, parameter_schema_digest: digest('parameter-schema', schema), rendering: { parameter_schema_digest: digest('parameter-schema', schema) }, adapter_contract: TERRAFORM_PAIR_ADAPTER, concurrency: { coverage, predicate_descriptor: { id: 'plan', version: '1', language: 'kf-conjunction-v1', clauses: [{ kind: 'version_eq', resource: r.resource, expected_version: '1' }] } } };
const args = { node: r.resource.id, expected_version: 1, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest };
pass(() => validateTerraformPairDescriptor(d, r));
pass(() => validateTerraformPairArguments(d, args, r));
for (const key of ['profile', 'manifestDigest', 'effectDigest', 'inspectionSha256']) { const bad = copy(r); bad[key] = 'other'; refuse(() => validateTerraformPairDescriptor(d, bad)); }
refuse(() => validateTerraformPairDescriptor(d, undefined));
refuse(() => validateTerraformPairDescriptor({ ...d, action: 'other' }, r));
for (const mutate of [x => x.adapter_contract.level = 'Level_A', x => x.adapter_contract.guard_primitive = 'FencingToken', x => x.concurrency.coverage.uncoordinated_writers = [], x => x.parameter_schema.additionalProperties = true, x => x.parameter_schema_digest = 'd'.repeat(64), x => x.concurrency.predicate_descriptor.clauses[0].resource.incarnation = 'other']) { const bad = copy(d); mutate(bad); refuse(() => validateTerraformPairDescriptor(bad, r)); }
for (const key of ['node', 'expected_version', 'manifest_digest', 'effect_digest', 'command', 'credential', 'kf_fence']) { const bad = copy(args); bad[key] = key === 'expected_version' ? 2 : 'other'; refuse(() => validateTerraformPairArguments(d, bad, r)); }
const g = { action: { id: TERRAFORM_PAIR_ACTION, version: '1.0' }, parameters_digest: digest('parameters', args), resources: [r.resource], adapter_contract: TERRAFORM_PAIR_ADAPTER, completion_mode: 'dispatch_bound', parent_grant_digest: null, saga_budget: null, root_id: 'original-root', valid_from: 1, expires_at: 100, fence: 1 };
pass(() => validateTerraformPairGrant(d, g, args, r));
for (const mutate of [x => x.parent_grant_digest = 'd'.repeat(64), x => x.saga_budget = {}, x => x.parameters_digest = 'd'.repeat(64), x => x.resources[0].incarnation = 'other', x => x.action.version = '2']) { const bad = copy(g); mutate(bad); refuse(() => validateTerraformPairGrant(d, bad, args, r)); }
const receipt = { attempt_id: 'original-attempt', grant_digest: 'd'.repeat(64), resource: r.resource, fence: 1, status: 'committed' };
const pair = { tool_succeeded: true, backend_progress: true, members: r.members.map(m => ({ ...m, state: 'desired', observation_digest: '8'.repeat(64), observed_at: 15 })) };
const report = { profile: TERRAFORM_PAIR_RUNNER, status: 'committed', replayed: false, observed_postcondition: true, intent: { profile: TERRAFORM_PAIR_RUNNER, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest, grant_digest: receipt.grant_digest, root_id: g.root_id, attempt_id: receipt.attempt_id, state: 'applied', initiated_at: 10, backend_before_sha256: 'e'.repeat(64), backend_after_sha256: 'f'.repeat(64), observed_after_digest: digest('terraform-pair-observation', pair), last_error: null, pair } };
const result = { structuredContent: { kedgeflow_terraform_report: report, kedgeflow_terraform_binding: terraformPairMetadata(r) } };
pass(() => validateTerraformPairResult(d, result, { payload: g }, receipt, r));
for (const mutate of [x => x.observed_postcondition = false, x => x.replayed = true, x => x.extra = true, x => x.intent.state = 'unknown', x => x.intent.attempt_id = 'other', x => x.intent.root_id = 'other', x => x.intent.effect_digest = '2'.repeat(64), x => x.intent.grant_digest = '2'.repeat(64), x => x.intent.manifest_digest = '2'.repeat(64), x => x.intent.last_error = 'unresolved', x => x.intent.backend_after_sha256 = x.intent.backend_before_sha256, x => x.intent.observed_after_digest = null, x => x.intent.initiated_at = 100]) { const bad = copy(result); mutate(bad.structuredContent.kedgeflow_terraform_report); refuse(() => validateTerraformPairResult(d, bad, { payload: g }, receipt, r)); }
{ const bad = copy(result); bad.structuredContent.kedgeflow_terraform_binding.target_atomic = true; refuse(() => validateTerraformPairResult(d, bad, { payload: g }, receipt, r)); }
class Client {
  constructor() { this.extensions = { 'io.kedgeflow/governed-mcp': { profile: 'KF-MCP-0.1' }, [STATUS_EXTENSION]: { profile: STATUS_PROFILE }, [TERRAFORM_PAIR_EXTENSION]: TERRAFORM_PAIR_CAPABILITIES }; this.catalog = { tools: [{ name: 'terraform_apply', inputSchema: schema, annotations: { readOnlyHint: false }, _meta: { [TERRAFORM_PAIR_EXTENSION]: terraformPairMetadata(r) } }] }; }
  async connect() {}
  getNegotiatedProtocolVersion() { return '2026-07-28'; }
  getServerCapabilities() { return { extensions: this.extensions }; }
  async listTools() { return this.catalog; }
}
const seed = privateSeed(Buffer.alloc(32, 2));
const descriptor = signedRecord('ctd', d, 'key-2', seed);
const config = { descriptor, descriptorDigest: recordDigest(strictJson(descriptor)), registryKeys: { 'key-2': publicBytes(seed).toString('base64url') }, gatewayUrl: d.gateway_audience, admissionUrl: 'https://control.test/admit', issuanceUrl: 'https://control.test/issue', delegationAudience: 'urn:agent', workloadId: 'spiffe://test/agent', tenant: 'test', toolName: 'terraform_apply', terraformPair: r };
const create = () => new AgentAdapter({ Client, StreamableHTTPClientTransport: class {}, config, store: { withLock() {} }, dpopKey: privateSeed(Buffer.alloc(32, 8)) });
const agent = create(); await agent.connect(); checks++;
{ const a = create(); a.client.extensions[TERRAFORM_PAIR_EXTENSION] = { ...TERRAFORM_PAIR_CAPABILITIES, target_atomic: true }; await assert.rejects(a.connect()); checks++; }
{ const a = create(); a.client.catalog.tools[0].inputSchema = {}; await assert.rejects(a.connect()); checks++; }
{ const a = create(); a.client.catalog.tools[0]._meta[TERRAFORM_PAIR_EXTENSION] = { ...terraformPairMetadata(r), manifest_digest: '2'.repeat(64) }; await assert.rejects(a.connect()); checks++; }
for (const mutate of [x => x.members.reverse(), x => x.members.pop(), x => x.members[1].target_uid = x.members[0].target_uid, x => x.members[1].id = 'other', x => x.resource.id = 'terraform:plan', x => x.resource.incarnation = 'uid']) { const bad = copy(r); mutate(bad); refuse(() => validateTerraformPairDescriptor(d, bad)); }
for (const mutate of [x => delete x.intent.pair, x => x.intent.pair.tool_succeeded = false, x => x.intent.pair.backend_progress = false, x => x.intent.pair.members.reverse(), x => x.intent.pair.members[1].state = 'original_observed', x => x.intent.pair.members[1].target_uid = 'other', x => x.intent.pair.members[1].observed_at = 9, x => x.intent.pair.members[1].observed_at = 1.5, x => x.intent.pair.members[1].observation_digest = null, x => x.intent.pair.members[1].extra = true, x => x.intent.observed_after_digest = '8'.repeat(64)]) { const bad = copy(result); mutate(bad.structuredContent.kedgeflow_terraform_report); refuse(() => validateTerraformPairResult(d, bad, { payload: g }, receipt, r)); }
for (const mutate of [x => x.resource.incarnation = 'other', x => x.fence = 2]) { const bad = copy(receipt); mutate(bad); refuse(() => validateTerraformPairResult(d, result, { payload: g }, bad, r)); }
{ const a = create(); delete a.client.extensions[TERRAFORM_PAIR_EXTENSION]; a.client.extensions['io.kedgeflow/terraform-apply'] = { profile: 'KF-TERRAFORM-GATEWAY-0.1-draft' }; await assert.rejects(a.connect({ queryOnly: true })); checks++; }
{ const bad = { ...config, terraform: r }; refuse(() => new AgentAdapter({ Client, StreamableHTTPClientTransport: class {}, config: bad, store: { withLock() {} }, dpopKey: privateSeed(Buffer.alloc(32, 8)) })); }
console.log(JSON.stringify({ status: 'PASS', checks, scope: 'Terraform pair exact registration, descriptor, arguments, grant, outcome and discovery; no target-atomic claim' }));
