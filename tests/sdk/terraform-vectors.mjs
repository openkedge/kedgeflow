import assert from 'node:assert/strict';
import { digest, privateSeed, publicBytes, recordDigest, signedRecord, strictJson } from '../../sdk/node/records.mjs';
import { AgentAdapter, STATUS_EXTENSION, STATUS_PROFILE } from '../../sdk/node/agent-adapter.mjs';
import { TERRAFORM_ACTION, TERRAFORM_PROFILE, TERRAFORM_RUNNER, TERRAFORM_EXTENSION, TERRAFORM_CAPABILITIES, TERRAFORM_ADAPTER, terraformSchema, terraformMetadata, validateTerraformDescriptor, validateTerraformArguments, validateTerraformGrant, validateTerraformResult } from '../../sdk/node/terraform.mjs';
let checks = 0;
const pass = f => { f(); checks++; };
const refuse = f => { assert.throws(f); checks++; };
const copy = x => structuredClone(x);
const r = { profile: TERRAFORM_PROFILE, manifestDigest: 'a'.repeat(64), effectDigest: 'b'.repeat(64), inspectionSha256: 'c'.repeat(64), resource: { id: 'terraform:plan', incarnation: 'target-uid' } };
const schema = terraformSchema(r);
const coverage = { coordinated_writers: ['protected-terraform-runner'], uncoordinated_writers: ['privileged-administrators', 'kubernetes-control-plane'] };
coverage.inventory_digest = digest('coverage-inventory', coverage);
const d = { action: TERRAFORM_ACTION, version: '1.0', gateway_audience: 'https://gateway.test/mcp', parameter_schema: schema, parameter_schema_digest: digest('parameter-schema', schema), rendering: { parameter_schema_digest: digest('parameter-schema', schema) }, adapter_contract: TERRAFORM_ADAPTER, concurrency: { coverage, predicate_descriptor: { id: 'plan', version: '1', language: 'kf-conjunction-v1', clauses: [{ kind: 'version_eq', resource: r.resource, expected_version: '1' }] } } };
const args = { node: r.resource.id, expected_version: 1, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest };
pass(() => validateTerraformDescriptor(d, r));
pass(() => validateTerraformArguments(d, args, r));
for (const key of ['profile', 'manifestDigest', 'effectDigest', 'inspectionSha256']) { const bad = copy(r); bad[key] = 'other'; refuse(() => validateTerraformDescriptor(d, bad)); }
refuse(() => validateTerraformDescriptor(d, undefined));
refuse(() => validateTerraformDescriptor({ ...d, action: 'other' }, r));
for (const mutate of [x => x.adapter_contract.level = 'Level_A', x => x.adapter_contract.guard_primitive = 'FencingToken', x => x.concurrency.coverage.uncoordinated_writers = [], x => x.parameter_schema.additionalProperties = true, x => x.parameter_schema_digest = 'd'.repeat(64), x => x.concurrency.predicate_descriptor.clauses[0].resource.incarnation = 'other']) { const bad = copy(d); mutate(bad); refuse(() => validateTerraformDescriptor(bad, r)); }
for (const key of ['node', 'expected_version', 'manifest_digest', 'effect_digest', 'command', 'credential', 'kf_fence']) { const bad = copy(args); bad[key] = key === 'expected_version' ? 2 : 'other'; refuse(() => validateTerraformArguments(d, bad, r)); }
const g = { action: { id: TERRAFORM_ACTION, version: '1.0' }, parameters_digest: digest('parameters', args), resources: [r.resource], adapter_contract: TERRAFORM_ADAPTER, completion_mode: 'dispatch_bound', parent_grant_digest: null, saga_budget: null, root_id: 'original-root', valid_from: 1, expires_at: 100 };
pass(() => validateTerraformGrant(d, g, args, r));
for (const mutate of [x => x.parent_grant_digest = 'd'.repeat(64), x => x.saga_budget = {}, x => x.parameters_digest = 'd'.repeat(64), x => x.resources[0].incarnation = 'other', x => x.action.version = '2']) { const bad = copy(g); mutate(bad); refuse(() => validateTerraformGrant(d, bad, args, r)); }
const receipt = { attempt_id: 'original-attempt', grant_digest: 'd'.repeat(64), resource: r.resource, fence: 1, status: 'committed' };
const report = { profile: TERRAFORM_RUNNER, status: 'committed', replayed: false, observed_postcondition: true, intent: { profile: TERRAFORM_RUNNER, manifest_digest: r.manifestDigest, effect_digest: r.effectDigest, grant_digest: receipt.grant_digest, root_id: g.root_id, attempt_id: receipt.attempt_id, state: 'applied', initiated_at: 10, backend_before_sha256: 'e'.repeat(64), backend_after_sha256: 'f'.repeat(64), observed_after_digest: '1'.repeat(64), last_error: null } };
const result = { structuredContent: { kedgeflow_terraform_report: report, kedgeflow_terraform_binding: terraformMetadata(r) } };
pass(() => validateTerraformResult(d, result, { payload: g }, receipt, r));
for (const mutate of [x => x.observed_postcondition = false, x => x.replayed = true, x => x.extra = true, x => x.intent.state = 'unknown', x => x.intent.attempt_id = 'other', x => x.intent.root_id = 'other', x => x.intent.effect_digest = '2'.repeat(64), x => x.intent.grant_digest = '2'.repeat(64), x => x.intent.manifest_digest = '2'.repeat(64), x => x.intent.last_error = 'unresolved', x => x.intent.backend_after_sha256 = x.intent.backend_before_sha256, x => x.intent.observed_after_digest = null, x => x.intent.initiated_at = 100]) { const bad = copy(result); mutate(bad.structuredContent.kedgeflow_terraform_report); refuse(() => validateTerraformResult(d, bad, { payload: g }, receipt, r)); }
{ const bad = copy(result); bad.structuredContent.kedgeflow_terraform_binding.target_atomic = true; refuse(() => validateTerraformResult(d, bad, { payload: g }, receipt, r)); }
class Client {
  constructor() { this.extensions = { 'io.kedgeflow/governed-mcp': { profile: 'KF-MCP-0.1' }, [STATUS_EXTENSION]: { profile: STATUS_PROFILE }, [TERRAFORM_EXTENSION]: TERRAFORM_CAPABILITIES }; this.catalog = { tools: [{ name: 'terraform_apply', inputSchema: schema, annotations: { readOnlyHint: false }, _meta: { [TERRAFORM_EXTENSION]: terraformMetadata(r) } }] }; }
  async connect() {}
  getNegotiatedProtocolVersion() { return '2026-07-28'; }
  getServerCapabilities() { return { extensions: this.extensions }; }
  async listTools() { return this.catalog; }
}
const seed = privateSeed(Buffer.alloc(32, 2));
const descriptor = signedRecord('ctd', d, 'key-2', seed);
const config = { descriptor, descriptorDigest: recordDigest(strictJson(descriptor)), registryKeys: { 'key-2': publicBytes(seed).toString('base64url') }, gatewayUrl: d.gateway_audience, admissionUrl: 'https://control.test/admit', issuanceUrl: 'https://control.test/issue', delegationAudience: 'urn:agent', workloadId: 'spiffe://test/agent', tenant: 'test', toolName: 'terraform_apply', terraform: r };
const create = () => new AgentAdapter({ Client, StreamableHTTPClientTransport: class {}, config, store: { withLock() {} }, dpopKey: privateSeed(Buffer.alloc(32, 8)) });
const agent = create(); await agent.connect(); checks++;
{ const a = create(); a.client.extensions[TERRAFORM_EXTENSION] = { ...TERRAFORM_CAPABILITIES, target_atomic: true }; await assert.rejects(a.connect()); checks++; }
{ const a = create(); a.client.catalog.tools[0].inputSchema = {}; await assert.rejects(a.connect()); checks++; }
{ const a = create(); a.client.catalog.tools[0]._meta[TERRAFORM_EXTENSION] = { ...terraformMetadata(r), manifest_digest: '2'.repeat(64) }; await assert.rejects(a.connect()); checks++; }
console.log(JSON.stringify({ status: 'PASS', checks, scope: 'Terraform exact registration, descriptor, arguments, grant, outcome and discovery; no target-atomic claim' }));
