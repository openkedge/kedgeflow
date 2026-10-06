import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

// The Rust fixture supplies loopback endpoint and one issuer-signed grant. This
// adapter uses documented SDK options; SDK request/result code is unmodified.
const fixture = JSON.parse(await readFile(process.argv[2], 'utf8'));
let activeGrant;
const wire = [];
const grantFetch = async (input, init = {}) => {
  const headers = new Headers(init.headers);
  let message;
  if (typeof init.body === 'string') message = JSON.parse(init.body);
  if (message?.method === 'tools/call' && activeGrant) {
    headers.set('Mcp-KedgeFlow-Grant', activeGrant);
  }
  if (message?.method) wire.push({
    method: message.method,
    protocolVersion: message.params?._meta?.['io.modelcontextprotocol/protocolVersion'],
    negotiatedKedgeFlow: message.params?._meta?.['io.modelcontextprotocol/clientCapabilities']?.extensions?.['io.kedgeflow/governed-mcp']?.profile === 'KF-MCP-0.1',
    grantPresent: headers.has('Mcp-KedgeFlow-Grant')
  });
  return fetch(input, { ...init, headers });
};
const client = new Client({ name: 'kedgeflow-sdk-conformance', version: '0.9.0' }, {
  versionNegotiation: { mode: { pin: '2026-07-28' } },
  capabilities: { extensions: { 'io.kedgeflow/governed-mcp': { profile: 'KF-MCP-0.1' } } }
});
const transport = new StreamableHTTPClientTransport(new URL(fixture.endpoint), {
  fetch: grantFetch,
  requestInit: { headers: { Authorization: 'DPoP synthetic-sdk-test-token' } }
});
try {
  await client.connect(transport);
  assert.equal(client.getProtocolEra(), 'modern');
  const catalog = await client.listTools();
  assert(catalog.tools.some(tool => tool.name === 'node_drain'));
  const call = { name: 'node_drain', arguments: { node: 'node-a', expected_version: 1 } };
  let remediation;
  try { await client.callTool(call); assert.fail('missing grant executed'); }
  catch (error) {
    assert.equal(error.code, -32001);
    assert.match(error.message, /NEEDS_EVIDENCE/);
    assert.equal(error.data.code, 'NEEDS_EVIDENCE');
    assert.equal(error.data.profile, 'KF-JSON-0.2');
    assert.equal(error.data.proposal_digest, null);
    assert.equal(error.data.grant_carriage, 'Mcp-KedgeFlow-Grant');
    assert.match(error.data.parameters_digest, /^[0-9a-f]{64}$/);
    assert(error.data.obligations.length >= 1);
    remediation = { code: error.code, message: 'NEEDS_EVIDENCE', obligations: error.data.obligations.length };
  }
  // A production Agent Adapter would obtain evidence/admission/grant here. This
  // focused SDK test uses an already issued, cryptographically verified fixture.
  activeGrant = fixture.grant;
  const result = await client.callTool(call);
  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.drained, true);
  const receipt = result.structuredContent.kedgeflow_terminal_receipt;
  assert.equal(receipt.status, 'committed');
  assert.equal(receipt.grant_digest, fixture.grant_digest);
  assert(receipt.attempt_id);
  try { await client.callTool(call); assert.fail('grant replay executed'); }
  catch (error) {
    assert.equal(error.code, -32007);
    assert.match(error.message, /NONCE_CONSUMED/);
  }
  assert.equal(wire.filter(row => row.method === 'tools/call').length, 3);
  assert(wire.every(row => row.protocolVersion === '2026-07-28'));
  assert(wire.filter(row => row.method === 'tools/call').every(row => row.negotiatedKedgeFlow));
  console.log(JSON.stringify({
    status: 'PASS', sdk: '@modelcontextprotocol/client', version: '2.3.0', node: process.version,
    protocol: '2026-07-28', era: client.getProtocolEra(),
    remediation, admittedFixtureRetry: 'terminal receipt verified', replay: 'NONCE_CONSUMED',
    adapter: 'documented Client options plus fetch header injection; SDK unmodified',
    identityScope: 'synthetic AuthFunc over loopback; cryptographic production authentication tested separately',
    wire
  }, null, 2));
} finally {
  await client.close();
}
