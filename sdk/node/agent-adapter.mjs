import { randomUUID, sign, verify } from 'node:crypto';
import { canonical, digest, exact, hash, publicBytes, publicKey, recordDigest, same, signedRecord, strictJson, verifyRecord } from './records.mjs';
import { fixedHttps } from './transport.mjs';

export const STATUS_PROFILE = 'KF-EXECUTION-STATUS-0.1-draft';
export const STATUS_EXTENSION = 'io.kedgeflow/execution-status';
export const CAPABILITIES = { extensions: {
  'io.kedgeflow/governed-mcp': { profile: 'KF-MCP-0.1' },
  [STATUS_EXTENSION]: { profile: STATUS_PROFILE }
} };
const CONTROL_PROFILE = 'KF-LEAF-CONTROL-0.1-draft';
const controlFailures = ['invalid_record', 'unauthenticated', 'forbidden', 'unsupported_profile', 'stale_control', 'missing_evidence', 'admission_denied', 'issuance_conflict', 'authority_consumed', 'authority_unavailable', 'outcome_unknown'];
const states = ['unclaimed', 'claimed', 'dispatch_authorized', 'committed', 'not_dispatched', 'state_guard_violation', 'unknown'];
// The official SDK validates the wire resultType and removes it before passing
// the normalized extension result to this Standard Schema validator.
const statusSchema = { '~standard': { version: 1, vendor: 'kedgeflow', validate(value) {
  try {
    exact(value, ['profile', 'state', 'attempt_id', 'grant_digest']);
    if (value.profile !== STATUS_PROFILE || !states.includes(value.state) || !/^[a-f0-9]{64}$/.test(value.grant_digest) || (value.state === 'unclaimed' ? value.attempt_id !== null : typeof value.attempt_id !== 'string' || !value.attempt_id || value.attempt_id.length > 1024)) throw new Error('invalid retained status');
    return { value };
  } catch (e) { return { issues: [{ message: e.message }] }; }
} } };

export function validateRemediation(remediation, config, call, now) {
  exact(remediation, ['remediation_id', 'code', 'proposal_digest', 'action', 'parameters_digest', 'obligations', 'admission_endpoint', 'profile', 'grant_carriage', 'expires_at', 'retry_after_admission']);
  if (remediation.code !== 'NEEDS_EVIDENCE' || remediation.profile !== 'KF-JSON-0.2' || remediation.proposal_digest !== null || remediation.admission_endpoint !== config.admissionUrl || !same(remediation.action, config.action) || remediation.parameters_digest !== digest('parameters', call.arguments) || remediation.grant_carriage !== 'Mcp-KedgeFlow-Grant' || remediation.retry_after_admission !== true || !Number.isSafeInteger(remediation.expires_at) || now >= remediation.expires_at || remediation.expires_at > now + 60000 || !Array.isArray(remediation.obligations) || !remediation.obligations.length) throw new Error('untrusted or stale remediation');
  // Hints explain a refusal; the independently configured evidence source and
  // admission endpoint determine the actual obligations. No hint selects a URL.
}

export class AgentAdapter {
  constructor({ Client, StreamableHTTPClientTransport, config, fetch, tokenProvider, proposalKey, dpopKey, evidenceSource, store, now = Date.now }) {
    for (const url of [config.gatewayUrl, config.admissionUrl, config.issuanceUrl]) fixedHttps(url);
    if (config.admissionUrl === config.issuanceUrl || !config.delegationAudience || !config.workloadId || !config.tenant || !config.toolName || !store?.withLock) throw new Error('incomplete agent configuration');
    const descriptor = verifyRecord(config.descriptor, 'ctd', config.registryKeys);
    if (recordDigest(descriptor) !== config.descriptorDigest || descriptor.payload.gateway_audience !== config.gatewayUrl) throw new Error('descriptor pin mismatch');
    this.config = { ...config, action: { id: descriptor.payload.action, version: descriptor.payload.version, digest: config.descriptorDigest } };
    this.descriptor = descriptor; this.fetch = fetch; this.tokenProvider = tokenProvider;
    this.proposalKey = proposalKey; this.dpopKey = dpopKey; this.evidenceSource = evidenceSource; this.store = store; this.now = now;
    this.jwk = { kty: 'OKP', crv: 'Ed25519', x: publicBytes(dpopKey).toString('base64url') };
    this.jkt = hash(canonical(this.jwk)).toString('base64url');
    this.client = new Client({ name: 'kedgeflow-leaf-agent', version: '0.9.0-alpha.1' }, { versionNegotiation: { mode: { pin: '2026-07-28' } }, capabilities: CAPABILITIES });
    this.transport = new StreamableHTTPClientTransport(new URL(config.gatewayUrl), { fetch: this.gatewayFetch.bind(this) });
  }

  async token() {
    const token = this.executionToken ?? await this.tokenProvider();
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('access token framing');
    const h = strictJson(Buffer.from(parts[0], 'base64url').toString());
    const c = strictJson(Buffer.from(parts[1], 'base64url').toString());
    if (h.jwk !== undefined || h.alg !== 'EdDSA' || h.typ !== 'at+jwt' || !verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey(this.config.authorizationKey), Buffer.from(parts[2], 'base64url')) || c.iss !== this.config.subject.iss || c.sub !== this.config.subject.sub || c.aud !== this.config.delegationAudience || c.cnf?.jkt !== this.jkt || !Number.isSafeInteger(c.exp) || this.now() >= c.exp * 1000 || !Number.isSafeInteger(c.iat) || c.iat * 1000 > this.now() + 5000 || typeof c.scope !== 'string') throw new Error('access token binding or validity');
    const scopes = c.scope.trim().split(/\s+/);
    if (!scopes[0] || scopes.length > 128 || new Set(scopes).size !== scopes.length || c.exp * 1000 > Number.MAX_SAFE_INTEGER || c.iat < 0 || c.iat >= c.exp) throw new Error('access token scope/time');
    const delegation = { access_token_digest: hash(token).toString('hex'), dpop_jkt: this.jkt, authorization_server: c.iss, token_audience: c.aud, scopes, expires_at: c.exp * 1000 };
    return { token, delegation };
  }

  async headers(url, initial) {
    const { token } = await this.token();
    const h = { alg: 'EdDSA', typ: 'dpop+jwt', jwk: this.jwk };
    const c = { jti: randomUUID(), htm: 'POST', htu: url, iat: Math.floor(this.now() / 1000), ath: hash(token).toString('base64url') };
    const input = `${Buffer.from(JSON.stringify(h)).toString('base64url')}.${Buffer.from(JSON.stringify(c)).toString('base64url')}`;
    const proof = `${input}.${sign(null, Buffer.from(input), this.dpopKey).toString('base64url')}`;
    const headers = new Headers(initial); headers.set('Authorization', `DPoP ${token}`); headers.set('DPoP', proof);
    return headers;
  }

  async gatewayFetch(input, init = {}) {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url !== this.config.gatewayUrl) throw new Error('gateway routing mismatch');
    const headers = await this.headers(url, init.headers);
    if (headers.has('Mcp-KedgeFlow-Grant') || headers.has('Mcp-KedgeFlow-Grant-Ref')) throw new Error('caller-selected grant header');
    const request = typeof init.body === 'string' ? strictJson(init.body) : null;
    if (request?.method === 'tools/call' && this.activeGrant) {
      if (!same({ name: request.params.name, arguments: request.params.arguments }, this.activeCall)) throw new Error('changed active call');
      headers.set('Mcp-KedgeFlow-Grant', Buffer.from(this.activeGrant).toString('base64url'));
    }
    return this.fetch(input, { ...init, headers, redirect: 'error' });
  }

  async connect({ queryOnly = false } = {}) {
    await this.client.connect(this.transport);
    const extensions = this.client.getServerCapabilities()?.extensions;
    if (this.client.getNegotiatedProtocolVersion() !== '2026-07-28' || extensions?.['io.kedgeflow/governed-mcp']?.profile !== 'KF-MCP-0.1' || extensions?.[STATUS_EXTENSION]?.profile !== STATUS_PROFILE) throw new Error('required profiles unsupported');
    if (!queryOnly) {
      const catalog = await this.client.listTools();
      if (!catalog.tools.some(t => t.name === this.config.toolName && t.annotations?.readOnlyHint === false)) throw new Error('protected tool not advertised');
    }
  }
  async close() { await this.client.close(); }

  async control(url, body, operation) {
    const response = await this.fetch(url, { method: 'POST', headers: await this.headers(url, { 'Content-Type': 'application/json' }), body: canonical(body), redirect: 'error' });
    if (response.url !== url) throw new Error('control response routing mismatch');
    const value = strictJson(await response.text());
    if (value.profile !== CONTROL_PROFILE || value.request_id !== body.request_id) throw new Error('uncorrelated control response');
    if (!response.ok) {
      exact(value, ['profile', 'operation', 'request_id', 'code']);
      if (value.operation !== 'failure' || !controlFailures.includes(value.code)) throw new Error('unsupported control failure');
      const e = new Error('control operation refused'); e.state = value.code; throw e;
    }
    exact(value, operation === 'admitted' ? ['profile', 'operation', 'request_id', 'certificate'] : ['profile', 'operation', 'request_id', 'issuance_key', 'reused', 'grant']);
    if (value.operation !== operation) throw new Error('unexpected control operation');
    return value;
  }

  async status(qid) {
    const record = await this.store.get(qid);
    if (!record?.grant) return { state: 'unavailable', attempt_id: null };
    const verified = verifyRecord(record.grant, 'grant', this.config.issuerKeys);
    const proposal = verifyRecord(record.proposal, 'proposal', this.config.proposalKeys);
    if (proposal.payload.qid !== qid || verified.payload.proposal_digest !== recordDigest(proposal) || !same(verified.payload.subject, this.config.subject) || verified.payload.workload_id !== this.config.workloadId || verified.payload.dpop_jkt !== this.jkt) throw new Error('retained operation correlation mismatch');
    const status = await this.client.request({ method: 'kedgeflow/status', params: { name: this.config.toolName, arguments: { profile: STATUS_PROFILE, grant: record.grant } } }, statusSchema);
    if (status.grant_digest !== recordDigest(verified)) throw new Error('status grant mismatch');
    return status;
  }

  async execute({ qid, arguments: args }) {
    if (this.busy) throw new Error('one active operation per adapter');
    this.busy = true;
    try {
      return await this.store.withLock(qid, async () => {
        const call = strictJson(canonical({ name: this.config.toolName, arguments: args }));
        const fingerprint = digest('agent-operation', { qid, call, action: this.config.action, subject: this.config.subject, workload_id: this.config.workloadId, dpop_jkt: this.jkt });
        let retained = await this.store.get(qid);
        if (retained && retained.fingerprint !== fingerprint) throw new Error('operation identity binding conflict');
        if (retained?.grant) return this.status(qid);
        const { token, delegation } = await this.token(); this.executionToken = token;
        try {
          let remediation;
          try { await this.client.callTool(call); throw new Error('ungranted call unexpectedly executed'); }
          catch (e) { if (e.code !== -32001) throw e; remediation = e.data; }
          validateRemediation(remediation, this.config, call, this.now());
          if (!retained) {
            const context = { qid, call, delegation, subject: this.config.subject, workloadId: this.config.workloadId, descriptor: this.descriptor.payload, action: this.config.action, now: this.now() };
            const proposal = strictJson(canonical(await this.evidenceSource.prepareProposal(context)));
            if (proposal.qid !== qid || proposal.tenant !== this.config.tenant || !same(proposal.parameters, args) || !same(proposal.action, this.config.action) || !same(proposal.subject, this.config.subject) || proposal.workload_id !== this.config.workloadId || !same(proposal.delegation, delegation) || proposal.created_at !== context.now || proposal.workflow !== null || proposal.requested_completion !== 'dispatch_bound') throw new Error('proposal source changed binding');
            retained = { fingerprint, proposal: signedRecord('proposal', proposal, this.config.proposalKeyId, this.proposalKey) };
            await this.store.put(qid, retained);
          }
          const proposal = verifyRecord(retained.proposal, 'proposal', this.config.proposalKeys);
          if (!same(proposal.payload.delegation, delegation)) throw new Error('execution delegation changed; resolve status or start a new operation');
          if (!retained.packet) {
            const evidence = await this.evidenceSource.collect({ proposal: retained.proposal, proposal_digest: recordDigest(proposal) });
            const manifest = verifyRecord(evidence.manifest, 'manifest', this.config.manifestKeys);
            if (manifest.payload.proposal_digest !== recordDigest(proposal) || !Array.isArray(evidence.witnesses) || evidence.witnesses.length > 64) throw new Error('evidence proposal mismatch');
            for (const raw of evidence.witnesses) {
              const w = verifyRecord(raw, 'evidence', this.config.evidenceKeys);
              if (w.payload.proposal_digest !== recordDigest(proposal) || this.now() >= w.payload.expires_at) throw new Error('stale or rebound evidence');
            }
            retained.packet = { descriptor: this.config.descriptor, manifest: evidence.manifest, witnesses: evidence.witnesses };
            await this.store.put(qid, retained);
          }
          const admitted = await this.control(this.config.admissionUrl, { profile: CONTROL_PROFILE, operation: 'admit', request_id: randomUUID(), proposal: retained.proposal, ...retained.packet }, 'admitted');
          const certificate = verifyRecord(admitted.certificate, 'certificate', this.config.admissionKeys);
          const c = certificate.payload;
          if (c.proposal_digest !== recordDigest(proposal) || c.descriptor_digest !== this.config.descriptorDigest || c.evidence_manifest_digest !== recordDigest(verifyRecord(retained.packet.manifest, 'manifest', this.config.manifestKeys)) || c.delegation_digest !== digest('delegation', delegation) || !same(c.subject, this.config.subject) || c.workload_id !== this.config.workloadId || this.now() >= c.expires_at) throw new Error('certificate binding mismatch');
          const issued = await this.control(this.config.issuanceUrl, { profile: CONTROL_PROFILE, operation: 'issue', request_id: randomUUID(), proposal: retained.proposal, certificate: admitted.certificate }, 'issued');
          const grant = verifyRecord(issued.grant, 'grant', this.config.issuerKeys);
          const g = grant.payload;
          if (g.proposal_digest !== c.proposal_digest || g.certificate_digest !== recordDigest(certificate) || g.delegation_digest !== c.delegation_digest || g.parameters_digest !== digest('parameters', args) || !same(g.subject, this.config.subject) || g.workload_id !== this.config.workloadId || g.dpop_jkt !== this.jkt || !same(g.action, this.config.action) || g.audience !== this.config.gatewayUrl || this.now() < g.valid_from || this.now() >= g.expires_at || g.expires_at > c.expires_at) throw new Error('grant binding mismatch');
          const limit = this.client.getServerCapabilities().extensions['io.kedgeflow/governed-mcp'].max_inline_grant_header_bytes;
          if (!Number.isSafeInteger(limit) || Buffer.from(issued.grant).toString('base64url').length > limit) throw new Error('inline grant exceeds negotiated bound');
          retained.grant = issued.grant; retained.certificate = admitted.certificate;
          await this.store.put(qid, retained); // Must be durable before tools/call.
          this.activeGrant = issued.grant; this.activeCall = call;
          try {
            const result = await this.client.callTool(call);
            const receipt = result.structuredContent?.kedgeflow_terminal_receipt;
            if (result.isError || receipt?.grant_digest !== recordDigest(grant) || typeof receipt.attempt_id !== 'string' || !receipt.attempt_id || receipt.attempt_id.length > 1024 || !same(receipt.resource, g.resources[0]) || receipt.fence !== g.fence || !['committed', 'state_guard_violation'].includes(receipt.status)) throw new Error('uncorrelated terminal receipt');
            return { state: receipt.status, attempt_id: receipt.attempt_id, grant_digest: receipt.grant_digest, result };
          } catch {
            // Possible sends resolve by query; there is no automatic tools/call
            // retry, grant renewal, compensation or consumed allowance refund.
            this.activeGrant = null; this.executionToken = null;
            try { return await this.status(qid); } catch { return { state: 'unavailable', attempt_id: null, grant_digest: recordDigest(grant) }; }
          }
        } catch (e) {
          return { state: e.state ?? 'unavailable', attempt_id: null };
        } finally { this.executionToken = null; this.activeGrant = null; this.activeCall = null; }
      });
    } finally { this.busy = false; }
  }
}
