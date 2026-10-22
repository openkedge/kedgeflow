// Protected host orchestration. The local collector never imports target
// credentials from an owner intent, and each leaf still uses AgentAdapter.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, open } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { AgentAdapter } from './agent-adapter.mjs';
import { canonical, digest, exact, same, strictJson } from './records.mjs';
export const SAGA_PROFILE = 'KF-FAMILY-SAGA-0.1-draft';
const reference = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const actions = ['observe', 'quiesce', 'prepare-compensation'];
const executeFile = promisify(execFile);
const copy = v => strictJson(canonical(v));

export class LocalSagaClient {
  constructor({ executable, config, ownerKeyId, ownerKey }) {
    if (![executable, config, ownerKey].every(isAbsolute) || typeof ownerKeyId !== 'string' || !ownerKeyId) throw new Error('protected absolute saga paths required');
    this.executable = executable; this.config = config; this.ownerKeyId = ownerKeyId; this.ownerKey = ownerKey;
  }
  async invoke(args) {
    const { stdout } = await executeFile(this.executable, ['--config', this.config, ...args], { encoding: 'utf8', maxBuffer: 1 << 20 });
    return strictJson(stdout);
  }
  status() { return this.invoke(['status']); }
  stage({ operationKey, action, path }) {
    if (!reference(operationKey) || !actions.includes(action) || !isAbsolute(path)) throw new Error('fixed owner operation/action/path required');
    return this.invoke(['stage', '--action', action, '--operation-key', operationKey, '--owner-key-id', this.ownerKeyId, '--owner-key', this.ownerKey, '--out', path]);
  }
  lookup(path) { return this.invoke(['lookup', '--prepared', path]); }
  apply(path) { return this.invoke(['apply', '--prepared', path]); }
}

export class FamilySagaRunner {
  #registration; #members; #local; #store; #directory; #digest;
  constructor({ registration, members, local, store, directory }) {
    if (registration?.profile !== SAGA_PROFILE || registration.composition?.profile !== SAGA_PROFILE ||
        !Array.isArray(registration.children) || !Array.isArray(registration.composition.nodes) ||
        registration.composition.nodes.length < 1 || registration.composition.nodes.length > 8 ||
        typeof local?.status !== 'function' || typeof local?.lookup !== 'function' || typeof local?.apply !== 'function' ||
        typeof local?.stage !== 'function' || !store?.withLock || !isAbsolute(directory)) throw new Error('protected complete saga configuration required');
    this.#registration = copy(registration); this.#digest = digest('family-registration', registration);
    this.#local = local; this.#store = store; this.#directory = directory; this.#members = new Map();
    if (!members || Object.keys(members).length !== registration.children.length || registration.children.length !== registration.composition.nodes.length) throw new Error('exact protected member catalog required');
    const operations = new Set();
    for (const n of this.#registration.composition.nodes) {
      const child = this.#registration.children.find(c => c.id === n.child_id);
      const member = members[n.child_id];
      if (!child || !member || this.#members.has(n.child_id)) throw new Error('duplicate or missing protected saga child');
      exact(member, child.inverse ? ['forward', 'inverse'] : ['forward']);
      const lanes = new Map();
      for (const lane of child.inverse ? ['forward', 'inverse'] : ['forward']) {
        const m = member[lane]; exact(m, ['adapter', 'qid', 'arguments']);
        if (!(m.adapter instanceof AgentAdapter) || typeof m.qid !== 'string' || !m.qid || m.qid.length > 1024) throw new Error('fixed native AgentAdapter/qid required');
        const c = m.adapter.config;
        const scope = lane === 'forward' ? child.reservation.scope : child.inverse.inverse_scope;
        const op = digest('issuance-key', { tenant: c.tenant, subject: c.subject, workload_id: c.workloadId, qid: m.qid });
        const expected = lane === 'forward' ? n.operation_key : child.inverse.inverse_operation_key;
        if (!reference(expected) || op !== expected || operations.has(op) || c.gatewayUrl !== scope.audience || !same(c.action, scope.action)) throw new Error('native operation/action/audience differs from protected catalog');
        m.adapter.operation(m.qid, m.arguments);
        operations.add(op);
        lanes.set(lane, { adapter: m.adapter, config: copy(c), qid: m.qid, arguments: copy(m.arguments), operation: op });
      }
      this.#members.set(n.child_id, lanes);
    }
  }
  #binding(child, lane) {
    const m = this.#members.get(child)?.get(lane);
    if (!m || !same(m.adapter.config, m.config)) throw new Error('protected native binding changed');
    m.adapter.operation(m.qid, m.arguments);
    return m;
  }
  async #state() {
    const s = await this.#local.status();
    if (s.profile !== SAGA_PROFILE || s.registration_digest !== this.#digest || !reference(s.head) ||
        !['forward', 'quiescing', 'compensating'].includes(s.phase)) throw new Error('uncorrelated saga state');
    return s;
  }
  // Execution never chooses another qid, refreshes an ambiguous grant or
  // restores an allowance. The server's original CAS remains authoritative.
  async execute(child, lane = 'forward') {
    const m = this.#binding(child, lane);
    const key = `family-saga-native:${this.#digest}:${m.operation}`;
    return this.#store.withLock(`family-saga:${this.#digest}`, async () => {
      const binding = digest('family-saga-native-call', { child, lane, qid: m.qid, arguments: m.arguments, operation: m.operation });
      const old = await this.#store.get(key);
      if (old) {
        if (old.binding !== binding || old.phase !== 'authority_started') throw new Error('retained native saga identity differs');
        return m.adapter.status(m.qid);
      }
      const s = await this.#state();
      const nodes = this.#registration.composition.nodes;
      if (Object.keys(s.members).length !== nodes.length || nodes.some(n => !s.members[n.child_id])) throw new Error('complete initial saga observation required');
      const current = s.members[child];
      if (lane === 'forward') {
        const n = nodes.find(n => n.child_id === child);
        if (s.phase !== 'forward' || n.depends_on.some(p => s.members[p].forward !== 'committed') || !['unissued', 'unclaimed'].includes(current.forward)) throw new Error('forward dependency or original effect blocks execution');
      } else {
        const descendants = new Set([child]);
        for (let i = 0; i < nodes.length; i++) for (const n of nodes) if (n.depends_on.some(p => descendants.has(p))) descendants.add(n.child_id);
        descendants.delete(child);
        if (s.phase !== 'compensating' || s.in_flight !== null || current.forward !== 'committed' || current.inverse !== 'absent' ||
            Object.values(s.members).some(m => m.forward === 'unknown') ||
            [...descendants].some(c => s.members[c].forward === 'committed' && s.members[c].inverse !== 'committed')) throw new Error('original inverse order, unresolved effect or in-flight claim blocks execution');
      }
      await this.#store.put(key, { binding, phase: 'authority_started' });
      // This record is durable before the first admission request, including
      // failures before AgentAdapter could retain its own proposal.
      return m.adapter.execute({ qid: m.qid, arguments: copy(m.arguments) });
    });
  }
  queryOriginal(child, lane = 'forward') { const m = this.#binding(child, lane); return m.adapter.status(m.qid); }
  #ownerPath(operationKey) {
    if (!reference(operationKey)) throw new Error('fixed owner operation key required');
    return join(this.#directory, `${this.#digest}-${operationKey}.json`);
  }
  async #original(path, operationKey, action) {
    let file;
    try { file = await open(path, 'r'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.size > ((512 + 32) << 10)) throw new Error('prepared owner file exceeds bound');
      const p = strictJson(await file.readFile('utf8'));
      if (p.intent?.profile !== SAGA_PROFILE || p.intent.payload.family_digest !== this.#digest || p.intent.payload.operation_key !== operationKey ||
          (action && p.intent.payload.action !== action.replaceAll('-', '_'))) throw new Error('retained owner command differs');
      return p;
    } finally { await file.close(); }
  }
  async owner({ operationKey, action }) {
    if (!actions.includes(action)) throw new Error('explicit owner action required');
    const path = this.#ownerPath(operationKey);
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    return this.#store.withLock(`family-saga:${this.#digest}`, async () => {
      if (await this.#original(path, operationKey, action)) return this.#local.lookup(path);
      await this.#state();
      await this.#local.stage({ operationKey, action, path });
      if (!await this.#original(path, operationKey, action)) throw new Error('durable prepared command absent');
      // No authenticated native network call between local capture and apply:
      // even shared DPoP replay retention would invalidate the capture epoch.
      try { return await this.#local.apply(path); }
      catch { return this.#local.lookup(path); }
    });
  }
  // Explicit retry replays the same signed bytes. It never recollects a proof,
  // changes an operation key, extends a deadline or re-signs an expired intent.
  async replayOwner(operationKey) {
    const path = this.#ownerPath(operationKey);
    return this.#store.withLock(`family-saga:${this.#digest}`, async () => {
      if (!await this.#original(path, operationKey)) throw new Error('original prepared command required');
      return this.#local.apply(path);
    });
  }
}
