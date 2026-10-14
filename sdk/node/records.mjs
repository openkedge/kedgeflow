import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

export function canonical(value) {
  const string = s => {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const next = s.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('unpaired surrogate');
      } else if (c >= 0xdc00 && c <= 0xdfff) throw new Error('unpaired surrogate');
    }
    return JSON.stringify(s);
  };
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return string(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    return `{${Object.keys(value).sort().map(k => `${string(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  throw new Error('unsupported canonical value');
}

// JSON.parse alone discards duplicate fields and rounds unsafe integers. This
// bounded parser preserves the same closed lexical subset as the Rust server.
export function strictJson(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > 1 << 20) throw new Error('JSON bound');
  let i = 0;
  const ws = () => { while (/[\x20\x09\x0a\x0d]/.test(raw[i] ?? '\x00')) i++; };
  const str = () => {
    const start = i++;
    while (i < raw.length) {
      if (raw[i] === '\\') { i += 2; continue; }
      if (raw[i++] === '"') return JSON.parse(raw.slice(start, i));
    }
    throw new Error('unterminated string');
  };
  const value = (depth = 0) => {
    if (depth > 80) throw new Error('JSON depth');
    ws();
    if (raw[i] === '"') return str();
    if (raw[i] === '{') {
      i++; ws(); const o = Object.create(null);
      if (raw[i] === '}') { i++; return o; }
      for (;;) {
        ws(); if (raw[i] !== '"') throw new Error('object key');
        const k = str();
        if (Object.hasOwn(o, k)) throw new Error('duplicate key');
        ws(); if (raw[i++] !== ':') throw new Error('object separator');
        o[k] = value(depth + 1); ws();
        const end = raw[i++]; if (end === '}') return o;
        if (end !== ',') throw new Error('object delimiter');
      }
    }
    if (raw[i] === '[') {
      i++; ws(); const a = [];
      if (raw[i] === ']') { i++; return a; }
      for (;;) {
        a.push(value(depth + 1)); ws();
        const end = raw[i++]; if (end === ']') return a;
        if (end !== ',') throw new Error('array delimiter');
      }
    }
    for (const [token, v] of [['true', true], ['false', false], ['null', null]]) {
      if (raw.slice(i, i + token.length) === token) { i += token.length; return v; }
    }
    const token = /^-?(?:0|[1-9][0-9]*)/.exec(raw.slice(i))?.[0];
    if (!token) throw new Error('JSON value');
    i += token.length;
    if (/[.eE]/.test(raw[i] ?? '\x00')) throw new Error('non-integer token');
    const n = Number(token); if (!Number.isSafeInteger(n)) throw new Error('unsafe integer');
    return n;
  };
  const result = value(); ws(); if (i !== raw.length) throw new Error('trailing JSON');
  canonical(result); return result;
}

export const hash = bytes => createHash('sha256').update(bytes).digest();
export const digest = (kind, value) => hash(`KedgeFlow/KF-JSON-0.2/${kind}\0${canonical(value)}`).toString('hex');
export const recordDigest = e => digest(e.kind, e.kind === 'proposal' ? { schema: e.schema, payload: e.payload } : e);
export const same = (a, b) => canonical(a) === canonical(b);
export function exact(value, keys) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).length !== keys.length || !keys.every(k => Object.hasOwn(value, k))) throw new Error('closed fields mismatch');
}
const definitions = { lease: 'AdmissionLease', proposal: 'Proposal', ctd: 'ConsequentialToolDescriptor', manifest: 'WitnessManifest', evidence: 'Evidence', certificate: 'AdmissionCertificate', grant: 'ExecutionGrant' };
const signatureInput = e => {
  const { signature, ...unsigned } = e;
  return Buffer.from(`KedgeFlow/KF-JSON-0.2\0${canonical(unsigned)}`);
};
export function privateSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new Error('Ed25519 seed length');
  return createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
}
export function publicBytes(key) {
  return createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
}
export function publicKey(raw) {
  const bytes = Buffer.from(raw, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== raw) throw new Error('public key encoding');
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes]), format: 'der', type: 'spki' });
}
export function signedRecord(kind, payload, keyId, key) {
  if (!definitions[kind]) throw new Error('unsupported signing kind');
  const e = { profile: 'KF-JSON-0.2', kind, schema: `https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/${definitions[kind]}`, key_id: keyId, payload };
  e.signature = sign(null, signatureInput(e), key).toString('base64url');
  return canonical(e);
}
export function verifyRecord(raw, kind, keys) {
  const e = strictJson(raw);
  exact(e, ['profile', 'kind', 'schema', 'key_id', 'payload', 'signature']);
  const sig = Buffer.from(e.signature, 'base64url');
  if (!definitions[kind] || e.kind !== kind || e.profile !== 'KF-JSON-0.2' || e.schema !== `https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/${definitions[kind]}` || !keys[e.key_id] || sig.length !== 64 || sig.toString('base64url') !== e.signature || !verify(null, signatureInput(e), publicKey(keys[e.key_id]), sig)) throw new Error('untrusted record');
  return e;
}
