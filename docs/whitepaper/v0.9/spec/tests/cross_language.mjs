// Independent Node.js checks for Python-produced integer-profile JCS/signatures.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createPublicKey, verify } from 'node:crypto';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'examples');
const read = name => JSON.parse(readFileSync(join(root, name), 'utf8'));
const keys = read('public-test-keys.json');
const vectors = read('fixture-digests.json');
const domain = kind => Buffer.from(`KedgeFlow/KF-JSON-0.2${kind ? '/' + kind : ''}\0`, 'utf8');

function string(value) {
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point >= 0xd800 && point <= 0xdfff) throw Error('invalid Unicode surrogate');
  }
  return JSON.stringify(value);
}

function jcs(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return string(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw Error('outside integer-profile domain');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (typeof value === 'object') return '{' + Object.keys(value).sort().map(key => string(key) + ':' + jcs(value[key])).join(',') + '}';
  throw Error('unsupported JSON value');
}

const sha = (kind, value) => createHash('sha256').update(domain(kind)).update(jcs(value)).digest('hex');
let count = 0;
for (const [kind, expectedDigest] of Object.entries(vectors)) {
  const envelope = read(kind + '.json');
  const { signature, ...unsigned } = envelope;
  const key = keys[envelope.key_id];
  const publicKey = createPublicKey({ key: { kty: key.kty, crv: key.crv, x: key.x }, format: 'jwk' });
  if (!verify(null, Buffer.concat([domain(), Buffer.from(jcs(unsigned))]), publicKey, Buffer.from(signature, 'base64url'))) throw Error(`signature mismatch: ${kind}`);
  const digest = kind === 'proposal' ? sha('proposal', {schema: envelope.schema, payload: envelope.payload}) : sha(kind, envelope);
  if (digest !== expectedDigest) throw Error(`record digest mismatch: ${kind}`);
  count++;
}
const proposal = read('proposal.json'), certificate = read('certificate.json'), grant = read('grant.json');
if (sha('parameters', proposal.payload.parameters) !== grant.payload.parameters_digest) throw Error('parameter digest mismatch');
if (sha('delegation', proposal.payload.delegation) !== grant.payload.delegation_digest) throw Error('delegation digest mismatch');
if (sha('constraints', certificate.payload.constraints) !== grant.payload.constraint_digest) throw Error('constraint digest mismatch');
const approval = read('hitl_witness.json').payload;
if (createHash('sha256').update(jcs(approval.approval)).digest('hex') !== approval.challenge_digest) throw Error('approval challenge mismatch');
if (jcs({'2':1,'10':2}) !== '{"10":2,"2":1}') throw Error('numeric property sort mismatch');
if (jcs({'\ue000':1,'😀':2}) !== '{"😀":2,"\ue000":1}') throw Error('UTF16 sort mismatch');
console.log(`PASS: Node.js independently verified ${count} Ed25519 envelopes, JCS record/parameter/delegation/constraint hashes, approval challenge, numeric-key and UTF16 ordering.`);
