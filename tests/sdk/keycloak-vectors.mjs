import assert from 'node:assert/strict';
import { sign } from 'node:crypto';
import { AgentAdapter } from '../../sdk/node/agent-adapter.mjs';
import { KEYCLOAK_PROFILE, identityProfile } from '../../sdk/node/identity-profile.mjs';
import { privateSeed, publicBytes } from '../../sdk/node/records.mjs';

for (const value of [null, {}, { profile: 'unknown', clientId: 'x' }, { profile: KEYCLOAK_PROFILE, clientId: '' }, { profile: KEYCLOAK_PROFILE, clientId: 'x', extra: true }]) assert.throws(() => identityProfile(value));
const issuer = privateSeed(Buffer.alloc(32, 7));
const adapter = Object.create(AgentAdapter.prototype);
adapter.config = { subject: { iss: 'https://keycloak.test/realms/pilot', sub: 'subject' }, delegationAudience: 'urn:kedgeflow:delegated-admission', authorizationKey: publicBytes(issuer).toString('base64url') };
adapter.jkt = 'confirmation';
adapter.now = () => 1800000000000;
const header = { alg: 'EdDSA', typ: 'JWT', kid: 'keycloak-key' };
const claims = { iss: adapter.config.subject.iss, sub: 'subject', aud: adapter.config.delegationAudience, exp: 1800000060, iat: 1800000000, scope: 'kf.admit capacity.reserve', cnf: { jkt: adapter.jkt, 'kc-jkt-type': 'DPoP' }, typ: 'DPoP', azp: 'kf-pilot-agent', jti: 'original' };
function token(h, c) {
  const raw = `${Buffer.from(JSON.stringify(h)).toString('base64url')}.${Buffer.from(JSON.stringify(c)).toString('base64url')}`;
  return `${raw}.${sign(null, Buffer.from(raw), issuer).toString('base64url')}`;
}
adapter.tokenProvider = async () => token(header, claims);
await assert.rejects(adapter.token(), /access token binding/);
adapter.identityProfile = identityProfile({ profile: KEYCLOAK_PROFILE, clientId: 'kf-pilot-agent' });
const result = await adapter.token();
assert.deepEqual(result.delegation.scopes, ['kf.admit', 'capacity.reserve']);
assert.equal(result.token, token(header, claims));
for (const change of [{ azp: 'other' }, { typ: 'Bearer' }, { jti: '' }, { jti: 'é'.repeat(257) }, { extra: true }, { aud: [claims.aud] }, { cnf: { jkt: adapter.jkt, 'kc-jkt-type': 'refresh' } }]) {
  adapter.tokenProvider = async () => token(header, { ...claims, ...change });
  await assert.rejects(adapter.token());
}
for (const change of [{ extra: true }, { jwk: null }, { kid: null }, { kid: '' }, { kid: 'é'.repeat(129) }]) {
  adapter.tokenProvider = async () => token({ ...header, ...change }, claims);
  await assert.rejects(adapter.token());
}
console.log('Keycloak SDK PASS: explicit profile, original raw token/delegation, signed semantic negatives and no legacy fallback');
