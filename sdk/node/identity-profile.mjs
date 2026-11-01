import { exact } from './records.mjs';

export const KEYCLOAK_PROFILE = 'KF-KEYCLOAK-SPIRE-0.1-pilot';

export function identityProfile(value) {
  if (value === undefined) return null;
  exact(value, ['profile', 'clientId']);
  if (value.profile !== KEYCLOAK_PROFILE || typeof value.clientId !== 'string' || !value.clientId || value.clientId.length > 256 || /[^\x21-\x7e]/.test(value.clientId)) throw new Error('unsupported configured identity profile');
  return Object.freeze({ profile: value.profile, clientId: value.clientId });
}

export function validateKeycloakToken(header, claims, selection) {
  exact(header, ['alg', 'typ', 'kid']);
  exact(claims, ['iss', 'sub', 'aud', 'exp', 'iat', 'scope', 'cnf', 'typ', 'azp', 'jti']);
  exact(claims.cnf, ['jkt', 'kc-jkt-type']);
  if (header.alg !== 'EdDSA' || header.typ !== 'JWT' || typeof header.kid !== 'string' || !header.kid || Buffer.byteLength(header.kid) > 256 || typeof claims.aud !== 'string' || claims.typ !== 'DPoP' || claims.cnf['kc-jkt-type'] !== 'DPoP' || claims.azp !== selection.clientId || typeof claims.jti !== 'string' || !claims.jti || Buffer.byteLength(claims.jti) > 512) throw new Error('Keycloak token profile/client mismatch');
}
