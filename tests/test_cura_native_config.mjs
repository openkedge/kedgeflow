import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { buildConfigs as render } from '../scripts/cura-native-config.mjs';
import { publicBytes } from '../sdk/node/records.mjs';

const directory=new URL('../results/verification/sql-pilot-aws-evidence-2026-11-22/',import.meta.url);
const registration=JSON.parse(await readFile(new URL('registration.json',directory),'utf8'));
const operator=JSON.parse(await readFile(new URL('technical-operator.json',directory),'utf8'));
const purposes=['admission','issuer','target-token','gateway-ack','receipt',
  'publish-policy','register-descriptor','install','revoke','identity-refresh'];
const stopUTC='2026-11-23T08:00:00Z';
const fixtureNow=Date.parse(stopUTC)-3600000;
const buildConfigs=i=>render(i,stopUTC,fixtureNow);
function input() {
  return {registration:structuredClone(registration),operator:structuredClone(operator),
    purposeKeys:Object.fromEntries(purposes.map(purpose=>[purpose,{
      key_id:`urn:kf:cura:${purpose}:v1`,
      public_key_base64:publicBytes(generateKeyPairSync('ed25519').privateKey).toString('base64')} ])),
    nativeRegistration:null};
}
function withNativeFixture(i) {
  const {governance:g}=buildConfigs(i).configurations;
  // Disposable public renderer fixture; never an enterprise acceptance record.
  i.nativeRegistration=structuredClone({tenant:'cura-pilot',scope:g.scope,policy:i.registration.contract.policy,
    obligation_manifest_digest:i.registration.obligationManifestDigest,ownership_epoch:1,
    acknowledger:g.acknowledger,trust_digest:'a'.repeat(64),
    issuer_keys:{[i.purposeKeys.issuer.key_id]:Buffer.from(i.purposeKeys.issuer.public_key_base64,'base64').toString('hex')}});
  return i;
}

test('split control configuration gives each signer only its own private path',()=>{
  const c=buildConfigs(input()).configurations;
  assert.equal(c.admission.runtime_role,'admission');
  assert.equal(c.issuer.runtime_role,'issuer');
  assert.equal(c.admission.status_url,'https://services.cura.kedgeflow.internal:9443/status');
  assert.equal(c.issuer.status_url,'https://services.cura.kedgeflow.internal:9448/status');
  assert.equal(c.admission.issuer_signing_key_file,undefined);
  assert.equal(c.issuer.admission_signing_key_file,undefined);
  assert.equal(c.governance.control.admission_signing_key_file,'');
  assert.equal(c.governance.control.issuer_signing_key_file,'');
  assert.equal(c.governance.control.identity_profile.client_id,'kf-pilot-operator');
  assert.equal(c.admission.identity_profile.client_id,'kf-pilot-agent');
  assert.deepEqual(c.governance.control.shared_auth.registrations[0].subject,operator.subject);
  const expected=Object.values(registration.evidenceKeys)[0];
  const actual=Object.values(c.admission.evidence['reservation-current'].keys)[0];
  assert.equal(actual,Buffer.from(expected,'base64url').toString('base64'));
});

test('purpose key reuse, altered descriptors and Agent admin scopes are refused',()=>{
  let i=input();i.purposeKeys.issuer.public_key_base64=i.purposeKeys.admission.public_key_base64;
  assert.throws(()=>buildConfigs(i),/distinct purpose/);
  i=input();const d=JSON.parse(i.registration.descriptor);d.payload.ownership_epoch++;
  i.registration.descriptor=JSON.stringify(d);assert.throws(()=>buildConfigs(i),/untrusted record/);
  i=input();i.operator.subject=i.registration.contract.subject;
  assert.throws(()=>buildConfigs(i),/enrolled SQL/);
  i=input();i.operator.scopes.push('reservation:request');assert.throws(()=>buildConfigs(i),/enrolled SQL/);
});

test('public control preparation can precede refresh authority but broker rendering cannot',()=>{
  const i=input();delete i.purposeKeys['identity-refresh'];
  assert.deepEqual(Object.keys(buildConfigs(i).configurations).sort(),['admission','governance','issuer']);
  withNativeFixture(i);
  assert.throws(()=>buildConfigs(i),/closed fields/);
});

test('native registration must bind issuer keys, exact policy and resource before further rendering',()=>{
  const i=withNativeFixture(input());
  const c=buildConfigs(i).configurations;
  assert.deepEqual(Object.keys(c).sort(),['admission','broker','gateway','governance','issuer','recovery','target']);
  assert.equal(c.target.database.executor_user,'kf_executor');
  assert.equal(c.target.database.query_user,'kf_reader');
  assert.equal(c.gateway.actor_workload,'spiffe://cura.kedgeflow.internal/agent');
  assert.equal(c.broker.allow_unmanaged_fixture,false);
  assert.equal(c.broker.identity_refresh.minimum_epoch_file,'/etc/kedgeflow/broker/identity-floor');
  assert.equal(c.recovery.query_url,'https://sql.cura.kedgeflow.internal:8451/query');
  for(const change of [x=>x.nativeRegistration.policy.epoch++,
    x=>x.nativeRegistration.scope.resource.incarnation='different',
    x=>x.nativeRegistration.issuer_keys={},x=>x.nativeRegistration.trust_digest='unbound']) {
    const altered=structuredClone(i);change(altered);
    assert.throws(()=>buildConfigs(altered),/native registration binding/);
  }
});

test('window input cannot replay expired material or silently extend a registration',()=>{
  const i=input();
  assert.throws(()=>render(i),/explicit future stop/);
  assert.throws(()=>render(i,stopUTC,Date.parse(stopUTC)),/explicit future stop/);
  assert.throws(()=>render(i,stopUTC,fixtureNow-86400000),/explicit future stop/);
  for(const value of ['2026-11-23T09:00:00+01:00','2026-11-23T08:00:00.500Z',
    '2026-11-23T08:00:00.000Z'])
    assert.throws(()=>render(i,value,fixtureNow),/explicit future stop/);
  assert.throws(()=>render(i,'2026-11-23T09:00:00Z',fixtureNow),/enrolled SQL/);
  // Disposable public metadata can model the new bound; this grants no authority.
  i.registration.contract.until=Date.parse('2026-11-23T09:00:00Z');
  const candidate=render(i,'2026-11-23T09:00:00Z',fixtureNow);
  assert.ok(candidate.configurations.admission);
  assert.equal(candidate.execution_authority,false);
  assert.equal(candidate.enterprise_qualified,false);
});
