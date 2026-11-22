import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authenticate, consume, observation, rowState, validateContract, RESULT_SCHEMA }
  from '../scripts/cura-sql-evidence.mjs';
import { canonical, digest, hash, privateSeed, publicBytes, recordDigest, signedRecord,
  strictJson, verifyRecord } from '../sdk/node/records.mjs';
import { buildProfile } from '../scripts/cura-sql-profile.mjs';
import { validateSqlDescriptor } from '../sdk/node/sql-leaf.mjs';

const key = () => generateKeyPairSync('ed25519').privateKey;
const proposal=key(),evidence=key(),manifest=key(),dpop=key(),authorization=key();
const now=1800000000000;
const jwk={crv:'Ed25519',kty:'OKP',x:publicBytes(dpop).toString('base64url')};
const c={profile:'kedgeflow-cura-sql-observer-v1',tenant:'cura-pilot',
  resource:{id:'slot-a',incarnation:'cura-reservation-'+'a'.repeat(32)},
  subject:{iss:'https://identity.cura.kedgeflow.internal:8443/realms/kedgeflow-pilot',
    sub:'d0b36f01-1188-4f01-907a-000000000001'},
  workload:'spiffe://cura.kedgeflow.internal/agent',proposalKeys:{'urn:kf:unit:proposal':publicBytes(proposal).toString('base64url')},
  descriptorDigest:'d'.repeat(64),policy:{id:'cura-pilot:policy:reservation',epoch:1,digest:'b'.repeat(64)},
  question:{id:'cura-pilot:question:reservation',schema:'urn:kf:cura:reservation-question:1.0',digest:'c'.repeat(64)},
  resultSchema:{id:'cura-pilot:result:reservation',schema:'urn:kf:cura:reservation-result:1.0',digest:digest('result-schema',RESULT_SCHEMA)},
  providerId:'cura-pilot:provider:sql-observer',evidenceKeyId:'urn:kf:cura:evidence:v1',manifestKeyId:'urn:kf:cura:manifest:v1',
  evidencePublicKey:publicBytes(evidence).toString('base64url'),manifestPublicKey:publicBytes(manifest).toString('base64url'),
  authorizationKeyId:'unit-auth',authorizationKey:publicBytes(authorization).toString('base64url'),
  dpopThumbprint:hash(canonical(jwk)).toString('base64url'),until:now+600000};
const row={tenant:'cura-pilot',conflict_domain:'cura-sql-pilot:reservations',resource_id:'slot-a',
  incarnation:c.resource.incarnation,version:'1',last_fence:'0',reservation:'available',active:true};
const args={resource_id:'slot-a',expected_version:1,reservation:'unit:booking'};
const jwt=(h,p,k)=>{const raw=[h,p].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  return raw+'.'+sign(null,Buffer.from(raw),k).toString('base64url');};
function headers(change={},proofChange={}) {
  const token=jwt({alg:'EdDSA',typ:'JWT',kid:'unit-auth'},{...c.subject,aud:'urn:kedgeflow:delegated-admission',
    exp:now/1000+300,iat:now/1000,scope:'reservation:request kf.admit kf.issue kf.status kf.evidence',
    cnf:{jkt:c.dpopThumbprint,'kc-jkt-type':'DPoP'},typ:'DPoP',azp:'kf-pilot-agent',jti:'unit-token',...change},authorization);
  return {authorization:'DPoP '+token,dpop:jwt({alg:'EdDSA',typ:'dpop+jwt',jwk},
    {jti:'unit-proof',htm:'POST',htu:'https://services.cura.kedgeflow.internal:8444/evidence',
      iat:now/1000,ath:hash(token).toString('base64url'),...proofChange},dpop)};
}
function packet(identity, baseline) {
  const raw=signedRecord('proposal',{qid:'unit:reservation',tenant:c.tenant,subject:c.subject,
    workload_id:c.workload,delegation:identity.delegation,intent:'Disposable signature test only.',
    action:{id:'postgres.reservation.set.v1',version:'1.0',digest:c.descriptorDigest},resources:[c.resource],
    parameters:args,dependencies:[],baseline_state:[baseline],requested_completion:'dispatch_bound',
    created_at:now,workflow:null},Object.keys(c.proposalKeys)[0],proposal);
  return {proposal:raw,proposal_digest:recordDigest(strictJson(raw))};
}

test('closed contract and real record signatures bind actual row, proposal, policy and manifest',()=>{
  validateContract(c);
  const identity=authenticate(headers(),c,now);
  const baseline=observation({operation:'baseline',parameters:args},row,c,identity,{},now);
  const body=packet(identity,baseline);
  const result=observation(body,row,c,identity,{evidence,manifest},now+1);
  const e=verifyRecord(result.witnesses[0],'evidence',{[c.evidenceKeyId]:publicBytes(evidence).toString('base64url')});
  const m=verifyRecord(result.manifest,'manifest',{[c.manifestKeyId]:publicBytes(manifest).toString('base64url')});
  assert.equal(e.payload.state_digest,rowState(row,c));
  assert.equal(e.payload.proposal_digest,body.proposal_digest);
  assert.equal(canonical(e.payload.result),canonical({version:'1',reservation:'available',active:true,satisfied:true}));
  assert.equal(m.payload.witnesses[0].witness.digest,recordDigest(e));
  assert.equal(canonical(m.payload.policy),canonical(c.policy));
});

test('authentication refuses wrong subject, scope, confirmation, endpoint, stale proof and token',()=>{
  for(const change of [{sub:'wrong'},{scope:'reservation:request kf.evidence'},{exp:now/1000},
    {cnf:{jkt:'wrong','kc-jkt-type':'DPoP'}},{azp:'other-client'},{aud:'other-audience'}])
    assert.throws(()=>authenticate(headers(change),c,now));
  for(const change of [{htu:'https://sql.cura.kedgeflow.internal:8452/evidence'},
    {htm:'GET'},{iat:now/1000-61},{ath:'wrong'},{extra:true}])
    assert.throws(()=>authenticate(headers({},change),c,now));
  assert.throws(()=>authenticate({...headers(),dpop:headers().dpop+'='},c,now));
  assert.throws(()=>authenticate(headers(),c,c.until));
});

test('fresh signed proposal cannot obtain evidence for changed or stale database state',()=>{
  const identity=authenticate(headers(),c,now);
  const baseline=observation({operation:'baseline',parameters:args},row,c,identity,{},now);
  const body=packet(identity,baseline);
  for(const changed of [{...row,version:'2'},{...row,last_fence:'1'},
    {...row,reservation:'another:booking'},{...row,incarnation:'other-incarnation'}])
    assert.throws(()=>observation(body,changed,c,identity,{evidence,manifest},now+1));
  assert.throws(()=>observation(body,row,c,identity,{evidence,manifest},now+60000));
  assert.throws(()=>observation({...body,proposal_digest:'e'.repeat(64)},row,c,identity,{evidence,manifest},now));
  const wrongKey=privateSeed(Buffer.alloc(32,99));
  const replaced=strictJson(body.proposal);
  const forged=signedRecord('proposal',replaced.payload,replaced.key_id,wrongKey);
  assert.throws(()=>observation({proposal:forged,proposal_digest:recordDigest(strictJson(forged))},row,c,identity,{evidence,manifest},now));
});

test('persistent replay consumption survives verifier recreation and rejects clock rollback',async()=>{
  const root=await mkdtemp(join(tmpdir(),'kf-evidence-replay-'));
  try {
    const id='a'.repeat(64);await consume(root,id,now);
    await assert.rejects(consume(root,id,now+1));
    await assert.rejects(consume(root,'b'.repeat(64),now-1000));
    await consume(root,id,now+66001);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('observer contract rejects unknown fields, reused signing identity and unregistered row',()=>{
  for(const changed of [{...c,extra:true},{...c,manifestKeyId:c.evidenceKeyId},
    {...c,resource:{...c.resource,id:'other'}},{...c,resultSchema:{...c.resultSchema,digest:'0'.repeat(64)}}])
    assert.throws(()=>validateContract(changed));
  for(const changed of [{...row,tenant:'other'},{...row,version:'9007199254740992'},
    {...row,last_fence:'-1'},{...row,extra:'sql'},{...row,active:'true'}])
    assert.throws(()=>rowState(changed,c));
});

test('registry candidate uses official SQL schema and real independently verified record signature',async()=>{
  const registry=key(),base64=k=>publicBytes(k).toString('base64');
  const input={resource:c.resource,agent:{proposal_key_id:'urn:kf:cura:agent-proposal:v1',
    proposal_public_key_base64:base64(proposal),workload:c.workload,dpop_thumbprint:c.dpopThumbprint},
    observerKeys:{evidence:base64(evidence),manifest:base64(manifest)},
    keycloakKeys:{keys:[{kid:c.authorizationKeyId,kty:'OKP',crv:'Ed25519',use:'sig',alg:'EdDSA',x:c.authorizationKey}]},
    until:c.until};
  const cedar=strictJson(await readFile(new URL('../spec/drafts/cedar-leaf-v0.1.schema.json',import.meta.url),'utf8'));
  const profile=buildProfile(input,registry,cedar);
  const descriptor=verifyRecord(profile.descriptor,'ctd',profile.registryKeys);
  validateSqlDescriptor(descriptor.payload);
  assert.equal(descriptor.payload.concurrency.predicate_descriptor.clauses[0].expected_version,'1');
  assert.equal(profile.contract.descriptorDigest,recordDigest(descriptor));
  assert.equal(profile.owner_acceptance,'BLOCKED_EXTERNAL_INPUT');
  assert.equal(profile.writerInventory.runtime_writer_bypass_qualification,'PENDING');
});
