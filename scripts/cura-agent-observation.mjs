#!/usr/bin/env node
// Runs only as the isolated actual Agent UID. No client/service/writer secret is delivered here.
import { readFile, writeFile, lstat, mkdtemp, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { randomUUID, sign, verify, X509Certificate } from 'node:crypto';
import { request } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { connect } from 'node:net';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { canonical, exact, hash, privateSeed, publicBytes, publicKey, recordDigest,
  signedRecord, strictJson, verifyRecord } from '../sdk/node/records.mjs';
import { validateKeycloakToken } from '../sdk/node/identity-profile.mjs';

const exec=promisify(execFile),BASE='/var/lib/kedgeflow/node/workflow';
const ENDPOINT='https://services.cura.kedgeflow.internal:8444/evidence';
const TOKEN_ENDPOINT='https://identity.cura.kedgeflow.internal:8443/realms/kedgeflow-pilot/protocol/openid-connect/token';
let phase='protected_agent_preconditions';
function require(value){if(!value)throw Error('closed agent observation');}
async function protectedFile(path,uid,mode){const s=await lstat(path);
  require(s.isFile()&&s.nlink===1&&s.uid===uid&&(s.mode&0o7777)===mode&&s.size<1<<20);
  return readFile(path);}
const proof=(key,jwk,url,token)=>{const h={alg:'EdDSA',typ:'dpop+jwt',jwk};
  const c={jti:randomUUID(),htm:'POST',htu:url,iat:Math.floor(Date.now()/1000),
    ...(token?{ath:hash(token).toString('base64url')}: {})};
  const unsigned=[h,c].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  return unsigned+'.'+sign(null,Buffer.from(unsigned),key).toString('base64url');};
async function denied(host,port){return new Promise(resolve=>{
  const socket=connect({host,port});let settled=false;
  const done=value=>{if(!settled){settled=true;socket.destroy();resolve(value);}};
  socket.setTimeout(2000,()=>done(true));socket.on('error',()=>done(true));socket.on('connect',()=>done(false));
});}
function post(body,headers,tls){return new Promise((resolve,reject)=>{
  const req=request(ENDPOINT,{...tls,method:'POST',agent:false,rejectUnauthorized:true,
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['http/1.1'],headers,
    checkServerIdentity(host,cert){const error=checkServerIdentity(host,cert);if(error)return error;
      const uris=new X509Certificate(cert.raw).subjectAltName.split(', ').filter(s=>s.startsWith('URI:'));
      if(canonical(uris)!==canonical(['URI:spiffe://cura.kedgeflow.internal/evidence-relay']))return Error('peer');}},res=>{
      let size=0;const chunks=[];
      res.on('data',part=>{size+=part.length;if(size>65536)req.destroy(Error('bound'));else chunks.push(part);});
      res.on('error',reject);res.on('end',()=>{try{resolve({status:res.statusCode,
        body:strictJson(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(chunks)))});}
        catch(error){reject(error);}});
    });req.setTimeout(5000,()=>req.destroy(Error('deadline')));req.on('error',reject);req.end(canonical(body));
});}

async function main(mode,configPath){
  require(process.platform==='linux'&&process.getuid()===969&&process.getgid()===969&&
    process.getgroups().every(g=>g===969));
  const status=Object.fromEntries((await readFile('/proc/self/status','utf8')).split('\n')
    .filter(line=>line.includes(':')).map(line=>line.split(':').map(s=>s.trim())));
  require(status.CapEff==='0000000000000000'&&status.NoNewPrivs==='1'&&status.Seccomp==='2');
  const config=strictJson((await protectedFile(configPath,0,0o440)).toString());
  exact(config,['generation','contract','serviceCa']);const c=config.contract;
  require(/^[a-z0-9-]{1,40}$/.test(config.generation)&&Date.now()<c.until);
  const dpop=privateSeed(Buffer.from((await protectedFile(BASE+'/dpop.seed',969,0o400)).toString(),'base64'));
  const jwk={crv:'Ed25519',kty:'OKP',x:publicBytes(dpop).toString('base64url')};
  require(hash(canonical(jwk)).toString('base64url')===c.dpopThumbprint);
  const proofFile=BASE+'/subject-proof-'+config.generation+'.json';
  const tokenFile=BASE+'/subject-token-'+config.generation+'.json';
  if(mode==='prepare'){
    phase='own_sender_constrained_proof';
    const packet={format:'kedgeflow-cura-subject-proof-v1',generation:config.generation,
      contract_digest:hash(canonical(c)).toString('hex'),issued_at:Date.now(),
      proof:proof(dpop,jwk,TOKEN_ENDPOINT)};
    await writeFile(proofFile,canonical(packet),{flag:'wx',mode:0o400});
    console.log(JSON.stringify({status:'own_subject_proof_prepared',proof_returned:false}));return;
  }
  require(mode==='probe');phase='current_subject_token_verification';
  const packet=strictJson((await protectedFile(tokenFile,969,0o400)).toString());
  require(packet.generation===config.generation&&packet.contract_digest===hash(canonical(c)).toString('hex'));
  const token=packet.access_token,parts=token.split('.');require(parts.length===3);
  const header=strictJson(Buffer.from(parts[0],'base64url').toString()),claims=strictJson(Buffer.from(parts[1],'base64url').toString());
  validateKeycloakToken(header,claims,{clientId:'kf-pilot-agent'});
  require(header.kid===c.authorizationKeyId&&verify(null,Buffer.from(parts[0]+'.'+parts[1]),
    publicKey(c.authorizationKey),Buffer.from(parts[2],'base64url'))&&claims.iss===c.subject.iss&&
    claims.sub===c.subject.sub&&claims.aud==='urn:kedgeflow:delegated-admission'&&
    claims.cnf.jkt===c.dpopThumbprint&&claims.exp*1000>Date.now()+15000);
  const delegation={access_token_digest:hash(token).toString('hex'),dpop_jkt:c.dpopThumbprint,
    authorization_server:claims.iss,token_audience:claims.aud,
    scopes:claims.scope.trim().split(/\s+/),expires_at:claims.exp*1000};
  const headers=()=>({'content-type':'application/json',authorization:'DPoP '+token,
    dpop:proof(dpop,jwk,ENDPOINT,token)});
  phase='actual_workload_x509_fetch';
  const temporary=await mkdtemp(BASE+'/observation-x509-');
  try{
    await exec('/opt/kedgeflow/runtime/spire/bin/spire-agent',['api','fetch','x509','-socketPath',
      '/run/kedgeflow-spire-agent/agent.sock','-timeout','5s','-silent','-write',temporary],
      {timeout:10000,maxBuffer:16384});
    const tls={ca:await protectedFile(config.serviceCa,0,0o444),
      cert:await protectedFile(join(temporary,'svid.0.pem'),969,0o600),
      key:await protectedFile(join(temporary,'svid.0.key'),969,0o600)};
    phase='actual_fixed_row_baseline';
    const parameters={resource_id:c.resource.id,expected_version:1,reservation:'cura:observation-only'};
    const baselineBody={operation:'baseline',parameters},firstHeaders=headers();
    const initial=await post(baselineBody,firstHeaders,tls);require(initial.status===200);
    const baseline=initial.body;require(baseline.version==='1'&&baseline.resource.incarnation===c.resource.incarnation);
    phase='actual_replay_and_arbitrary_input_refusals';
    require((await post(baselineBody,firstHeaders,tls)).status===403);
    require((await post({operation:'baseline',parameters:{...parameters,sql:'SELECT arbitrary'}},headers(),tls)).status===403);
    phase='actual_signed_fresh_sql_evidence';
    const proposalKey=privateSeed(Buffer.from((await protectedFile(BASE+'/proposal.seed',969,0o400)).toString(),'base64'));
    const keyId=Object.keys(c.proposalKeys)[0];
    require(publicBytes(proposalKey).toString('base64url')===c.proposalKeys[keyId]);
    const proposal=signedRecord('proposal',{qid:'cura-pilot:q:'+config.generation,tenant:c.tenant,
      subject:c.subject,workload_id:c.workload,delegation,intent:'Observe the isolated registered reservation without dispatch.',
      action:{id:'postgres.reservation.set.v1',version:'1.0',digest:c.descriptorDigest},resources:[c.resource],
      parameters,dependencies:[],baseline_state:[baseline],requested_completion:'dispatch_bound',
      created_at:Date.now(),workflow:null},keyId,proposalKey);
    const body={proposal,proposal_digest:recordDigest(strictJson(proposal))};
    const collected=await post(body,headers(),tls);require(collected.status===200);
    const m=verifyRecord(collected.body.manifest,'manifest',{[c.manifestKeyId]:c.manifestPublicKey});
    require(collected.body.witnesses.length===1);
    const e=verifyRecord(collected.body.witnesses[0],'evidence',{[c.evidenceKeyId]:c.evidencePublicKey});
    require(m.payload.proposal_digest===body.proposal_digest&&e.payload.proposal_digest===body.proposal_digest&&
      e.payload.state_digest===baseline.state_digest&&m.payload.witnesses[0].witness.digest===recordDigest(e)&&
      canonical(m.payload.policy)===canonical(c.policy)&&e.payload.result.version==='1'&&
      e.payload.observed_at<=Date.now()&&e.payload.expires_at>Date.now());
    phase='actual_tampered_proposal_refusal';
    require((await post({...body,proposal:proposal.replace('Observe the isolated','Tamper the isolated')},headers(),tls)).status===403);
    require((await post(baselineBody,headers(),tls)).status===200);
    phase='actual_agent_network_and_custody_refusals';
    const refusals={metadata:await denied('169.254.169.254',80),
      direct_sql_observer:await denied('sql.cura.kedgeflow.internal',8452),
      postgres_tcp:await denied('sql.cura.kedgeflow.internal',5432)};
    require(Object.values(refusals).every(Boolean));
    const retained={manifest:collected.body.manifest,witnesses:collected.body.witnesses};
    await writeFile(BASE+'/observation-public-proof-'+config.generation+'.json',canonical(retained),{flag:'wx',mode:0o400});
    console.log(JSON.stringify({status:'actual_managed_agent_observation_passed',uid:process.getuid(),
      caps_zero:true,no_new_privs:true,seccomp:true,registered_workload_x509_used:true,
      signed_evidence_verified:true,signed_manifest_verified:true,proposal_policy_state_binding_verified:true,
      replay_refused:true,arbitrary_input_refused:true,tampered_proposal_refused:true,
      network_refusals:refusals,sql_version:baseline.version,evidence_digest:recordDigest(e),manifest_digest:recordDigest(m),
      credentials_returned:false,dispatches_issued:0,owner_acceptance:'BLOCKED_EXTERNAL_INPUT',execution_authority:false}));
  }finally{await rm(temporary,{recursive:true,force:true});}
}

main(process.argv[2],process.argv[3]).catch(()=>{
  console.log(JSON.stringify({status:'failed',phase}));process.exitCode=1;
});
