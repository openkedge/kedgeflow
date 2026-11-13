// Synthetic signed-owner/parser tests only; no deployed or independent acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm, mkdir, realpath, symlink, truncate, cp, link, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonical } from '../sdk/node/records.mjs';
import { PROFILE, GATES, deploymentDigest, sha256, signatureInput, evaluate, prepareRequest } from '../scripts/terraform-acceptance-records.mjs';
const NOW = 2_000_000_000_000;
const ROOT = resolve(import.meta.dirname,'..');
const clone = x => JSON.parse(JSON.stringify(x));
async function fixture(profile = 'single', now = NOW) {
  const directory = await mkdtemp(join(await realpath(tmpdir()),'kf-acceptance-'));
  await mkdir(join(directory,'artifacts'));
  const keys = Object.values(GATES).map(()=>generateKeyPairSync('ed25519'));
  const artifact = async text => {
    const digest = sha256(text);
    await writeFile(join(directory,'artifacts',digest),text);
    return digest;
  };
  const deployment = {profile:PROFILE,deployment_id:'test-only:owned-fixture',source_commit:'a'.repeat(40),bundle_sha256:'b'.repeat(64),configuration_sha256:'c'.repeat(64),writer_inventory_sha256:await artifact('SYNTHETIC TEST INVENTORY; no deployed writer coverage'),scope:{profile:'KF-TERRAFORM-GATEWAY-0.1-draft',resource:{id:'terraform:'+ 'd'.repeat(64),incarnation:'test-configmap-uid'},manifest_digest:'d'.repeat(64),effect_digest:'e'.repeat(64),guard_level:'Level_C',target_atomic:false},not_before:now-10000,expires_at:now+100000};
  if(profile === 'pair') {deployment.scope.profile='KF-TERRAFORM-PAIR-GATEWAY-0.1-draft';deployment.scope.resource.id='terraform-pair:'+deployment.scope.manifest_digest;deployment.scope.resource.incarnation='f'.repeat(64);}
  const digest = deploymentDigest(deployment);
  const trust = {profile:PROFILE,deployment_digest:digest,not_before:now-20000,expires_at:now+200000,owners:Object.values(GATES).map((g,i)=>({id:'test-owner-'+i,role:g.role,administration_domain:'test-domain-'+i,key_id:'test-key-'+i,public_key:keys[i].publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64url'),minimum_sequence:1,not_before:now-20000,expires_at:now+100000}))};
  const evidence = {profile:PROFILE,deployment_digest:digest,gates:[]};
  for(const [id,g] of Object.entries(GATES)) {
    const checks=[];
    for(const check of g.checks) checks.push({id:check,result:'pass',artifact_sha256:await artifact('SYNTHETIC CHECK ONLY: '+id+'/'+check)});
    evidence.gates.push({id,deployment_digest:digest,scope:'deployed',observed_at:now-1000,valid_until:now+50000,checks});
  }
  const approvals = {profile:PROFILE,deployment_digest:digest,approvals:[]};
  const resign = (i,context=signatureInput) => {
    const owner=trust.owners[i];
    const unsigned={profile:PROFILE,owner_id:owner.id,role:owner.role,key_id:owner.key_id,payload:{deployment_digest:digest,gate:evidence.gates[i].id,observation_sha256:sha256(canonical(evidence.gates[i])),decision:'accept',issued_at:now-500,expires_at:now+30000,sequence:1}};
    approvals.approvals[i]={...unsigned,signature:sign(null,context(unsigned),keys[i].privateKey).toString('base64url')};
  };
  const resignCurrent = i => {const {signature,...u}=approvals.approvals[i];approvals.approvals[i].signature=sign(null,signatureInput(u),keys[i].privateKey).toString('base64url');};
  for(let i=0;i<7;i++) resign(i);
  const persist = async () => {
    for(const [name,value] of Object.entries({'deployment.json':deployment,'trust.json':trust,'evidence.json':evidence,'approvals.json':approvals})) await writeFile(join(directory,name),JSON.stringify(value));
  };
  await persist();
  const options = () => ({trustFile:join(directory,'trust.json'),trustSha256:sha256(JSON.stringify(trust)),expectedDeployment:digest,now});
  return {directory,deployment,digest,trust,evidence,approvals,resign,resignCurrent,persist,options,artifact};
}
async function withFixture(run,profile) {
  const f=await fixture(profile);
  try {await run(f);} finally {await rm(f.directory,{recursive:true,force:true});}
}
async function blocked(mutate) {
  await withFixture(async f=>{
    await mutate(f);await f.persist();
    const report=await evaluate(f.directory,f.options());
    assert.equal(report.state,'blocked');assert(report.gaps.length>0);
    assert.equal(report.execution_authority,false);assert.equal(report.production_qualified,false);
  });
}

test('all exact signed owner records verify, without producing execution authority or production certification',()=>withFixture(async f=>{
  const report=await evaluate(f.directory,f.options());
  assert.equal(report.state,'owner_records_verified',JSON.stringify(report));
  assert.equal(report.gates.length,7);assert.equal(report.artifacts_verified,26);
  assert.equal(report.valid_until,NOW+30000);assert.equal(report.trust_sha256,f.options().trustSha256);
  assert.equal(report.production_qualified,false);assert.equal(report.execution_authority,false);
  if(process.env.KF_ACCEPTANCE_TEST_OUTPUT) {
    const out=resolve(process.env.KF_ACCEPTANCE_TEST_OUTPUT);
    await mkdir(out,{mode:0o700});
    for(const name of ['deployment.json','trust.json','evidence.json','approvals.json','artifacts']) await cp(join(f.directory,name),join(out,name),{recursive:true,errorOnExist:true,force:false});
    await writeFile(join(out,'expected.json'),JSON.stringify({...f.options(),trustFile:'trust.json',synthetic_only:true,report},null,2)+'\n');
  }
}));
const negatives = {
  'missing owner approval':f=>f.approvals.approvals.pop(),
  'explicit owner rejection':f=>{f.approvals.approvals[0].payload.decision='reject';f.resignCurrent(0);},
  'forged approval signature':f=>{f.approvals.approvals[0].signature='A'.repeat(86);},
  'owner role substitution':f=>{f.approvals.approvals[0].role='deployment';f.resignCurrent(0);},
  'another deployment approval':f=>{f.approvals.approvals[0].payload.deployment_digest='0'.repeat(64);f.resignCurrent(0);},
  'a changed configuration invalidates the external deployment pin':f=>{f.deployment.configuration_sha256='f'.repeat(64);},
  'a changed release invalidates the external deployment pin':f=>{f.deployment.source_commit='f'.repeat(40);},
  'changed observation cannot reuse an approval':f=>{f.evidence.gates[0].observed_at--;},
  'local fixture observation cannot count as deployed evidence':f=>{f.evidence.gates[0].scope='local_fixture';f.resign(0);},
  'unknown check remains blocked even with a valid owner signature':f=>{f.evidence.gates[0].checks[0].result='unknown';f.resign(0);},
  'failed check remains blocked even with a valid owner signature':f=>{f.evidence.gates[0].checks[0].result='fail';f.resign(0);},
  'missing required check':f=>{f.evidence.gates[0].checks.pop();f.resign(0);},
  'duplicate check cannot replace coverage':f=>{f.evidence.gates[0].checks[1]=clone(f.evidence.gates[0].checks[0]);f.resign(0);},
  'extra check cannot enlarge the admitted profile':f=>{f.evidence.gates[0].checks.push(clone(f.evidence.gates[0].checks[0]));f.resign(0);},
  'duplicate approval cannot satisfy two owners':f=>{f.approvals.approvals[1]=clone(f.approvals.approvals[0]);},
  'unknown gate':f=>{f.evidence.gates[0].id='arbitrary';},
  'missing deployed observation':f=>{f.evidence.gates.pop();},
  'same key cannot impersonate independent owners':f=>{f.trust.owners[1].public_key=f.trust.owners[0].public_key;},
  'same principal cannot impersonate independent owners':f=>{f.trust.owners[1].id=f.trust.owners[0].id;},
  'storage shares the deployment administration domain':f=>{f.trust.owners.find(o=>o.role==='storage').administration_domain=f.trust.owners.find(o=>o.role==='deployment').administration_domain;},
  'reproducer shares the audit administration domain':f=>{f.trust.owners.find(o=>o.role==='independent_reproducer').administration_domain=f.trust.owners.find(o=>o.role==='audit').administration_domain;},
  'withdrawn owner key refuses the old signature':f=>{f.trust.owners[0].public_key=f.trust.owners[1].public_key;},
  'approval below the trusted sequence floor':f=>{f.trust.owners[0].minimum_sequence=2;},
  'expired owner approval':f=>{f.approvals.approvals[0].payload.expires_at=NOW;f.resignCurrent(0);},
  'expired observation':f=>{f.evidence.gates[0].valid_until=NOW;f.resign(0);},
  'future observation':f=>{f.evidence.gates[0].observed_at=NOW+1;f.resign(0);},
  'expired deployment':f=>{f.deployment.expires_at=NOW;},
  'expired trust':f=>{f.trust.expires_at=NOW;},
  'future trust':f=>{f.trust.not_before=NOW+1;},
  'owner record is signed with a grant-like signature domain':f=>{f.resign(0,u=>Buffer.from('KedgeFlow/KF-JSON-0.2\0'+canonical(u)));},
  'extra fields refuse, rather than enabling a new deployment mode':f=>{f.deployment.production_qualified=true;},
  'target atomicity claim refuses':f=>{f.deployment.scope.target_atomic=true;},
  'registered resource cannot be substituted':f=>{f.deployment.scope.resource.id='terraform:wrong';},
  'null identifier refuses':f=>{f.deployment.scope.resource.incarnation=null;},
  'artifact traversal refuses':f=>{f.evidence.gates[0].checks[0].artifact_sha256='../trust.json';f.resign(0);},
  'changed artifact bytes refuse':async f=>{await writeFile(join(f.directory,'artifacts',f.evidence.gates[0].checks[0].artifact_sha256),'tampered');},
  'missing artifact refuses':async f=>{await rm(join(f.directory,'artifacts',f.evidence.gates[0].checks[0].artifact_sha256));},
  'missing writer inventory refuses':async f=>{await rm(join(f.directory,'artifacts',f.deployment.writer_inventory_sha256));},
  'oversized artifact refuses':async f=>{await truncate(join(f.directory,'artifacts',f.evidence.gates[0].checks[0].artifact_sha256),(4<<20)+1);},
};
for(const [name,mutate] of Object.entries(negatives)) test(name,()=>blocked(mutate));

test('external trust pin prevents silently supplying a different owner trust set',()=>withFixture(async f=>{
  const options=f.options();f.trust.owners[0].minimum_sequence=2;await f.persist();
  const report=await evaluate(f.directory,options);assert.equal(report.state,'blocked');assert.equal(report.gaps[0].reason,'trust_digest_mismatch');
}));
test('strict JSON refuses duplicate keys and unsafe integer tokens before signature checks',()=>withFixture(async f=>{
  for(const text of ['{"profile":"x","profile":"y"}','{"expires_at":9007199254740993}']) {
    await writeFile(join(f.directory,'evidence.json'),text);
    assert.equal((await evaluate(f.directory,f.options())).state,'blocked');
  }
}));
test('symlink artifacts and symlink input parents refuse',()=>withFixture(async f=>{
  const digest=f.evidence.gates[0].checks[0].artifact_sha256,path=join(f.directory,'artifacts',digest);
  await rm(path);await symlink(join(f.directory,'deployment.json'),path);
  assert.equal((await evaluate(f.directory,f.options())).state,'blocked');
  const alias=f.directory+'-alias';await symlink(f.directory,alias);
  try {assert.equal((await evaluate(alias,f.options())).state,'blocked');} finally {await rm(alias);}
}));
test('special files refuse without waiting for a writer',{skip:process.platform==='win32'},()=>withFixture(async f=>{
  const path=join(f.directory,'artifacts',f.evidence.gates[0].checks[0].artifact_sha256);
  await rm(path);assert.equal(spawnSync('mkfifo',[path]).status,0);
  assert.equal((await evaluate(f.directory,f.options())).state,'blocked');
}));
test('prepared requests contain unknown evidence and zero fabricated approvals',()=>withFixture(async f=>{
  const request=prepareRequest(f.deployment);
  assert.equal(request.state,'awaiting_deployed_evidence_and_owners');
  assert.equal(request.approvals.approvals.length,0);
  assert(request.evidence.gates.every(g=>g.scope==='unqualified'&&g.checks.every(c=>c.result==='unknown'&&c.artifact_sha256===null)));
  f.evidence=request.evidence;await writeFile(join(f.directory,'evidence.json'),JSON.stringify(request.evidence));
  assert.equal((await evaluate(f.directory,f.options())).state,'blocked');
}));
test('prepare CLI creates a reviewable pending directory and refuses overwrite',()=>withFixture(async f=>{
  const out=join(f.directory,'pending');
  const args=[join(ROOT,'scripts/prepare-terraform-acceptance.mjs'),'--deployment',join(f.directory,'deployment.json'),'--output',out];
  const result=spawnSync(process.execPath,args,{encoding:'utf8'});
  assert.equal(result.status,0,result.stdout+result.stderr);
  assert.equal(JSON.parse(await readFile(join(out,'approvals.json'),'utf8')).approvals.length,0);
  assert.equal(spawnSync(process.execPath,args).status,1);
  assert.equal(JSON.parse(await readFile(join(out,'deployment.json'),'utf8')).deployment_id,f.deployment.deployment_id);
}));
test('verify CLI uses actual time, has no backdating flag, and reports missing inputs closed',()=>{
  for(const args of [[],['--now-ms',String(NOW)]]) {
    const result=spawnSync(process.execPath,[join(ROOT,'scripts/verify-terraform-acceptance.mjs'),...args],{encoding:'utf8'});
    assert.notEqual(result.status,0);assert.equal(JSON.parse(result.stdout).state,'blocked');
  }
});

test('separately registered pair profile verifies its own exact resource identity',()=>withFixture(async f=>{
  const report=await evaluate(f.directory,f.options());assert.equal(report.state,'owner_records_verified',JSON.stringify(report));
},'pair'));

test('verify CLI accepts a current pinned synthetic cohort and returns a non-authoritative report',async()=>{
 const f=await fixture('single',Date.now());
 try {
  const o=f.options();
  const args=[join(ROOT,'scripts/verify-terraform-acceptance.mjs'),'--directory',f.directory,'--trust',o.trustFile,'--trust-sha256',o.trustSha256,'--deployment-digest',o.expectedDeployment];
  const r=spawnSync(process.execPath,args,{encoding:'utf8'});
  assert.equal(r.status,0,r.stdout+r.stderr);
  const report=JSON.parse(r.stdout);assert.equal(report.state,'owner_records_verified');assert.equal(report.execution_authority,false);assert.equal(report.production_qualified,false);
  await rm(join(f.directory,'approvals.json'));
  const refused=spawnSync(process.execPath,args,{encoding:'utf8'});assert.equal(refused.status,1);assert.equal(JSON.parse(refused.stdout).state,'blocked');
 } finally {await rm(f.directory,{recursive:true,force:true});}
});

test('hardlinked evidence refuses even when its digest is correct',()=>withFixture(async f=>{
 const source=join(f.directory,'artifacts',f.evidence.gates[0].checks[0].artifact_sha256);
 await link(source,join(f.directory,'alias-hardlink'));
 assert.equal((await evaluate(f.directory,f.options())).state,'blocked');
}));
test('correctly signed future approval refuses',()=>blocked(f=>{f.approvals.approvals[0].payload.issued_at=NOW+1;f.resignCurrent(0);}));
test('correctly signed approval cannot outlive its evidence',()=>blocked(f=>{f.approvals.approvals[0].payload.expires_at=NOW+60000;f.resignCurrent(0);}));
test('aggregate evidence has a finite read budget',()=>withFixture(async f=>{
 let index=0;
 for(const gate of f.evidence.gates) {
  for(const check of gate.checks) {
   const bytes=Buffer.alloc(4<<20,index++);check.artifact_sha256=await f.artifact(bytes);
  }
 }
 for(let i=0;i<7;i++) f.resign(i);
 await f.persist();
 const report=await evaluate(f.directory,f.options());
 assert.equal(report.state,'blocked');assert(report.gaps.some(x=>x.reason==='evidence_size_bound'));
}));

test('retained artifact bytes are hashed, never executed',()=>withFixture(async f=>{
 const marker=join(f.directory,'MUST-NOT-EXIST');
 const digest=await f.artifact('#!/bin/sh\ntouch '+marker+'\n');
 f.evidence.gates[0].checks[0].artifact_sha256=digest;f.resign(0);await f.persist();
 assert.equal((await evaluate(f.directory,f.options())).state,'owner_records_verified');
 await assert.rejects(access(marker));
}));

test('draft schema and semantic verifier require the same gate roles and check IDs',async()=>{
 const schema=JSON.parse(await readFile(join(ROOT,'spec/drafts/terraform-deployment-acceptance-v0.1.schema.json'),'utf8'));
 assert.deepEqual(schema.$defs.Owner.properties.role.enum,Object.values(GATES).map(g=>g.role));
 const observations=schema.$defs.Observation.oneOf;assert.equal(observations.length,7);
 for(const [gate,g] of Object.entries(GATES)) {
  const shape=observations.find(s=>s.properties.id.const===gate);assert(shape);
  assert.deepEqual(shape.properties.checks.items.properties.id.enum,g.checks);
  assert.equal(shape.properties.checks.minItems,g.checks.length);
  assert.equal(shape.properties.scope.const,'deployed');
 }
});
