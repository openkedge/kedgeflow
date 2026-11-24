// Synthetic records exercise administrative verification, never deployed acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, realpath, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical } from '../sdk/node/records.mjs';
import { PROFILE,GATES,validateDeployment,deploymentDigest,signatureInput,sha256,evaluate,prepareRequest } from '../scripts/pilot-acceptance-records.mjs';
import { signatureInput as terraformInput } from '../scripts/terraform-acceptance-records.mjs';
import { REQUIRED_JOBS,REQUIRED_STEPS } from '../scripts/release-ci.mjs';
const now=2_000_000_000_000;
function deployment() {return {profile:PROFILE,deployment_id:'test-only:sql-pilot',
  source_commit:'a'.repeat(40),bundle_sha256:'b'.repeat(64),configuration_sha256:'c'.repeat(64),
  writer_inventory_sha256:'d'.repeat(64),capabilities_sha256:'e'.repeat(64),
  scope:{profile:'KF-POSTGRES-LEAF-0.1-draft',action:'postgres.reservation.set.v1',action_version:'1.0',
    resource:{id:'slot',incarnation:'incarnation-1'},ctd_sha256:'f'.repeat(64),parameter_schema_sha256:'1'.repeat(64),
    guard_level:'Level_A',target_atomic:true,guard:'version_eq',guard_primitive:'FencingToken',completion_mode:'dispatch_bound',review:'none',delegation:false,
    tenancy:'single_organization_isolated',platform:'linux_systemd'},not_before:now-10000,expires_at:now+100000};}
function ci() {return {run:{repository:{full_name:'openkedge/kedgeflow'},path:'.github/workflows/ci.yml',
  head_sha:'a'.repeat(40),id:123,run_attempt:1,status:'completed',conclusion:'success'},
  jobs:{total_count:REQUIRED_JOBS.length,jobs:REQUIRED_JOBS.map((name,i)=>({name,id:1000+i,run_id:123,
    run_attempt:1,head_sha:'a'.repeat(40),status:'completed',conclusion:'success',
    steps:REQUIRED_STEPS[name].map(name=>({name,status:'completed',conclusion:'success'}))}))}};}
async function fixture(run, mutate=()=>{}, context=signatureInput) {
  const directory=await mkdtemp(join(await realpath(tmpdir()),'kf-sql-acceptance-'));
  try {
    await mkdir(join(directory,'artifacts'));
    const artifact=async bytes=>{const digest=sha256(bytes);await writeFile(join(directory,'artifacts',digest),bytes);return digest;};
    const d=deployment();d.writer_inventory_sha256=await artifact('SYNTHETIC writer inventory');
    d.capabilities_sha256=await artifact('SYNTHETIC capabilities');
    const digest=deploymentDigest(d),keys=Object.values(GATES).map(()=>generateKeyPairSync('ed25519'));
    const trust={profile:PROFILE,deployment_digest:digest,not_before:now-20000,expires_at:now+100000,
      owners:Object.values(GATES).map((g,i)=>({id:'test-owner-'+i,role:g.role,administration_domain:'test-domain-'+i,
        key_id:'test-key-'+i,public_key:keys[i].publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64url'),
        minimum_sequence:1,not_before:now-20000,expires_at:now+100000}))};
    const record=ci();mutate(record);
    const evidence={profile:PROFILE,deployment_digest:digest,gates:[]},approvals={profile:PROFILE,deployment_digest:digest,approvals:[]};
    for (const [id,g] of Object.entries(GATES)) {
      const checks=[];
      for (const check of g.checks) checks.push({id:check,result:'pass',artifact_sha256:await artifact(
        check==='required_ci_same_source_no_skips' ? JSON.stringify(record) : 'SYNTHETIC '+id+'/'+check)});
      const o={id,deployment_digest:digest,scope:'deployed',observed_at:now-1000,valid_until:now+50000,checks};
      evidence.gates.push(o);
      const i=evidence.gates.length-1,owner=trust.owners[i];
      const unsigned={profile:PROFILE,owner_id:owner.id,role:owner.role,key_id:owner.key_id,payload:{
        deployment_digest:digest,gate:id,observation_sha256:sha256(canonical(o)),decision:'accept',issued_at:now-500,
        expires_at:now+30000,sequence:1}};
      approvals.approvals.push({...unsigned,signature:sign(null,context(unsigned),keys[i].privateKey).toString('base64url')});
    }
    const persist=async()=>{for(const [name,value] of Object.entries({'deployment.json':d,'trust.json':trust,
      'evidence.json':evidence,'approvals.json':approvals})) await writeFile(join(directory,name),JSON.stringify(value));};
    await persist();
    const options={trustFile:join(directory,'trust.json'),trustSha256:sha256(JSON.stringify(trust)),expectedDeployment:digest,now};
    await run({directory,d,evidence,approvals,persist,options});
  } finally {await rm(directory,{recursive:true,force:true});}
}
test('SQL records require every owner and exact successful CI; certification stays false',()=>fixture(async f=>{
  const r=await evaluate(f.directory,f.options);assert.equal(r.state,'owner_records_verified',JSON.stringify(r));
  assert.equal(r.gates.length,7);assert.equal(r.production_qualified,false);assert.equal(r.execution_authority,false);
}));
test('even a signed assertion cannot override a red CI record',()=>fixture(async f=>{
  const r=await evaluate(f.directory,f.options);assert.equal(r.state,'blocked');assert(r.gaps.some(g=>g.reason==='ci_not_successful'));
},r=>r.run.conclusion='failure'));
test('even a signed assertion cannot substitute another source CI',()=>fixture(async f=>{
  const r=await evaluate(f.directory,f.options);assert.equal(r.state,'blocked');
},r=>r.run.head_sha='b'.repeat(40)));
test('Terraform signatures cannot approve SQL pilot records',()=>fixture(async f=>{
  assert.equal((await evaluate(f.directory,f.options)).state,'blocked');
},()=>{},terraformInput));
test('pending owner request never synthesizes evidence or keys',()=>{
  const r=prepareRequest(deployment());assert.equal(r.approvals.approvals.length,0);
  assert(r.evidence.gates.every(g=>g.scope==='unqualified'&&g.checks.every(c=>c.result==='unknown')));
});
test('missing independent owner blocks acceptance',()=>fixture(async f=>{
  f.approvals.approvals.pop();await f.persist();assert.equal((await evaluate(f.directory,f.options)).state,'blocked');
}));
test('changed retained capabilities block acceptance',()=>fixture(async f=>{
  await writeFile(join(f.directory,'artifacts',f.d.capabilities_sha256),'changed');
  assert.equal((await evaluate(f.directory,f.options)).state,'blocked');
}));
for (const [field,value] of [['profile','KF-TERRAFORM-GATEWAY-0.1-draft'],['guard_level','Level_C'],
  ['target_atomic',false],['guard','arbitrary'],['action','postgres.arbitrary'],['review','webauthn'],
  ['delegation',true],['tenancy','multi_tenant'],['platform','kubernetes']]) {
  test('pilot refuses unsupported '+field,()=>{const d=deployment();d.scope[field]=value;assert.throws(()=>validateDeployment(d));});
}
