import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {verify,verifyCase} from '../scripts/verify-terraform-active.mjs';
const root='.cache/terraform-active-replay';
const positive=await verify(root),negative=[];
const temp=await mkdtemp(join(tmpdir(),'kf-terraform-active-verifier-'));
try {
 for(const [name,caseName,mutate] of [
  ['wrong-child-parent','provider-kill',(p,n)=>{p.provider_parent=p.gateway_pid;n.injection=p;}],
  ['live-group-claimed-clean','terraform-kill',(p,n)=>{p.no_live_group_at_release=false;n.injection=p;}],
  ['pipe-deadline-delay','terraform-kill',(p,n)=>{p.ordinary_unknown_at=p.intervention_at+6000;p.gate_completion.released_at_ms=p.ordinary_unknown_at+1;n.injection=p;}],
  ['late-before-cleanup','deadline-late',(p,n)=>{p.gate_completion.forwarded_at_ms=p.ordinary_unknown_at-1;n.injection=p;}],
  ['unknown-promoted','deadline-late',(p,n)=>{n.native_state='committed';}],
  ['erased-late-target','deadline-late',(p,n)=>{p.target_after_release.metadata.annotations['kedgeflow.dev/revision']='before';n.injection=p;}]
 ]) {
  const testRoot=join(temp,name);await mkdir(join(testRoot,'cases'),{recursive:true});
  const base=join(testRoot,'cases',caseName);await cp(join(root,'cases',caseName),base,{recursive:true,dereference:true});
  const p=JSON.parse(await readFile(join(base,'active-child-proof.json'),'utf8')),n=JSON.parse(await readFile(join(base,'sdk-native-report.json'),'utf8'));mutate(p,n);
  await writeFile(join(base,'active-child-proof.json'),JSON.stringify(p));await writeFile(join(base,'sdk-native-report.json'),JSON.stringify(n));
  await assert.rejects(verifyCase(testRoot,caseName));negative.push({name,status:'REFUSED'});
 }
 const result={status:'PASS',positive,negative};await writeFile('.cache/terraform-active-verifier-tests.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
} finally {await rm(temp,{recursive:true,force:true});}
