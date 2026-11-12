import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {verify,verifyCase} from '../scripts/verify-terraform-gateway-death.mjs';
const root='.cache/terraform-gateway-death-replay',positive=await verify(root),negative=[];
const temp=await mkdtemp(join(tmpdir(),'kf-gateway-death-verifier-'));
try {
 for(const [name,caseName,mutate] of [
  ['wrong-gateway-exit','gateway-kill-drop',(p,n)=>{p.gateway_exit_signal=15;n.injection=p;}],
  ['missing-surviving-provider','gateway-kill-drop',(p,n)=>{p.orphans_after_gateway_death=p.orphans_after_gateway_death.filter(x=>x.pid!==p.provider_pid);n.injection=p;}],
  ['false-terminal-publication','gateway-kill-drop',(p,n)=>{n.counters.ordinary_outcomes=1;}],
  ['promoted-native-phase','gateway-kill-late',(p,n)=>{n.native_state='committed';}],
  ['forward-before-expiry','gateway-kill-late',(p,n)=>{p.gate_completion.forwarded_at_ms=p.grant_expires_at-1;n.injection=p;}],
  ['erased-late-target','gateway-kill-late',(p,n)=>{p.target_after_release.metadata.annotations['kedgeflow.dev/revision']='before';n.injection=p;}]
 ]) {
  const testRoot=join(temp,name);await mkdir(join(testRoot,'cases'),{recursive:true});
  const base=join(testRoot,'cases',caseName);await cp(join(root,'cases',caseName),base,{recursive:true,dereference:true});
  const p=JSON.parse(await readFile(join(base,'gateway-death-proof.json'),'utf8')),n=JSON.parse(await readFile(join(base,'sdk-native-report.json'),'utf8'));mutate(p,n);
  await writeFile(join(base,'gateway-death-proof.json'),JSON.stringify(p));await writeFile(join(base,'sdk-native-report.json'),JSON.stringify(n));
  await assert.rejects(verifyCase(testRoot,caseName));negative.push({name,status:'REFUSED'});
 }
 const result={status:'PASS',positive,negative};await writeFile('.cache/terraform-gateway-death-verifier-tests.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
} finally {await rm(temp,{recursive:true,force:true});}
