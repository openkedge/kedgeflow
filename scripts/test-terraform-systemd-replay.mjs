#!/usr/bin/env node
// Mutate copied public records; never execute tools, read secrets or contact targets.
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { verify } from './verify-terraform-systemd.mjs';
const original=resolve(process.argv[2]);
assert.equal((await verify(original)).status,'PASS');
const tests=[
 ['wrong-kill-mode',async edit=>edit('service-starts.jsonl',x=>{x[0].properties.KillMode='process';})],
 ['cgroup-delegation',async edit=>edit('service-starts.jsonl',x=>{x[0].properties.Delegate='yes';})],
 ['same-agent-uid',async edit=>edit('host.json',x=>{x.agent_uid=x.uid;})],
 ['agent-writer-readable',async edit=>edit('service-starts.jsonl',x=>{x[0].custody_probes.find(p=>p.resource==='writer').agent_read_refused=false;})],
 ['unproven-readonly-refusal',async edit=>edit('service-starts.jsonl',x=>{x[0].custody_probes.find(p=>p.service_write_refused).errno='EPERM';})],
 ['old-cgroup-survives',async (edit,proof)=>proof('cgroup-drop',p=>{p.systemd.old_group_empty=false;})],
 ['detached-child-survives',async (edit,proof)=>proof('cgroup-drop',p=>{p.systemd.escaped_process_terminated=false;})],
 ['fixture-killed-group',async (edit,proof)=>proof('cgroup-drop',p=>{p.systemd.fixture_group_kill=true;})],
 ['late-effect-before-expiry',async (edit,proof)=>proof('cgroup-late',p=>{p.gate_completion.forwarded_at_ms=p.grant_expires_at-1;})],
 ['false-outcome-publication',async (edit,proof)=>{
   await proof('cgroup-late',p=>{p.native_counts.ordinary_outcomes=1;});
   await edit('cases/cgroup-late/sdk-native-report.json',n=>{n.counters.ordinary_outcomes=1;});
 }],
 ['repeated-dispatch',async (edit,proof)=>{
   await proof('cgroup-drop',p=>{p.native_counts.dispatches=2;});
   await edit('cases/cgroup-drop/sdk-native-report.json',n=>{n.counters.dispatches=2;});
 }],
 ['cold-query-mutates',async edit=>edit('cases/cgroup-late/sdk-native-report.json',n=>{n.resumed.wire.push({method:'tools/call',grantPresent:true});})],
];
const outcomes=[];
for(const [name,mutate] of tests) {
 const dir=await mkdtemp(join(tmpdir(),'kf-systemd-replay-'));
 try {
  await cp(original,dir,{recursive:true});
  const edit=async (path,change)=>{
   const file=join(dir,path),lines=path.endsWith('.jsonl');
   const raw=await readFile(file,'utf8');
   const value=lines?raw.trim().split('\n').map(x=>JSON.parse(x)):JSON.parse(raw);
   change(value);
   await writeFile(file,lines?value.map(x=>JSON.stringify(x)).join('\n')+'\n':JSON.stringify(value));
  };
  const proof=async (which,change)=>{
   await edit(`cases/${which}/systemd-proof.json`,change);
   await edit(`cases/${which}/sdk-native-report.json`,n=>change(n.injection));
  };
  await mutate(edit,proof);
  await assert.rejects(verify(dir),undefined,name);
  outcomes.push({name,rejected:true});
 } finally {await rm(dir,{recursive:true,force:true});}
}
console.log(JSON.stringify({status:'PASS',positive_records:1,negative_records:outcomes.length,outcomes},null,2));
