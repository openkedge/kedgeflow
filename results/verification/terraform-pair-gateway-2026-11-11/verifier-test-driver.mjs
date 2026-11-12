import assert from 'node:assert/strict';
import { mkdtemp, mkdir, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verify } from '../scripts/verify-terraform-pair-gateway.mjs';
import { verifyCase } from '../scripts/verify-terraform-pair.mjs';
const root = '.cache/terraform-pair-gateway-replay';
const positive = await verify(root), negative = [];
const temp = await mkdtemp(join(tmpdir(), 'kf-pair-gateway-verifier-'));
const edit = async (base, file, mutate) => { const p = join(base,file), value=JSON.parse(await readFile(p,'utf8')); mutate(value); await writeFile(p, JSON.stringify(value)); };
try {
  for (const [name, caseName, mutate] of [
    ['altered-target','normal', async b => edit(b,'target-raw-observation.json',v=>v.members[0].object.metadata.annotations['kedgeflow.dev/revision']='other')],
    ['partial-promoted','partial', async b => edit(b,'sdk-native-report.json',v=>v.native_state='committed')],
    ['false-lost-reply','lost', async b => edit(b,'sdk-native-report.json',v=>v.first.lost_reply_bytes=0)],
    ['second-dispatch','partial-lost', async b => edit(b,'sdk-native-report.json',v=>v.counters.dispatches=2)],
    ['audit-order','partial', async b => {
      for (const f of ['audit-events.json','audit-events-after-query.json']) await edit(b,f,v=>v[1].requestReceivedTimestamp='2000-01-01T00:00:00Z');
      await edit(b,'sdk-native-report.json',v=>{for (const k of ['audit_before_queries','audit_after_queries']) v[k][1].requestReceivedTimestamp='2000-01-01T00:00:00Z';});
    }]
  ]) {
    const testRoot = join(temp,name); await mkdir(join(testRoot,'cases'),{recursive:true});
    const base=join(testRoot,'cases',caseName);await cp(join(root,'cases',caseName),base,{recursive:true,dereference:true});await mutate(base);
    await assert.rejects(verifyCase(testRoot,caseName,{gateway:true}));negative.push({name,status:'REFUSED'});
  }
  const result={status:'PASS',positive,negative};await writeFile('.cache/terraform-pair-gateway-verifier-tests.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
} finally { await rm(temp,{recursive:true,force:true}); }
