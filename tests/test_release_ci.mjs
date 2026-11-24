import test from 'node:test';
import assert from 'node:assert/strict';
import { REQUIRED_JOBS, REQUIRED_STEPS, verifyCI } from '../scripts/release-ci.mjs';
export function ciFixture(source='a'.repeat(40)) {
  return {run:{repository:{full_name:'openkedge/kedgeflow'},path:'.github/workflows/ci.yml',
    head_sha:source,id:123,run_attempt:1,status:'completed',conclusion:'success'},
  jobs:{total_count:REQUIRED_JOBS.length,jobs:REQUIRED_JOBS.map((name,i)=>({
    name,id:1000+i,run_id:123,run_attempt:1,head_sha:source,status:'completed',conclusion:'success',
    steps:REQUIRED_STEPS[name].map(name=>({name,status:'completed',conclusion:'success'})),
  }))}};
}
test('complete same-source qualification accepts only as CI records',()=>{
  assert.deepEqual(verifyCI(ciFixture(),'a'.repeat(40)),[]);
});
for (const [name,mutate] of Object.entries({
  'wrong source':r=>r.run.head_sha='b'.repeat(40),
  'wrong repository':r=>r.run.repository.full_name='fork/kedgeflow',
  'wrong workflow':r=>r.run.path='.github/workflows/fake.yml',
  'pending run':r=>r.run.status='in_progress',
  'red run':r=>r.run.conclusion='failure',
  'truncated job response':r=>r.jobs.total_count++,
  'missing required job':r=>{r.jobs.jobs.pop();r.jobs.total_count--;},
  'duplicate jobs':r=>r.jobs.jobs[1]=r.jobs.jobs[0],
  'old rerun':r=>r.jobs.jobs[0].run_attempt=2,
  'mixed commit':r=>r.jobs.jobs[0].head_sha='b'.repeat(40),
  'skipped identity':r=>r.jobs.jobs.find(j=>j.name==='selfhosted-identity').conclusion='skipped',
  'deleted qualification step':r=>r.jobs.jobs[1].steps.pop(),
  'skipped qualification step':r=>r.jobs.jobs[1].steps[0].conclusion='skipped',
  'unknown failed step':r=>r.jobs.jobs[1].steps.push({name:'new required test',status:'completed',conclusion:'failure'}),
})) test(name+' blocks release',()=>{
  const r=ciFixture();mutate(r);assert(verifyCI(r,'a'.repeat(40)).length>0);
});
test('skipped GitHub post-cache hook does not hide qualification skips',()=>{
  const r=ciFixture();r.jobs.jobs[0].steps.push({name:'Post cache',status:'completed',conclusion:'skipped'});
  assert.deepEqual(verifyCI(r,'a'.repeat(40)),[]);
});
