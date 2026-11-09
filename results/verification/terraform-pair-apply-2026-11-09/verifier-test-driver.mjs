import {mkdtemp,mkdir,cp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';
import {verify,verifyCase} from '../scripts/verify-terraform-pair.mjs';
const root=await mkdtemp(join(tmpdir(),'kf-pair-verifier-'));
const result={status:'PASS',positive:null,negative:[]};
try {
 await mkdir(join(root,'cases'));
 for(const name of ['normal','partial','partial-lost']) await cp(resolve('.cache/terraform-pair-apply-complete2',name),join(root,'cases',name),{recursive:true});
 result.positive=await verify(root);
 async function bad(name,file,mutate,label){const path=join(root,'cases',name,file),saved=await readFile(path,'utf8');let value=JSON.parse(saved);mutate(value);await writeFile(path,JSON.stringify(value));let refused=false;try{await verifyCase(root,name);}catch{refused=true;}await writeFile(path,saved);if(!refused)throw Error('accepted '+label);result.negative.push({case:label,refused:true});}
 await bad('partial','audit-events.json',v=>v[1].requestReceivedTimestamp=v[0].requestReceivedTimestamp,'audit order/correlation changed');
 await bad('partial','target-raw-observation.json',v=>v.members[1].object.metadata.annotations['kedgeflow.dev/revision']='after','target observation changed');
 await bad('partial','pair-native-report.json',v=>{v.report.intent.state='applied';v.cold.intent.state='applied';v.report.status='committed';v.cold.status='committed';v.native_state='committed';},'partial promoted to committed');
 await bad('partial-lost','pair-native-report.json',v=>v.first_reply_bytes=1,'reply was available despite lost claim');
 await writeFile('.cache/terraform-pair-verifier-tests.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
} finally {await rm(root,{recursive:true});}
