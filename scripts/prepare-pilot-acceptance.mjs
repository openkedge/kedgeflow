#!/usr/bin/env node
// Prepare an unsigned owner request; observations and approvals remain absent.
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { parseArgs } from 'node:util';
import { strictJson } from '../sdk/node/records.mjs';
import { readRegular, prepareRequest } from './pilot-acceptance-records.mjs';
let created;
try {
  const {values} = parseArgs({options:{deployment:{type:'string'},output:{type:'string'}}});
  if (!values.deployment || !values.output) throw new Error('required_inputs');
  const d = strictJson((await readRegular(resolve(values.deployment))).toString('utf8'));
  const request = prepareRequest(d), out = resolve(values.output);
  await mkdir(out,{mode:0o700}); created=out;
  for (const [name,value] of Object.entries({'deployment.json':d,'request.json':request,
    'evidence.json':request.evidence,'approvals.json':request.approvals})) {
    await writeFile(join(out,name),JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
  }
  await mkdir(join(out,'artifacts'),{mode:0o700});
  console.log(JSON.stringify({state:request.state,deployment_digest:request.deployment_digest,
    required_owner_roles:request.required_owner_roles,execution_authority:false,production_qualified:false},null,2));
} catch {
  if (created) await rm(created,{recursive:true,force:true});
  console.log(JSON.stringify({state:'blocked',reason:'invalid_inputs_or_existing_output',
    execution_authority:false,production_qualified:false}));
  process.exitCode=1;
}
