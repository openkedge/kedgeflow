#!/usr/bin/env node
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { evaluate } from './pilot-acceptance-records.mjs';
try {
  const {values} = parseArgs({options:{directory:{type:'string'},trust:{type:'string'},
    'trust-sha256':{type:'string'},'deployment-digest':{type:'string'}}});
  if (!values.directory || !values.trust || !values['trust-sha256'] || !values['deployment-digest']) {
    throw new Error('required_inputs');
  }
  const report = await evaluate(resolve(values.directory),{trustFile:resolve(values.trust),
    trustSha256:values['trust-sha256'],expectedDeployment:values['deployment-digest']});
  console.log(JSON.stringify(report,null,2));
  if (report.state !== 'owner_records_verified') process.exitCode=1;
} catch {
  console.log(JSON.stringify({state:'blocked',reason:'required_or_invalid_arguments',
    execution_authority:false,production_qualified:false}));
  process.exitCode=2;
}
