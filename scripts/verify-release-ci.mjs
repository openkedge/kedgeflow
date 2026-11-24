#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { strictJson } from '../sdk/node/records.mjs';
import { readRegular } from './pilot-acceptance-records.mjs';
import { verifyCI } from './release-ci.mjs';
try {
  const {values} = parseArgs({options:{record:{type:'string'},source:{type:'string'}}});
  if (!values.record || !values.source) throw new Error('required_inputs');
  const record = strictJson((await readRegular(resolve(values.record),4<<20)).toString('utf8'));
  const gaps = verifyCI(record,values.source);
  console.log(JSON.stringify({state:gaps.length ? 'blocked' : 'ci_records_verified',
    source_commit:values.source,gaps,execution_authority:false,production_qualified:false},null,2));
  if (gaps.length) process.exitCode=1;
} catch {
  console.log(JSON.stringify({state:'blocked',gaps:['invalid_or_missing_ci_inputs'],
    execution_authority:false,production_qualified:false}));
  process.exitCode=2;
}
