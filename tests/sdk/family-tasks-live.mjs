import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { ListTasksRequest } from '@a2a-js/sdk';
import { ClientFactory, JsonRpcTransportFactory, DefaultAgentCardResolver } from '@a2a-js/sdk/client';
import { FamilyTaskAdapter, signFamilyCommand, FAMILY_EXTENSION } from '../../sdk/node/family-tasks.mjs';
import { familyTaskFetch } from '../../sdk/node/family-task-transport.mjs';
import { privateSeed, strictJson } from '../../sdk/node/records.mjs';
const f=strictJson(await readFile(process.argv[2],'utf8'));
const pinned=familyTaskFetch({tls:f.tls,endpoint:f.url,tokenProvider:async()=>f.token,dpopKey:privateSeed(Buffer.alloc(32,8)),now:()=>f.now});
await assert.rejects(pinned('https://elsewhere.invalid/a2a',{method:'POST',body:'{}'}),/unapproved/);
const wire=[];let lost=false;
const fetch=async(input,init={})=>{
  const body=init.body?strictJson(init.body):null;
  wire.push({method:body?.method??'card',grantHeader:new Headers(init.headers).has('Mcp-KedgeFlow-Grant')});
  const response=await pinned(input,init);
  // The command has committed before this response is intentionally lost.
  if(f.mode==='lost'&&body?.method==='SendMessage'&&body.params.message.parts[0].data.operation===undefined&&!lost){await response.arrayBuffer();lost=true;throw new Error('lost original task reply');}
  return response;
};
const factory=new ClientFactory({transports:[new JsonRpcTransportFactory({fetchImpl:fetch})],cardResolver:new DefaultAgentCardResolver({fetchImpl:fetch})});
const client=await factory.createFromUrl(new URL(f.url).origin);
const adapter=new FamilyTaskAdapter({client,registration:f.registration});
const status=await adapter.status();assert.equal(status.executionAuthority,false);
const command=f.command??signFamilyCommand({registration:f.registration,operationKey:'1'.repeat(64),expectedHead:status.familyHead,action:{operation:'attach',parent:'root',child_id:'child-0'},issuedAt:f.now,expiresAt:f.now+30000,keyId:'owner',key:privateSeed(Buffer.alloc(32,31))});
let task;
if(f.mode==='query')task=await adapter.queryOriginal(command);
else if(f.mode==='lost'){await assert.rejects(adapter.apply(command));assert(lost);task=await adapter.queryOriginal(command);const replay=await adapter.apply(command);assert.equal(replay.id,task.id);}
else task=await adapter.apply(command);
assert.equal(task.id,adapter.taskId(command));
assert.equal((await adapter.queryOriginal(command)).id,task.id);
await assert.rejects(adapter.cancelOriginal(command),e=>e.envelopeCode===-32002&&e.reason==='TASK_NOT_CANCELABLE');
const page=await client.listTasks(ListTasksRequest.fromJSON({pageSize:10,contextId:adapter.contextId,historyLength:0,includeArtifacts:true}),{serviceParameters:{'A2A-Version':'1.0','A2A-Extensions':FAMILY_EXTENSION}});
assert(page.tasks.some(t=>t.id===task.id));
assert(wire.every(r=>!r.grantHeader));
assert.equal(wire.filter(r=>r.method==='card').length,1);
console.log(JSON.stringify({status:'PASS',sdk:'@a2a-js/sdk',version:'1.0.1',mode:f.mode,taskId:task.id,command,wire}));
