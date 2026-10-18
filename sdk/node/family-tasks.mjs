// Official A2A v1 Client is supplied by the host. IDs stay separate from authority.
import { randomUUID, sign } from 'node:crypto';
import { canonical, digest, publicBytes, same, exact } from './records.mjs';
export const FAMILY_PROFILE = 'KF-FAMILY-AUTHORITY-0.1-draft';
export const FAMILY_TASK_PROFILE = 'KF-A2A-FAMILY-TASKS-0.1-draft';
export const FAMILY_EXTENSION = 'https://kedgeflow.dev/extensions/family-tasks/v0.1';
const reference = s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const options = {serviceParameters:{'A2A-Version':'1.0','A2A-Extensions':FAMILY_EXTENSION}};
export function signFamilyCommand({registration,operationKey,expectedHead,action,issuedAt,expiresAt,keyId,key}) {
  if (registration.profile !== FAMILY_PROFILE || !reference(operationKey) || !reference(expectedHead) ||
      !Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt ||
      issuedAt < registration.valid_from || expiresAt > registration.expires_at || expiresAt - issuedAt > 60000 ||
      !publicBytes(key).equals(Buffer.from(registration.signers?.[keyId]?.public_key ?? '', 'base64'))) throw new Error('protected family command pins required');
  const fields={delegate:['operation','parent','branch'],attach:['operation','parent','child_id'],stop:['operation','branch_id']}[action?.operation];
  if (!fields) throw new Error('unsupported family command');
  exact(action,fields);
  const unsigned={profile:FAMILY_PROFILE,key_id:keyId,payload:{family_digest:digest('family-registration',registration),operation_key:operationKey,expected_head:expectedHead,issued_at:issuedAt,expires_at:expiresAt,action}};
  if (Buffer.byteLength(canonical(unsigned))>15000) throw new Error('bounded family command required');
  const signature=sign(null,Buffer.from(`KedgeFlow:${FAMILY_PROFILE}:command\0${canonical(unsigned)}`),key).toString('base64url');
  return {...unsigned,signature};
}
function message(data,contextId='',taskId='') {
  return {tenant:'',message:{messageId:randomUUID(),contextId,taskId,role:1,parts:[{content:{$case:'data',value:data},filename:'',mediaType:'application/json'}],extensions:[FAMILY_EXTENSION],referenceTaskIds:[]},configuration:{acceptedOutputModes:['application/json'],returnImmediately:false,historyLength:0}};
}
// Mutations always take a previously signed command. This adapter never chooses
// another operation key or rewrites/re-signs an ambiguous request on its own.
export class FamilyTaskAdapter {
  constructor({client,registration}) {
    if (!client || registration?.profile!==FAMILY_PROFILE || typeof registration.namespace!=='string') throw new Error('approved family and A2A client required');
    this.client=client;
    this.registration=JSON.parse(canonical(registration));
    this.familyDigest=digest('family-registration',this.registration);
    this.contextId=digest('family-task-context',{namespace:this.registration.namespace,registration:this.familyDigest});
  }
  taskId(command) {
    if (command.profile!==FAMILY_PROFILE || command.payload.family_digest!==this.familyDigest || !reference(command.payload.operation_key)) throw new Error('command does not select approved family');
    return digest('family-task-id',{context:this.contextId,operation:command.payload.operation_key});
  }
  async status() {
    const result=await this.client.sendMessage(message({profile:FAMILY_TASK_PROFILE,operation:'status'},this.contextId),options);
    const data=result.parts?.[0]?.content;
    if (result.role!==2 || result.contextId!==this.contextId || data?.$case!=='data') throw new Error('uncorrelated family status');
    const value=data.value;
    exact(value,['profile','operation','familyDigest','familyHead','active','executionAuthority']);
    if (value.profile!==FAMILY_TASK_PROFILE || value.operation!=='status' || value.familyDigest!==this.familyDigest || !reference(value.familyHead) || typeof value.active!=='boolean' || value.executionAuthority!==false) throw new Error('unapproved family status');
    return value;
  }
  validateTask(task,command) {
    if (task.id!==this.taskId(command) || task.contextId!==this.contextId || task.status?.state!==3) throw new Error('uncorrelated coordination task');
    const part=task.artifacts?.find(a=>a.artifactId==='family-command-receipt')?.parts?.[0]?.content;
    const value=part?.value;
    if (part?.$case!=='data' || value.profile!==FAMILY_TASK_PROFILE || value.familyDigest!==this.familyDigest || value.operationKey!==command.payload.operation_key || !same(value.command,command) || value.executionAuthority!==false || value.targetEffectVerified!==false) throw new Error('invalid coordination receipt');
    return task;
  }
  async apply(command) {
    this.taskId(command);
    return this.validateTask(await this.client.sendMessage(message(command,this.contextId),options),command);
  }
  async queryOriginal(command) {
    return this.validateTask(await this.client.getTask({tenant:'',id:this.taskId(command),historyLength:0},options),command);
  }
  async cancelOriginal(command) {
    // This is a standard task request; the peer refuses cancellation of an
    // already committed coordination task and never releases the allocation.
    return this.client.cancelTask({tenant:'',id:this.taskId(command)},options);
  }
}
