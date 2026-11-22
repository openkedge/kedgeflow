#!/usr/bin/env node
// Technical version-one registration candidate; no owner acceptance or writer qualification.
import { readFile, lstat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, digest, exact, privateSeed, publicBytes, recordDigest, signedRecord,
  strictJson } from '../sdk/node/records.mjs';
import { SQL_ACTION, SQL_SCHEMA } from '../sdk/node/sql-leaf.mjs';
import { RESULT_SCHEMA, validateContract } from './cura-sql-evidence.mjs';

export function buildProfile(input, registryKey, cedarSchema) {
  exact(input,['resource','agent','observerKeys','keycloakKeys','until']);
  const resource=input.resource;
  if (resource.id!=='slot-a' || !/^cura-reservation-[a-f0-9]{32}$/.test(resource.incarnation) ||
      input.agent.proposal_key_id!=='urn:kf:cura:agent-proposal:v1' ||
      input.agent.workload!=='spiffe://cura.kedgeflow.internal/agent') throw Error('registered profile');
  const public64=x=>Buffer.from(x,'base64').toString('base64url');
  const keys=input.keycloakKeys.keys.filter(k=>k.kty==='OKP'&&k.crv==='Ed25519'&&k.use==='sig'&&k.alg==='EdDSA');
  if (keys.length!==1 || input.keycloakKeys.keys.some(k=>['d','p','q','dp','dq','qi','k'].some(n=>n in k)))
    throw Error('pinned public issuer key');
  const evidenceKeyId='urn:kf:cura:evidence:v1',manifestKeyId='urn:kf:cura:manifest:v1';
  const predicates=[{kind:'boolean_equals',field:'active',expected:true},
    {kind:'string_equals',field:'version',expected:'1'}];
  const question={id:'cura-pilot:question:reservation-current',
    schema:'urn:kedgeflow:cura:reservation-question:1.0',digest:digest('question',{
      action:SQL_ACTION,resource,expected_version:'1',require_active:true})};
  const resultSchema={id:'cura-pilot:result:reservation-current',
    schema:'urn:kedgeflow:cura:reservation-result:1.0',digest:digest('result-schema',RESULT_SCHEMA)};
  const requirement={obligation:{predicate_digest:digest('evidence-predicate',predicates),
    stage:'jit',execution_relevant:true},provider_id:'cura-pilot:provider:sql-observer',
    provider_version:'1.0',keys:{[evidenceKeyId]:Buffer.from(input.observerKeys.evidence,'base64').toString('hex')},
    question,result_schema_ref:resultSchema,result_schema:RESULT_SCHEMA,max_age_ms:30000,predicates};
  const obligationManifestDigest=digest('obligation-manifest',{profile:'KF-CEDAR-LEAF-0.1-draft',
    obligations:{'reservation-current':requirement}});
  const cedar='permit(principal, action == KedgeFlow::Action::"admit", resource) when { '+
    'context.tenant == "cura-pilot" && context.action_id == "postgres.reservation.set.v1" && '+
    'context.resource_id == "slot-a" && context.policy_epoch == 1 && '+
    'context.obligation_ids.contains("reservation-current") };';
  const policyDefinition={tenant:'cura-pilot',policy_id:'cura-pilot:policy:reservation-v1',cedar,
    obligation_manifest_digest:obligationManifestDigest,max_certificate_lifetime_ms:5000};
  const policy={id:policyDefinition.policy_id,epoch:1,digest:digest('policy',{
    profile:'KF-CEDAR-LEAF-0.1-draft',definition:policyDefinition,schema:cedarSchema})};
  const writerInventory={profile:'kedgeflow-cura-runtime-writer-inventory-v1',resource,
    registered_runtime_writer:'cura-pilot:writer:sql-target',
    privileged_maintenance:['kf-postgres kernel peer administrator','AWS/host operator'],
    runtime_writer_bypass_qualification:'PENDING',independent_resource_owner:'BLOCKED_EXTERNAL_INPUT'};
  const parameterDigest=digest('parameter-schema',SQL_SCHEMA);
  const descriptor={ctd_version:'1.0',id:'cura-pilot:ctd:reservation-set-v1',version:'1.0',
    tenant:'cura-pilot',action:SQL_ACTION,parameter_schema:SQL_SCHEMA,
    parameter_schema_digest:parameterDigest,rendering:{id:'cura-pilot:render:reservation-set',
      version:'1.0',media_type:'text/plain',template_digest:digest('rendering-template',
        'Set the registered reservation if its version still matches.'),
      parameter_schema_digest:parameterDigest,locale:'en-US'},
    consequence_tier:'StateMutating',consequence_tier_number:2,
    consequence_description:'Changes only the registered nonproduction reservation row by version/fence guarded SQL.',
    adapter_contract:{level:'Level_A',guard_primitive:'FencingToken',fence_parameter:'fence',
      guard_scope:[resource.id],completion_mode:'dispatch_bound',
      commit_point:'Registered PostgreSQL reservation transaction commit',
      idempotency:{mode:'resource_key',parameter:'kf_attempt_id',retention_ms:86400000}},
    concurrency:{conflict_domain:'cura-sql-pilot:reservations',predicate_descriptor:{
      id:'cura-pilot:predicate:reservation-version',version:'1.0',language:'kf-conjunction-v1',
      clauses:[{kind:'version_eq',resource,expected_version:'1'}]},
      coverage:{coordinated_writers:['cura-pilot:writer:sql-target'],uncoordinated_writers:[],
        inventory_digest:digest('writer-inventory',writerInventory)}},
    compensation:null,compensation_unavailable_reason:'No inverse action is registered in this SQL pilot.',
    ownership_epoch:1,gateway_audience:'https://services.cura.kedgeflow.internal:8443/mcp'};
  const registryKeyId='urn:kf:cura:registry:v1';
  const descriptorRaw=signedRecord('ctd',descriptor,registryKeyId,registryKey);
  const contract=validateContract({profile:'kedgeflow-cura-sql-observer-v1',tenant:'cura-pilot',resource,
    subject:{iss:'https://identity.cura.kedgeflow.internal:8443/realms/kedgeflow-pilot',
      sub:'d0b36f01-1188-4f01-907a-000000000001'},workload:input.agent.workload,
    proposalKeys:{[input.agent.proposal_key_id]:public64(input.agent.proposal_public_key_base64)},
    descriptorDigest:recordDigest(strictJson(descriptorRaw)),policy,question,resultSchema,
    providerId:requirement.provider_id,evidenceKeyId,manifestKeyId,
    evidencePublicKey:public64(input.observerKeys.evidence),
    manifestPublicKey:public64(input.observerKeys.manifest),
    authorizationKeyId:keys[0].kid,authorizationKey:keys[0].x,
    dpopThumbprint:input.agent.dpop_thumbprint,until:input.until});
  return {format:'kedgeflow-cura-sql-registration-v1',contract,descriptor:descriptorRaw,
    registryKeys:{[registryKeyId]:publicBytes(registryKey).toString('base64url')},
    evidenceKeys:{[evidenceKeyId]:public64(input.observerKeys.evidence)},
    manifestKeys:{[manifestKeyId]:public64(input.observerKeys.manifest)},
    evidenceRequirement:requirement,policyDefinition,obligationManifestDigest,writerInventory,
    owner_acceptance:'BLOCKED_EXTERNAL_INPUT',enterprise_qualified:false,execution_authority:false};
}

async function main(inputPath,seedPath) {
  if(process.platform!=='linux'||process.getuid()===0)throw Error('nonroot registered signer');
  const info=await lstat(seedPath);
  if(!info.isFile()||info.nlink!==1||info.uid!==process.getuid()||(info.mode&0o7777)!==0o400)
    throw Error('registry signing custody');
  const seed=Buffer.from((await readFile(seedPath)).toString(),'base64');
  const input=strictJson(await readFile(inputPath,'utf8'));
  const schema=strictJson(await readFile(new URL('../spec/drafts/cedar-leaf-v0.1.schema.json',import.meta.url),'utf8'));
  console.log(canonical(buildProfile(input,privateSeed(seed),schema)));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv.length!==4){console.log('{"status":"failed","phase":"profile_arguments"}');process.exitCode=1;}
  else main(process.argv[2],process.argv[3]).catch(()=>{
    console.log('{"status":"failed","phase":"protected_registry_signing"}');process.exitCode=1;});
}
