#!/usr/bin/env node
// Public configuration rendering only. No secret reading, signing or authority writes.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, exact, recordDigest, same, strictJson, verifyRecord } from '../sdk/node/records.mjs';

const SERVICES='https://services.cura.kedgeflow.internal';
const SQL='https://sql.cura.kedgeflow.internal:8451';
const AUDIENCE='urn:kedgeflow:delegated-admission';
const PURPOSES=['admission','issuer','target-token','gateway-ack','receipt',
  'publish-policy','register-descriptor','install','revoke','identity-refresh'];
const SCOPES=['reservation:request','kf.admit','kf.issue','kf.status','kf.evidence'];
const ADMIN=['publish_policy','register_descriptor','install','revoke','query'];
const b64=x=>Buffer.from(x,'base64url').toString('base64');
const root=role=>`/etc/kedgeflow/${role}`;
const file=(role,name)=>`${root(role)}/${name}`;
const clone=x=>strictJson(canonical(x));

export function buildConfigs(input, stopUTC, now=Date.now()) {
  // A runtime bound is not an approval or a replacement for a signed registration.
  const deadline=typeof stopUTC==='string'?Date.parse(stopUTC):NaN;
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(stopUTC)||
      !Number.isFinite(now)||!Number.isFinite(deadline)||
      new Date(deadline).toISOString().replace('.000Z','Z')!==stopUTC||
      !(now<deadline&&deadline<=now+86400000))
    throw Error('explicit future stop UTC within 24 hours required');
  exact(input,['registration','operator','purposeKeys','nativeRegistration']);
  const {registration:r,operator,purposeKeys:keys,nativeRegistration:native}=input;
  const requiredPurposes=native===null&&!Object.hasOwn(keys,'identity-refresh')?
    PURPOSES.filter(p=>p!=='identity-refresh'):PURPOSES;
  exact(keys,requiredPurposes);
  const contract=r.contract;
  const descriptor=verifyRecord(r.descriptor,'ctd',r.registryKeys);
  const d=descriptor.payload;
  if(r.format!=='kedgeflow-cura-sql-registration-v1'||r.enterprise_qualified!==false||
      recordDigest(descriptor)!==contract.descriptorDigest||d.tenant!=='cura-pilot'||
      d.action!=='postgres.reservation.set.v1'||d.gateway_audience!==`${SERVICES}:8443/mcp`||
      d.concurrency.conflict_domain!=='cura-sql-pilot:reservations'||
      d.concurrency.predicate_descriptor.clauses.length!==1||
      d.concurrency.predicate_descriptor.clauses[0].expected_version!=='1'||
      !same(d.concurrency.predicate_descriptor.clauses[0].resource,contract.resource)||
      contract.resource.id!=='slot-a'||contract.until!==deadline||
      contract.tenant!=='cura-pilot'||
      contract.subject.iss!=='https://identity.cura.kedgeflow.internal:8443/realms/kedgeflow-pilot'||
      contract.subject.sub!=='d0b36f01-1188-4f01-907a-000000000001'||
      contract.workload!=='spiffe://cura.kedgeflow.internal/agent'||
      operator.profile!=='kedgeflow-cura-technical-operator-enrollment-v1'||
      operator.status!=='technical_operator_enrolled'||operator.client_id!=='kf-pilot-operator'||
      operator.dpop_required!==true||operator.token_lifetime_seconds!==120||
      operator.independent_acceptor!==false||operator.subject.iss!==contract.subject.iss||
      operator.subject.sub===contract.subject.sub||
      operator.workload!=='spiffe://cura.kedgeflow.internal/operator'||
      !same([...operator.scopes].sort(),ADMIN.map(x=>'kf.'+x).sort()))
    throw Error('exact enrolled SQL/operator contract required');
  const occupied=new Set([...Object.values(contract.proposalKeys),...Object.values(r.registryKeys),
    ...Object.values(r.manifestKeys),...Object.values(r.evidenceKeys),contract.authorizationKey]);
  for(const purpose of requiredPurposes) {
    exact(keys[purpose],['key_id','public_key_base64']);
    const {key_id:id,public_key_base64:publicKey}=keys[purpose];
    const raw=Buffer.from(publicKey,'base64');
    if(id!==`urn:kf:cura:${purpose}:v1`||raw.length!==32||raw.toString('base64')!==publicKey||
        occupied.has(raw.toString('base64url')))throw Error('distinct purpose-bound public pins required');
    occupied.add(raw.toString('base64url'));
  }
  const keyMap=purpose=>({[keys[purpose].key_id]:keys[purpose].public_key_base64});
  const tls=role=>({certificate:file(role,'identity.pem'),private_key:file(role,'identity.key'),
    workload_ca:file(role,'workload-ca.pem')});
  const ledger=role=>({etcd_endpoint:'https://ledgera.cura.kedgeflow.internal:2379',
    etcd_prefix:'/kedgeflow/cura',etcd_ca:file(role,'ca.pem'),
    etcd_certificate:file(role,'identity.pem'),etcd_private_key:file(role,'identity.key'),
    etcd_token_file:file(role,'credentials/primary.token'),restore_gate:{
      endpoint:'https://witness.cura.kedgeflow.internal:2379',prefix:'/kedgeflow/cura',
      ca:file(role,'ca.pem'),certificate:file(role,'identity.pem'),private_key:file(role,'identity.key'),
      token_file:file(role,'credentials/witness.token')}});
  const shared=(subject,workload,scopes)=>({capacity:256,registrations:[{
    subject,workload_id:workload,allowed_scopes:scopes}]});
  const identity=client=>({profile:'KF-KEYCLOAK-SPIRE-0.1-pilot',client_id:client});
  const evidence=clone(r.evidenceRequirement);
  evidence.keys=Object.fromEntries(Object.entries(r.evidenceKeys).map(([id,key])=>[id,b64(key)]));
  const control=role=>({runtime_role:role==='governance'?'combined':role,
    identity_profile:identity(role==='governance'?'kf-pilot-operator':'kf-pilot-agent'),
    listen:`0.0.0.0:${role==='issuer'?9448:role==='governance'?9444:9443}`,
    admission_url:`${SERVICES}:9443/admission`,issuance_url:`${SERVICES}:9448/issuance`,
    status_url:`${SERVICES}:${role==='admission'?9443:9448}/status`,
    status_scope:'kf.status',delegation_audience:AUDIENCE,
    gateway_audience:d.gateway_audience,...tls(role),...ledger(role),
    shared_auth:role==='governance'?shared(operator.subject,operator.workload,operator.scopes):
      shared(contract.subject,contract.workload,SCOPES),
    oidc_issuer:contract.subject.iss,oidc_public_key_base64:b64(contract.authorizationKey),
    admission_key_id:keys.admission.key_id,issuer_key_id:keys.issuer.key_id,
    admission_verification_key_base64:keys.admission.public_key_base64,
    issuer_verification_key_base64:keys.issuer.public_key_base64,
    ...(role==='admission'?{admission_signing_key_file:file(role,'admission.seed')}:
      role==='issuer'?{issuer_signing_key_file:file(role,'issuer.seed')}:
        {admission_signing_key_file:'',issuer_signing_key_file:''}),
    tenant:contract.tenant,workload_id:contract.workload,subjects:[contract.subject],
    admission_scope:'kf.admit',issuance_scope:'kf.issue',action_scope:'reservation:request',
    proposal_keys:Object.fromEntries(Object.entries(contract.proposalKeys).map(([id,key])=>[id,b64(key)])),
    registry_keys:Object.fromEntries(Object.entries(r.registryKeys).map(([id,key])=>[id,b64(key)])),
    manifest_keys:Object.fromEntries(Object.entries(r.manifestKeys).map(([id,key])=>[id,b64(key)])),
    descriptor_digest:contract.descriptorDigest,ownership_epoch:d.ownership_epoch,max_proposal_age_ms:60000,
    policy:{id:contract.policy.id,epoch:contract.policy.epoch,cedar:r.policyDefinition.cedar,
      max_certificate_lifetime_ms:r.policyDefinition.max_certificate_lifetime_ms},
    evidence:{'reservation-current':evidence},require_control:true});
  const action={id:d.action,version:'1.0',digest:contract.descriptorDigest};
  const scope={conflict_domain:d.concurrency.conflict_domain,action,resource:contract.resource,
    audience:d.gateway_audience,adapter_contract:d.adapter_contract,
    predicate_descriptor:d.concurrency.predicate_descriptor};
  const governance={listen:'0.0.0.0:9444',external_url:`${SERVICES}:9444/enforcement`,
    control:control('governance'),scope,admission_keys:keyMap('admission'),issuer_keys:keyMap('issuer'),
    acknowledger:{component_id:'cura-sql-gateway',workload_id:'spiffe://cura.kedgeflow.internal/gateway',
      key_id:keys['gateway-ack'].key_id,
      public_key_hex:Buffer.from(keys['gateway-ack'].public_key_base64,'base64').toString('hex'),
      max_lifetime_ms:30000},roles:Object.fromEntries(ADMIN.map(role=>[role,{
        subject:operator.subject,workload_id:operator.workload,scope:'kf.'+role,
        keys:role==='query'?{}:keyMap(role.replaceAll('_','-'))}]))};
  const result={profile:'kedgeflow-cura-native-config-candidate-v1',
    configurations:{admission:control('admission'),issuer:control('issuer'),governance},
    execution_authority:false,enterprise_qualified:false,owner_acceptance:'BLOCKED_EXTERNAL_INPUT'};
  if(native===null)return result;
  if(native.tenant!==contract.tenant||!same(native.scope,scope)||
      !same(native.policy,contract.policy)||native.obligation_manifest_digest!==r.obligationManifestDigest||
      !same(native.issuer_keys,{[keys.issuer.key_id]:Buffer.from(keys.issuer.public_key_base64,'base64').toString('hex')})||
      native.ownership_epoch!==d.ownership_epoch||!same(native.acknowledger,governance.acknowledger)||
      !/^[a-f0-9]{64}$/.test(native.trust_digest))throw Error('native registration binding differs');
  const registration={tenant:contract.tenant,conflict_domain:scope.conflict_domain,action,
    resource:scope.resource,adapter_contract:scope.adapter_contract,
    predicate_id:scope.predicate_descriptor.id,predicate_version:scope.predicate_descriptor.version,
    gateway_workload:governance.acknowledger.workload_id,query_workload:'spiffe://cura.kedgeflow.internal/recovery',
    target_audience:`${SQL}/dispatch`,target_scope:'reservation:write'};
  const tool={name:'postgres_reserve',read_only:false,required_scope:'reservation:request',
    action,resource:scope.resource,conflict_domain:scope.conflict_domain,adapter_contract:scope.adapter_contract,
    predicate_id:registration.predicate_id,predicate_version:registration.predicate_version,
    version_parameter:'expected_version',fence_parameter:'fence',
    admission_endpoint:`${SERVICES}:9443/admission`,status_scope:'kf.status'};
  result.configurations.target={listen:'0.0.0.0:8451',dispatch_url:`${SQL}/dispatch`,query_url:`${SQL}/query`,
    ...tls('sql-target'),database:{socket_directory:'/run/kedgeflow-postgres',port:5432,database:'kedgeflow',
      executor_user:'kf_executor',query_user:'kf_reader'},gateway_audience:d.gateway_audience,
    grant_keys:keyMap('issuer'),token_issuer:`${SERVICES}:8448/token`,target_keys:keyMap('target-token'),
    query_token_file:file('sql-target','query.token'),registration};
  const gatewayLedger=ledger('gateway');
  delete gatewayLedger.etcd_endpoint;delete gatewayLedger.etcd_certificate;delete gatewayLedger.etcd_private_key;
  result.configurations.gateway={listen:'0.0.0.0:8443',external_url:d.gateway_audience,...tls('gateway'),
    ...gatewayLedger,etcd_endpoints:['ledgera','ledgerb','ledgerc'].map(x=>`https://${x}.cura.kedgeflow.internal:2379`),
    identity_profile:identity('kf-pilot-agent'),grant_key_id:keys.issuer.key_id,
    grant_public_key_base64:keys.issuer.public_key_base64,oidc_issuer:contract.subject.iss,
    oidc_public_key_base64:b64(contract.authorizationKey),delegation_audience:AUDIENCE,
    shared_auth:shared(contract.subject,contract.workload,SCOPES),broker_endpoint:`${SERVICES}:8448/token`,
    broker_ca:file('gateway','ca.pem'),grant_resolver_endpoint:'',grant_resolver_ca:'',
    target_audience:registration.target_audience,target_scope:registration.target_scope,
    actor_workload:contract.workload,actor_token_file:file('gateway','actor.jwt'),
    target_url:`${SQL}/dispatch`,target_ca:file('gateway','ca.pem'),read_token_file:'',tools:[tool],
    require_control:true,enforcement:{control_url:governance.external_url,
      control_ca:file('gateway','ca.pem'),installation_keys:keyMap('install'),
      component_id:governance.acknowledger.component_id,workload_id:registration.gateway_workload,
      acknowledgement_key_file:file('gateway','gateway-ack.seed')},
    postgres_adapter:{profile:'KF-POSTGRES-LEAF-0.1-draft',registration,
      token_issuer:`${SERVICES}:8448/token`,target_keys:keyMap('target-token')}};
  result.configurations.broker={listen:'0.0.0.0:8448',external_url:`${SERVICES}:8448/token`,
    ...tls('broker'),...ledger('broker'),identity_profile:identity('kf-pilot-agent'),
    gateway_audience:d.gateway_audience,delegation_audience:AUDIENCE,grant_keys:keyMap('issuer'),
    registration:{gateway_workload:registration.gateway_workload,target_audience:registration.target_audience,
      target_scope:registration.target_scope,max_lifetime_ms:5000,tool},
    target_key_id:keys['target-token'].key_id,target_signing_key_file:file('broker','target-token.seed'),
    target_verification_keys:keyMap('target-token'),allow_unmanaged_fixture:false,
    installed_trust_digest:native.trust_digest,identity_refresh:{
      authority_id:'cura-pilot:identity-refresh',issuer:contract.subject.iss,
      authority_keys:keyMap('identity-refresh'),signed_snapshot_file:file('broker','identities.signed.json'),
      head_file:file('broker','identity-head.json'),minimum_epoch_file:file('broker','identity-floor')}};
  result.configurations.recovery={...ledger('recovery'),gateway_audience:d.gateway_audience,
    grant_keys:keyMap('issuer'),query_url:`${SQL}/query`,query_ca:file('recovery','ca.pem'),
    query_certificate:file('recovery','identity.pem'),query_private_key:file('recovery','identity.key'),
    query_token_file:file('recovery','query.token'),receipt_key_id:keys.receipt.key_id,
    receipt_signing_key_file:file('recovery','receipt.seed'),source_id:registration.query_workload,
    page_size:16,poll_interval_ms:1000};
  return result;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv.length!==4){console.log('{"status":"failed","phase":"native_config_arguments"}');process.exitCode=1;}
  else readFile(process.argv[2],'utf8').then(raw=>console.log(canonical(buildConfigs(strictJson(raw),process.argv[3]))))
    .catch(()=>{console.log('{"status":"failed","phase":"public_native_config_binding"}');process.exitCode=1;});
}
