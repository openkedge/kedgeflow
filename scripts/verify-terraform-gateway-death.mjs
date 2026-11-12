#!/usr/bin/env node
// Read-only replay of local active-child evidence; no authority or attestation.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { digest, canonical, strictJson } from '../sdk/node/records.mjs';
const load = async p => strictJson(await readFile(p,'utf8'));
const equal = (a,b,m) => assert.equal(canonical(a),canonical(b),m);
const hash = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
export async function verifyCase(root,name) {
  const base=join(root,'cases',name);
  const [m,plan,inspection,n,p,targets,events,afterEvents,state] = await Promise.all(['manifest.json','inspection.json','report.json','sdk-native-report.json','gateway-death-proof.json','target-observation.json','audit-events.json','audit-events-after-query.json','state.json'].map(f=>load(join(base,f))));
  equal(n.injection,p,'inconsistent intervention proof');
  const late=name==='gateway-kill-late';
  const [registration,descriptor,grant,traces] = await Promise.all(['sdk-registration.json','sdk-descriptor.json','sdk-grant-payload.json','gate-requests.json'].map(f=>load(join(base,f))));
  const {validateTerraformDescriptor,validateTerraformGrant} = await import('../sdk/node/terraform.mjs');
  const parameters={node:registration.resource.id,expected_version:1,manifest_digest:registration.manifestDigest,effect_digest:registration.effectDigest};
  validateTerraformDescriptor(descriptor,registration);validateTerraformGrant(descriptor,grant,parameters,registration);
  assert.equal(grant.root_id,n.intent.root_id);assert.equal(grant.expires_at,p.grant_expires_at);
  assert.equal(registration.manifestDigest,n.intent.manifest_digest);assert.equal(registration.effectDigest,n.intent.effect_digest);assert.equal(registration.inspectionSha256,inspection.inspection_sha256);
  assert.equal(registration.resource.incarnation,m.target.uid);
  const requests=traces.filter(t=>t.method!=='GET');assert.equal(requests.length,1);
  assert.equal(requests[0].method,p.active_request.method);assert.equal(requests[0].path,p.active_request.path);
  assert.equal(requests[0].status,late?200:null);
  assert(['gateway-kill-drop','gateway-kill-late'].includes(name));
  assert.equal(m.profile,'KF-TERRAFORM-PLAN-0.2-draft');
  const manifest=digest('terraform-plan-manifest',m);
  assert.equal(manifest,inspection.manifest_digest);
  assert.equal(n.intent.manifest_digest,manifest);
  assert.equal(n.intent.effect_digest,digest('terraform-plan-effect',{address:'kubernetes_config_map_v1.target',before:plan.resource_changes[0].change.before,after:plan.resource_changes[0].change.after}));
  assert.equal(n.intent.effect_digest,inspection.effect_digest);
  assert.equal(n.intent.profile,'KF-TERRAFORM-APPLY-0.1-draft');
  assert(!Object.hasOwn(n.intent,'pair'));
  assert.equal(n.native_state,'dispatch_authorized');
  assert.equal(n.intent.state,'started');
  equal(n.intent,p.initial_intent);
  assert.equal(n.intent.backend_after_sha256,null);
  assert.equal(n.intent.observed_after_digest,null);
  assert.equal(p.initial_intent.state,'started');
  for (const k of ['profile','manifest_digest','effect_digest','grant_digest','root_id','attempt_id','initiated_at','backend_before_sha256']) equal(p.initial_intent[k],n.intent[k]);
  assert(['unavailable','dispatch_authorized'].includes(n.first.state));
  assert.equal(n.first.grant_digest,n.intent.grant_digest);
  if(n.first.state==='dispatch_authorized') assert.equal(n.first.attempt_id,n.intent.attempt_id);
  else assert.equal(n.first.attempt_id,null);
  assert.equal(n.resumed.state,'dispatch_authorized');assert.equal(n.resumed.attempt_id,n.intent.attempt_id);assert.equal(n.resumed.grant_digest,n.intent.grant_digest);
  for(const k of ['claims','permits','dispatches','intents','intent_requests']) assert.equal(n.counters[k],1);
  for(const k of ['intent_outcomes','ordinary_outcomes']) assert.equal(n.counters[k],0);
  assert.equal(n.retained_history_unchanged,true);
  for (const k of ['grant_expired_at_query','domain_revoked_at_query','broker_stopped_at_query','writer_absent_at_query']) assert.equal(n[k],true);
  assert.equal(n.first.wire.filter(w=>w.method==='tools/call'&&w.grantPresent).length,1);
  assert.equal(n.resumed.wire.filter(w=>['tools/call','admit','issue'].includes(w.method)).length,0);
  assert(n.resumed.wire.filter(w=>w.method==='kedgeflow/status').every(w=>!w.grantPresent));
  const pids=[p.gateway_pid,p.terraform_pid,p.provider_pid];
  assert(pids.every(x=>Number.isSafeInteger(x)&&x>1));assert.equal(new Set(pids).size,3);
  assert.equal(p.terraform_parent,p.gateway_pid);assert.equal(p.provider_parent,p.terraform_pid);assert.equal(p.process_group,p.terraform_pid);
  assert(typeof p.terraform_state==='string'&&!p.terraform_state.startsWith('Z'));
  assert(typeof p.provider_state==='string'&&!p.provider_state.startsWith('Z'));
  assert.equal(p.profile,'KF-TERRAFORM-GATEWAY-DEATH-EVIDENCE-0.1-test');
  assert.equal(p.gateway_exit_signal,9);
  assert.equal(p.no_live_group_at_fixture_end,true);
  assert.equal(p.native_phase_after_effect,'dispatch_authorized');assert.equal(p.native_outcome_publications,0);
  assert.equal(typeof p.fixture_group_kill,'boolean');if(!late) assert.equal(p.fixture_group_kill,true);
  const orphans=p.orphans_after_gateway_death;
  equal(orphans.map(x=>x.pid).sort((a,b)=>a-b),[p.terraform_pid,p.provider_pid].sort((a,b)=>a-b));
  assert.equal(orphans.find(x=>x.pid===p.terraform_pid).name,'terraform');
  assert.equal(orphans.find(x=>x.pid===p.provider_pid).name,'terraform-provider-kubernetes_v2.38.0_x5');
  assert(Array.isArray(p.group_at_expiry));
  for(const row of p.group_at_expiry) {assert([p.terraform_pid,p.provider_pid].includes(row.pid));assert.equal(row.group,p.process_group);assert(!row.state.startsWith('Z'));}
  if(!late) equal(p.group_at_expiry,[]);
  for(const pid of [p.terraform_pid,p.provider_pid]) {
    const row=orphans.find(x=>x.pid===pid);assert(row);assert.equal(row.group,p.process_group);assert(!row.state.startsWith('Z'));
  }
  assert.notEqual(orphans.find(x=>x.pid===p.terraform_pid).parent,p.gateway_pid);
  assert.equal(orphans.find(x=>x.pid===p.provider_pid).parent,p.terraform_pid);
  const e=p.active_request,c=p.gate_completion;
  for(const t of [n.intent.initiated_at,p.intervention_at,p.gateway_dead_at,p.orphans_observed_at,p.grant_expires_at,p.group_empty_at,e.received_at_ms,c.released_at_ms,...(late?[c.forwarded_at_ms,c.completed_at_ms]:[])]) assert(Number.isSafeInteger(t)&&t>=0);
  assert(p.intervention_at+2000<p.grant_expires_at);
  assert(p.intervention_at>=e.received_at_ms);assert(p.gateway_dead_at>=p.intervention_at);assert(p.gateway_dead_at<p.grant_expires_at);assert(p.orphans_observed_at>=p.gateway_dead_at);
  assert(c.released_at_ms>=p.grant_expires_at);assert(p.group_empty_at>=c.released_at_ms);
  for(const b of [p.backend_at_boundary,p.backend_after_release]) {assert(hash(b.sha256));assert(Number.isSafeInteger(b.serial)&&b.serial>=0);assert.equal(b.target_uid,m.target.uid);}
  assert.equal(p.backend_at_boundary.target_version,m.target.resource_version);assert.equal(p.backend_at_boundary.revision,m.before_revision);
  assert([m.before_revision,m.after_revision].includes(p.backend_after_release.revision));
  assert(p.backend_after_release.serial>=p.backend_at_boundary.serial);

  assert(['PATCH','PUT'].includes(e.method));assert.equal(e.path,`/api/v1/namespaces/${m.target.namespace}/configmaps/${m.target.name}`);assert(hash(e.body_sha256));assert.equal(e.forwarded,false);
  for(const k of ['method','path','body_sha256','received_at_ms']) equal(e[k],c[k]);
  assert(c.released_at_ms>=p.gateway_dead_at);
  assert.equal(c.forwarded,late);assert.equal(c.upstream_status,late?200:null);
  if(late) {assert(c.forwarded_at_ms>=p.grant_expires_at);assert(c.completed_at_ms>=c.forwarded_at_ms);}
  const original=state.resources[0].instances[0].attributes;
  const checkTarget=(v,desired)=>{
    assert.equal(v.metadata.uid,m.target.uid);assert.equal(v.metadata.namespace,m.target.namespace);assert.equal(v.metadata.name,m.target.name);
    assert.equal(v.metadata.annotations['kedgeflow.dev/revision'],desired?m.after_revision:m.before_revision);
    equal(v.data??{},original.data);equal(v.binaryData??{},original.binary_data);equal(v.immutable??false,original.immutable);equal(v.metadata.labels??{},original.metadata[0].labels);
    if(desired) assert.notEqual(v.metadata.resourceVersion,m.target.resource_version);else assert.equal(v.metadata.resourceVersion,m.target.resource_version);
  };
  checkTarget(p.target_before_release,false);checkTarget(p.target_after_release,late);
  equal(p.target_before_release,targets.before);equal(p.target_after_release,targets.after);
  assert.equal(p.backend_at_boundary.sha256,m.files['state.json']);assert.equal(n.intent.backend_before_sha256,m.files['state.json']);
  assert.equal(n.backend_sha256,p.backend_after_release.sha256);
  assert.equal(p.backend_at_boundary.lineage,p.backend_after_release.lineage);
  if(!late) equal(p.backend_at_boundary,p.backend_after_release);
  equal(events,afterEvents);equal(n.audit_before_queries,events);equal(n.audit_after_queries,afterEvents);
  assert.equal(events.length,late?1:0);
  if(late) {
    const a=events[0];assert.equal(a.stage,'ResponseComplete');assert.equal(a.user.username,`system:serviceaccount:${m.target.namespace}:runner`);assert.equal(a.objectRef.name,m.target.name);assert.equal(a.objectRef.namespace,m.target.namespace);assert.equal(a.objectRef.resource,'configmaps');assert.equal(a.verb,e.method.toLowerCase());assert.equal(a.responseStatus.code,200);
    assert(Date.parse(a.requestReceivedTimestamp)>=p.grant_expires_at);
    assert(Date.parse(a.stageTimestamp)>=Date.parse(a.requestReceivedTimestamp));
  }
  return {name,ordinary_state:n.native_state,intent_state:n.intent.state,children_survived_gateway:true,live_group_members_at_expiry:p.group_at_expiry.length,fixture_group_kill:p.fixture_group_kill,late_target_effect:late,audit_writes:events.length};
}
export async function verify(root) {return {status:'PASS',scope:'local whole-gateway-death replay; no containment or no-effect barrier',cases:await Promise.all(['gateway-kill-drop','gateway-kill-late'].map(n=>verifyCase(root,n)))};}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) console.log(JSON.stringify(await verify(resolve(process.argv[2])),null,2));
