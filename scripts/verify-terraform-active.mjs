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
  const [m,plan,inspection,n,p,targets,events,afterEvents,state] = await Promise.all(['manifest.json','inspection.json','report.json','sdk-native-report.json','active-child-proof.json','target-observation.json','audit-events.json','audit-events-after-query.json','state.json'].map(f=>load(join(base,f))));
  equal(n.injection,p,'inconsistent intervention proof');
  const late=name==='deadline-late';
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
  assert(['provider-kill','terraform-kill','deadline-late'].includes(name));
  assert.equal(m.profile,'KF-TERRAFORM-PLAN-0.2-draft');
  const manifest=digest('terraform-plan-manifest',m);
  assert.equal(manifest,inspection.manifest_digest);
  assert.equal(n.intent.manifest_digest,manifest);
  assert.equal(n.intent.effect_digest,digest('terraform-plan-effect',{address:'kubernetes_config_map_v1.target',before:plan.resource_changes[0].change.before,after:plan.resource_changes[0].change.after}));
  assert.equal(n.intent.effect_digest,inspection.effect_digest);
  assert.equal(n.intent.profile,'KF-TERRAFORM-APPLY-0.1-draft');
  assert(!Object.hasOwn(n.intent,'pair'));
  assert.equal(n.native_state,'unknown');
  assert.equal(n.intent.state,late?'started':'unknown');
  assert.equal(n.intent.backend_after_sha256,null);
  assert.equal(n.intent.observed_after_digest,null);
  assert.equal(p.initial_intent.state,'started');
  for (const k of ['profile','manifest_digest','effect_digest','grant_digest','root_id','attempt_id','initiated_at','backend_before_sha256']) equal(p.initial_intent[k],n.intent[k]);
  for (const r of [n.first,n.resumed]) {
    assert.equal(r.state,'unknown');assert.equal(r.attempt_id,n.intent.attempt_id);assert.equal(r.grant_digest,n.intent.grant_digest);
  }
  for (const k of ['claims','permits','dispatches','intents','intent_requests','ordinary_outcomes']) assert.equal(n.counters[k],1);
  assert.equal(n.counters.intent_outcomes,late?0:1);
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
  assert.equal(p.no_live_group_at_release,true);assert.equal(p.gateway_alive,true);
  assert.equal(p.signal,late?null:9);
  assert.equal(p.signal_target,late?'dispatch_deadline':name==='provider-kill'?'provider':'terraform');
  assert(p.intervention_at+2000<p.grant_expires_at);
  assert(p.intervention_at>=p.active_request.received_at_ms);
  assert(p.ordinary_unknown_at>=p.intervention_at);
  if(late) assert(p.ordinary_unknown_at>=p.grant_expires_at);
  if(name==='terraform-kill') assert(p.ordinary_unknown_at-p.intervention_at<5000);
  const e=p.active_request,c=p.gate_completion;
  for(const t of [n.intent.initiated_at,p.intervention_at,p.ordinary_unknown_at,p.grant_expires_at,e.received_at_ms,c.released_at_ms,...(late?[c.forwarded_at_ms,c.completed_at_ms]:[])]) assert(Number.isSafeInteger(t)&&t>=0);
  for(const b of [p.backend_at_boundary,p.backend_after_cleanup,p.backend_after_release]) {assert(hash(b.sha256));assert(Number.isSafeInteger(b.serial)&&b.serial>=0);assert.equal(b.target_uid,m.target.uid);assert.equal(b.target_version,m.target.resource_version);assert.equal(b.revision,m.before_revision);}

  assert(['PATCH','PUT'].includes(e.method));assert.equal(e.path,`/api/v1/namespaces/${m.target.namespace}/configmaps/${m.target.name}`);assert(hash(e.body_sha256));assert.equal(e.forwarded,false);
  for(const k of ['method','path','body_sha256','received_at_ms']) equal(e[k],c[k]);
  assert(c.released_at_ms>=p.ordinary_unknown_at);
  assert.equal(c.forwarded,late);assert.equal(c.upstream_status,late?200:null);
  if(late) {assert(c.forwarded_at_ms>=p.ordinary_unknown_at);assert(c.completed_at_ms>=c.forwarded_at_ms);}
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
  equal(p.backend_after_cleanup,p.backend_after_release);assert.equal(n.backend_sha256,p.backend_after_release.sha256);
  assert.equal(p.backend_at_boundary.lineage,p.backend_after_release.lineage);
  if(late) equal(p.backend_at_boundary,p.backend_after_release,'late API effect incorrectly inferred from local backend');
  equal(events,afterEvents);equal(n.audit_before_queries,events);equal(n.audit_after_queries,afterEvents);
  assert.equal(events.length,late?1:0);
  if(late) {
    const a=events[0];assert.equal(a.stage,'ResponseComplete');assert.equal(a.user.username,`system:serviceaccount:${m.target.namespace}:runner`);assert.equal(a.objectRef.name,m.target.name);assert.equal(a.objectRef.namespace,m.target.namespace);assert.equal(a.objectRef.resource,'configmaps');assert.equal(a.verb,e.method.toLowerCase());assert.equal(a.responseStatus.code,200);
    assert(Date.parse(a.requestReceivedTimestamp)>=p.ordinary_unknown_at);
    assert(Date.parse(a.stageTimestamp)>=Date.parse(a.requestReceivedTimestamp));
  }
  return {name,ordinary_state:n.native_state,intent_state:n.intent.state,active_children_observed:true,no_live_local_group:true,late_target_effect:late,audit_writes:events.length};
}
export async function verify(root) {return {status:'PASS',scope:'local read-only evidence replay; no independent attestation or no-effect barrier',cases:await Promise.all(['provider-kill','terraform-kill','deadline-late'].map(n=>verifyCase(root,n)))};}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) console.log(JSON.stringify(await verify(resolve(process.argv[2])),null,2));
