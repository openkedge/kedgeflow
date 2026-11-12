#!/usr/bin/env node
// Read-only local replay; generated fixture identities are not independent owners.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonical, digest, strictJson } from '../sdk/node/records.mjs';
import { validateTerraformDescriptor, validateTerraformGrant } from '../sdk/node/terraform.mjs';
import { verifyCase as verifyPair } from './verify-terraform-pair.mjs';
const load = async p => strictJson(await readFile(p, 'utf8'));
const equal = (a,b) => assert.equal(canonical(a),canonical(b));
export function verifyStart(s, host) {
  const p=s.properties, k=s.kernel;
  for(const [key,value] of Object.entries({KillMode:'control-group',Delegate:'no',ProtectSystem:'strict',NoNewPrivileges:'yes',ProtectControlGroups:'yes',PrivateTmp:'yes',CapabilityBoundingSet:''})) assert.equal(p[key],value);
  assert.equal(p.TimeoutStopUSec,'5s');
  assert.equal(Number(p.MainPID),s.pid);assert.equal(k.pid,s.pid);assert.equal(k.uid,host.uid);
  assert(host.uid>0&&host.agent_uid>0&&host.uid!==host.agent_uid);
  assert.equal(k.cap_eff,'0000000000000000');assert.equal(k.no_new_privs,'1');assert.equal(k.seccomp,'2');
  assert.equal(s.custody_probes.length,8);
  for(const name of ['writer','plan','gateway_key','process_environment','docker_socket']) {
    const rows=s.custody_probes.filter(p=>p.resource===name&&p.agent_read_refused===true&&p.errno==='EACCES'&&p.operation===(name==='docker_socket'?'connect':'read'));
    assert.equal(rows.length,1);
  }
  for(const name of ['plan','writer','configuration']) {
    const rows=s.custody_probes.filter(p=>p.resource===name&&p.service_write_refused===true&&p.errno==='EROFS');
    assert.equal(rows.length,1);
  }
}
export async function verifyCase(root,name,starts,host) {
  const base=join(root,'cases',name),late=name==='cgroup-late';
  const [m,plan,i,n,p,targets,events,after,grant,registration,descriptor,traces]=await Promise.all(
    ['manifest.json','inspection.json','report.json','sdk-native-report.json','systemd-proof.json','target-observation.json','audit-events.json','audit-events-after-query.json','sdk-grant-payload.json','sdk-registration.json','sdk-descriptor.json','gate-requests.json'].map(f=>load(join(base,f))));
  equal(n.injection,p);assert.equal(n.mode,late?'systemd-kill-late':'systemd-kill-drop');
  assert.equal(m.profile,'KF-TERRAFORM-PLAN-0.2-draft');
  const md=digest('terraform-plan-manifest',m);
  const effect=digest('terraform-plan-effect',{address:'kubernetes_config_map_v1.target',before:plan.resource_changes[0].change.before,after:plan.resource_changes[0].change.after});
  assert.equal(i.manifest_digest,md);assert.equal(n.intent.manifest_digest,md);
  assert.equal(i.effect_digest,effect);assert.equal(n.intent.effect_digest,effect);
  assert.equal(registration.manifestDigest,md);assert.equal(registration.effectDigest,effect);
  assert.equal(registration.inspectionSha256,i.inspection_sha256);
  validateTerraformDescriptor(descriptor,registration);
  validateTerraformGrant(descriptor,grant,{node:registration.resource.id,expected_version:1,manifest_digest:md,effect_digest:effect},registration);
  assert.equal(grant.root_id,n.intent.root_id);assert.equal(grant.expires_at,p.grant_expires_at);
  assert.equal(n.native_state,'dispatch_authorized');assert.equal(p.phase,n.native_state);
  assert.equal(n.intent.state,'started');assert.equal(n.intent.backend_after_sha256,null);assert.equal(n.intent.observed_after_digest,null);
  for(const key of ['claims','permits','dispatches','intents','intent_requests']) assert.equal(n.counters[key],1);
  for(const key of ['ordinary_outcomes','intent_outcomes']) assert.equal(n.counters[key],0);
  equal(p.native_counts,n.counters);
  for(const key of ['retained_history_unchanged','grant_expired_at_query','domain_revoked_at_query','broker_stopped_at_query','writer_absent_at_query']) assert.equal(n[key],true);
  assert.equal(n.resumed.state,'dispatch_authorized');assert.equal(n.resumed.attempt_id,n.intent.attempt_id);assert.equal(n.resumed.grant_digest,n.intent.grant_digest);
  assert.equal(n.first.wire.filter(x=>x.method==='tools/call'&&x.grantPresent).length,1);
  assert.equal(n.resumed.wire.filter(x=>['admit','issue','tools/call'].includes(x.method)).length,0);
  assert(n.resumed.wire.filter(x=>x.method==='kedgeflow/status').every(x=>!x.grantPresent));
  const s=p.systemd;assert.equal(s.exit_status,9);assert.equal(s.old_group_empty,true);
  assert.equal(s.escaped_process_terminated,true);assert.equal(s.fixture_group_kill,false);
  assert(s.killed_at+2000<p.grant_expires_at);assert(s.group_empty_at>=s.killed_at);
  assert(s.group_empty_at-s.killed_at<12000);
  const start=starts.find(x=>x.pid===Number(s.properties.MainPID));assert(start);verifyStart(start,host);
  equal(start.properties,s.properties);
  assert(s.old_processes.some(x=>x.exe==='terraform'));
  assert(s.old_processes.some(x=>x.exe.startsWith('terraform-provider-kubernetes')));
  assert(s.old_processes.some(x=>x.pid===s.escaped.pid&&x.pgid===s.escaped.pgid));
  assert(s.old_processes.every(x=>x.uid===host.uid&&x.cgroup===start.kernel.cgroup));
  assert(s.old_processes.filter(x=>x.exe==='terraform').every(x=>x.pgid!==s.escaped.pgid));
  assert(s.auto_restart_pid>1&&s.auto_restart_pid!==start.pid);
  assert.equal(s.auto_restart_kernel.uid,host.uid);assert.equal(Number(s.restart_properties.MainPID),s.auto_restart_pid);
  const c=p.gate_completion;assert(c.released_at_ms>=p.grant_expires_at);assert(c.released_at_ms>=s.group_empty_at);
  assert.equal(c.forwarded,late);assert.equal(c.upstream_status,late?200:null);
  const mutations=traces.filter(x=>x.method!=='GET');assert.equal(mutations.length,1);
  assert.equal(mutations[0].path,c.path);assert.equal(mutations[0].status,late?200:null);
  assert.equal(c.path,`/api/v1/namespaces/${m.target.namespace}/configmaps/${m.target.name}`);
  equal(targets.after,p.target_after);
  for(const [v,revision] of [[targets.before,m.before_revision],[targets.after,late?m.after_revision:m.before_revision]]) {
    assert.equal(v.metadata.uid,m.target.uid);assert.equal(v.metadata.name,m.target.name);assert.equal(v.metadata.namespace,m.target.namespace);
    assert.equal(v.metadata.annotations['kedgeflow.dev/revision'],revision);
    equal(v.data??{},plan.resource_changes[0].change.before.data);
    equal(v.binaryData??{},plan.resource_changes[0].change.before.binary_data??{});
    equal(v.immutable??false,plan.resource_changes[0].change.before.immutable??false);
    equal(v.metadata.labels??{},plan.resource_changes[0].change.before.metadata[0].labels??{});
  }
  equal(events,after);equal(n.audit_before_queries,events);equal(n.audit_after_queries,after);
  assert.equal(events.length,late?1:0);
  if(late) {
    assert(c.forwarded_at_ms>=p.grant_expires_at);
    const e=events[0];assert.equal(e.stage,'ResponseComplete');assert.equal(e.verb,c.method.toLowerCase());
    assert.equal(e.responseStatus.code,200);assert.equal(e.objectRef.namespace,m.target.namespace);assert.equal(e.objectRef.name,m.target.name);
    assert.equal(e.user.username,`system:serviceaccount:${m.target.namespace}:runner`);
    assert(Date.parse(e.requestReceivedTimestamp)>=p.grant_expires_at);
  }
  return {name,state:n.native_state,old_cgroup_drained:true,detached_child_terminated:true,late_effect:late,audit_writes:events.length};
}
export async function verify(root) {
  const host=await load(join(root,'host.json'));
  assert.equal(host.same_host_administered_fixture,true);
  const starts=(await readFile(join(root,'service-starts.jsonl'),'utf8')).trim().split('\n').map(strictJson);
  assert.equal(starts.length,8);assert.equal(new Set(starts.map(s=>s.unit)).size,4);
  for(const s of starts) verifyStart(s,host);
  const normal=await load(join(root,'cases','normal','sdk-native-report.json'));
  assert.equal(normal.native_state,'committed');assert.equal(normal.intent.state,'applied');
  for(const key of ['claims','permits','dispatches','intents']) assert.equal(normal.counters[key],1);
  assert.equal(normal.counters.ordinary_outcomes,1);assert.equal(normal.retained_history_unchanged,true);
  const cases=await Promise.all(['cgroup-drop','cgroup-late'].map(n=>verifyCase(root,n,starts,host)));
  const pair=await verifyPair(root,'partial',{gateway:true});
  return {status:'PASS',scope:'same-host Linux systemd and custody software qualification; no production acceptance',service_starts:starts.length,cases,pair};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) console.log(JSON.stringify(await verify(resolve(process.argv[2])),null,2));
