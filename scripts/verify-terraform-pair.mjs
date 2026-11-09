#!/usr/bin/env node
// Read-only local evidence replay, not execution authority or signed attestation.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { strictJson, digest, canonical } from '../sdk/node/records.mjs';

const load = async path => strictJson(await readFile(path, 'utf8'));
const equal = (a,b,message) => assert.equal(canonical(a),canonical(b),message);
function time(value) {
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
  assert(match, 'invalid audit timestamp');
  return BigInt(Date.parse(match[1] + 'Z')) * 1000000n + BigInt((match[2] ?? '').padEnd(9, '0'));
}
const field = (value, key, fallback) => Object.hasOwn(value, key) ? value[key] : fallback;
export async function verifyCase(root, name) {
  const base = join(root, 'cases', name);
  const [manifest, plan, inspection, native, backend, targets, events, afterEvents, state] = await Promise.all(
    ['manifest.json', 'inspection.json', 'report.json', 'pair-native-report.json', 'backend-observation.json', 'target-raw-observation.json', 'audit-events.json', 'audit-events-after-query.json', 'state.json'].map(file => load(join(base, file)))
  );
  const partial = name !== 'normal';
  const report = native.report, intent = report.intent;
  assert.equal(manifest.profile, 'KF-TERRAFORM-PAIR-PLAN-0.1-draft');
  assert.equal(report.profile, 'KF-TERRAFORM-PAIR-APPLY-0.1-draft');
  equal(manifest.members.map(m => m.id), ['first', 'second']);
  assert.equal(intent.manifest_digest, digest('terraform-pair-plan-manifest', manifest));
  const effects = manifest.members.map((m, i) => ({ id: m.id, address: `kubernetes_config_map_v1.${m.id}`, target: m.target,
    effect_digest: digest('terraform-plan-effect', { address: 'kubernetes_config_map_v1.target', before: plan.resource_changes[i].change.before, after: plan.resource_changes[i].change.after }) }));
  equal(effects, inspection.members);
  assert.equal(intent.effect_digest, digest('terraform-pair-plan-effect', { members: effects, order: ['first', 'second'] }));
  equal(native.cold.intent, intent, 'cold query rewrote history');
  assert.equal(native.cold.replayed, true);
  assert.equal(native.cold.profile, report.profile);
  assert.equal(native.legacy_loader_refused, true);
  assert.equal(intent.state, partial ? 'partial_observed' : 'applied');
  assert.equal(report.status, partial ? 'unknown' : 'committed');
  assert.equal(native.native_state, report.status);
  assert.equal(native.cold.status, report.status);
  assert.equal(intent.pair.tool_succeeded, !partial);
  assert.equal(intent.pair.backend_progress, true);
  assert.equal(intent.observed_after_digest, digest('terraform-pair-observation', intent.pair));
  assert.equal(backend.before.sha256, manifest.files['state.json']);
  assert.equal(backend.before.sha256, intent.backend_before_sha256);
  assert.equal(backend.after.sha256, intent.backend_after_sha256);
  assert.equal(backend.before.lineage, backend.after.lineage);
  assert(backend.after.serial > backend.before.serial);
  equal(native.counts, [1, 1, 1, 1, 1, 1]);
  for (const key of ['grant_expired_at_query', 'domain_revoked_at_query', 'writer_absent_at_query', 'broker_unavailable_at_query']) assert.equal(native[key], true);
  assert.equal(native.second_permission_restored, partial);
  assert.equal(native.lost_reply, name === 'partial-lost');
  if (native.lost_reply) assert.equal(native.first_reply_bytes, 0, 'reply was not actually withheld');
  else assert(native.first_reply_bytes > 0);
  for (let i = 0; i < 2; i++) {
    const m = manifest.members[i], observation = intent.pair.members[i], value = targets.members[i].object;
    const desired = !partial || i === 0;
    assert.equal(observation.id, m.id);
    assert.equal(observation.target_uid, m.target.uid);
    assert.equal(observation.state, desired ? 'desired' : 'original_observed');
    assert.equal(observation.observation_digest, digest('terraform-pair-member-observation', value));
    assert(Number.isSafeInteger(observation.observed_at) && observation.observed_at >= intent.initiated_at);
    assert.equal(value.metadata.uid, m.target.uid);
    assert.equal(value.metadata.namespace, m.target.namespace);
    assert.equal(value.metadata.name, m.target.name);
    if (desired) assert.notEqual(value.metadata.resourceVersion, m.target.resource_version);
    else assert.equal(value.metadata.resourceVersion, m.target.resource_version);
    const before = state.resources[i].instances[0].attributes;
    const annotations = { ...before.metadata[0].annotations, 'kedgeflow.dev/revision': desired ? m.after_revision : m.before_revision };
    equal(value.metadata.annotations, annotations);
    equal(field(value.metadata, 'labels', {}), before.metadata[0].labels);
    equal(field(value, 'data', {}), before.data);
    equal(field(value, 'binaryData', {}), before.binary_data);
    equal(field(value, 'immutable', false), before.immutable);
    assert.equal(backend.members[i].uid, m.target.uid);
    if (desired) {
      assert.equal(backend.members[i].revision, annotations['kedgeflow.dev/revision']);
      assert.equal(backend.members[i].resource_version, value.metadata.resourceVersion);
    } else assert([m.before_revision, m.after_revision].includes(backend.members[i].revision));
  }
  equal(afterEvents, events, 'query/replay caused another target write');
  assert.equal(new Set(events.map(e => e.auditID)).size, events.length);
  const user = `system:serviceaccount:${manifest.members[0].target.namespace}:runner`;
  const rows = manifest.members.map(m => events.filter(e => e.objectRef.name === m.target.name));
  assert(rows.every(r => r.length > 0));
  assert.equal(rows.flat().length, events.length);
  for (const e of events) {
    assert.equal(e.stage, 'ResponseComplete'); assert.equal(e.user.username, user);
    assert.equal(e.objectRef.namespace, manifest.members[0].target.namespace);
    assert.equal(e.objectRef.resource, 'configmaps'); assert(['patch', 'update'].includes(e.verb));
    assert(time(e.requestReceivedTimestamp) <= time(e.stageTimestamp));
  }
  assert(rows[0].every(e => e.responseStatus.code >= 200 && e.responseStatus.code < 300));
  assert(rows[1].every(e => partial ? e.responseStatus.code === 403 : e.responseStatus.code >= 200 && e.responseStatus.code < 300));
  const firstCompleted = rows[0].map(e => time(e.stageTimestamp)).reduce((a,b) => a > b ? a : b);
  const secondReceived = rows[1].map(e => time(e.requestReceivedTimestamp)).reduce((a,b) => a < b ? a : b);
  assert(firstCompleted <= secondReceived, 'first write did not precede second request');
  return { name, ordinary_state: report.status, retained_state: intent.state, audit_write_requests: events.length, target_and_backend_replayed: true, ordered: true };
}
export async function verify(root) {
  return { status: 'PASS', scope: 'read-only local evidence replay; no independent attestation or execution authority', cases: await Promise.all(['normal', 'partial', 'partial-lost'].map(name => verifyCase(root, name))) };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  console.log(JSON.stringify(await verify(resolve(process.argv[2])), null, 2));
}
