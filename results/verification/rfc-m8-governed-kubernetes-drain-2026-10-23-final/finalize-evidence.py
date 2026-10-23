from pathlib import Path
import base64
import copy
import datetime
import gzip
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root = Path.cwd()
base = root / '.cache/m8-kube-drain-20261023-budget-repair'
out = root / 'results/verification/rfc-m8-governed-kubernetes-drain-2026-10-23-final'
assert not (out / 'final-source.json').exists(), 'Finalize exactly once'
h = json.loads((base / 'source-sha256.json').read_text())
current = runpy.run_path('scripts/conformance.py')['source_hashes']
assert current() == h
s = json.loads((out / 'summary.json').read_text())
assert s['status'] == 'passed_software_checks' and s['source_sha256'] == h
assert all(c['exit_code'] == 0 for c in s['commands'])
r = s['rust_tests']
assert r['failed'] == r['ignored'] == 0 and r['passed'] == r['manifest_cases']
assert len([c for c in s['commands'] if c['name'].startswith('artifact-verify-')]) == 6
with zipfile.ZipFile(base / 'source.zip') as z:
    assert {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()} == h
shutil.copyfile(base / 'source.zip', out / 'source.zip')

rbac = json.loads((out / 'kube-rbac.json').read_text())
assert rbac['status'] == 'passed' and len(rbac['cases']) == 7
assert sum(c['status'] == 403 for c in rbac['cases']) == 5
completed = out / 'native-artifacts/kube-drain-completed'
no_effect = out / 'native-artifacts/kube-drain-no-effect'
b = json.loads((completed / 'aggregate.json').read_text())
state = json.loads((completed / 'controller-state.json').read_text())['body']
assert [x['response']['http_status'] for x in state['steps']] == [200, 429, 201]
assert json.loads((completed / 'verification.json').read_text())['status'] == 'forward_completed'
closed_bundle = json.loads((no_effect / 'aggregate.json').read_text())
closed = closed_bundle['evidence']['current']['snapshot']['members']['child-1']['physical']['controller']['body']
assert not closed['steps'] and closed['closed'] is not None
assert json.loads((no_effect / 'verification.json').read_text())['status'] == 'compensated'

# A separate shipping CLI must reject exactly the malformed historical epoch
# while the original serialized bytes already passed required offline replay.
def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def digest(kind, v):
    return hashlib.sha256(('KedgeFlow/KF-JSON-0.2/' + kind + '\0').encode() + canonical(v)).hexdigest()

def sign(v, domain, seed):
    unsigned = {k: x for k, x in v.items() if k != 'signature'}
    v['signature'] = base64.urlsafe_b64encode(
        Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).sign(
            (domain + '\0').encode() + canonical(unsigned)
        )
    ).decode().rstrip('=')

bad = copy.deepcopy(b)
capture = bad['evidence']['current']
assert digest('family-saga-complete-snapshot', capture['snapshot']) == capture['seal']['snapshot_digest']
old = capture['snapshot']['members']['child-1']['physical']['retained_completion']
old['observation']['body']['native_epoch'] = 'invalid'
sign(old['observation'], 'KedgeFlow:KF-KUBE-DRAIN-0.1-draft', 49)
capture['seal']['snapshot_digest'] = digest('family-saga-complete-snapshot', capture['snapshot'])
sign(capture['seal'], 'KedgeFlow:KF-FAMILY-SAGA-0.1-draft:native-capture', 34)
bad['checkpoint']['evidence_digest'] = digest('family-saga-complete-evidence', bad['evidence'])
sign(bad['checkpoint'], 'KedgeFlow:KF-FAMILY-SAGA-0.1-draft:aggregate-history', 34)
bad_path = out / 'malformed-historical-epoch.json'
bad_path.write_bytes(canonical(bad))
binary = Path(os.environ.get('CARGO_TARGET_DIR', '/private/tmp/kedgeflow-paper-target')) / 'debug/kf-family-saga'
negative = subprocess.run([str(binary), 'verify', '--bundle', str(bad_path), '--trust', str(completed / 'audit-trust.json')], capture_output=True, text=True, check=False)
assert negative.returncode != 0 and 'historical physical completion' in negative.stderr, negative.stderr
(out / 'negative-offline-replay.log').write_text(negative.stdout + negative.stderr)
(out / 'negative-offline-replay.json').write_text(json.dumps({
    'status': 'passed_expected_refusal', 'exit_code': negative.returncode,
    'changed_field': 'current physical retained_completion.observation.body.native_epoch',
    'source_bundle_sha256': hashlib.sha256((completed / 'aggregate.json').read_bytes()).hexdigest(),
    'signatures': 'valid generated fixture observer 49 and collector 34; no production signing material',
    'expected_diagnostic': 'historical physical completion',
}, indent=2) + '\n')

logs = sorted(root.glob('.cache/kube-*.log'))
focused = []
for p in logs:
    if p.name == 'kube-drain-full-run-4.log':
        continue
    raw = p.read_bytes()
    name = 'diagnostic-' + p.name + '.gz'
    (out / name).write_bytes(gzip.compress(raw, mtime=0))
    focused.append({'file': name, 'uncompressed_sha256': hashlib.sha256(raw).hexdigest(), 'scope': 'focused or interrupted development diagnostic; does not qualify final source'})
(out / 'focused-attempts.json').write_text(json.dumps(focused, indent=2) + '\n')
observations = json.loads((base / 'observations.json').read_text())
observations.append({'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'stage': 'after_full_run_and_negative_offline_replay', 'source_files': len(h), 'unchanged': True})
(out / 'source-observations.json').write_text(json.dumps(observations, indent=2) + '\n')
(out / 'qualification-build.json').write_text(json.dumps({
    'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0', 'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '2',
    'runtime_limits': 'Production authority/transport/grant deadlines unchanged; original fixed bounds never extended on polling, restart or PDB retry.',
    'topology': 'Darwin ARM64 host; actual peer PostgreSQL and three etcd members; three actual Kubernetes nodes in one task-owned isolated local VZ VM; no host directory mounts, SSH agent or default context activation.',
    'roles': 'Native/controller/observer roles are co-located Rust fixture tasks with generated signing identities; actual separate mutator/read-only Kubernetes service accounts; bootstrap/readiness/cleanup use a separate owned administrator context. No independent OS-administrator custody claim.',
    'clock': 'The two new native Kubernetes cases use TestClock zero delegating to SystemClock. Shipping controller has no test clock override. Other retained corpus fixtures include controlled historical clocks.',
    'execution_scope': 'Host native forward/owner/inverse orchestration; actual limited-SA cordon and policy/v1 eviction; six separate shipping offline verifier processes. Shipping controller/gateway/SDK drain deployment and process-loss qualification remain open.',
    'node_image': 'kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5',
    'local_bootstrap_tools_sha256': json.loads((root / '.cache/m8-kube-tools/installed-tools.json').read_text()),
    'postgres_runtime': 'All 744 installed runtime files verified against the protected task backup before this retry; none missing or changed.',
    'frozen_inputs': 'Previously committed results, paper, schema, fixtures and SQL migrations unchanged.',
}, indent=2) + '\n')
python_count = re.search(r'(\d+) passed', (out / 'python.log').read_text()).group(1)
pg, family_pg, kube_pg = s['postgres']['passed'], s['family_saga_postgres']['passed'], s['kube_drain_postgres']['passed']
(out / 'README.md').write_text(f'''# Governed Kubernetes drain — 23 October 2026

Baseline: {s['baseline_commit']}. [RFC 0055](../../../docs/rfcs/0055-governed-kubernetes-drain.md)
and the [implementation boundary](../../../docs/KUBERNETES_DRAIN.md) describe
bounded M8e1: native Level C controller acceptance, original Pending journal,
independent physical observation and complete family aggregate replay.

The exact frozen-source run passed **{r['passed']} Rust tests across {r['binaries']}
unique binaries** ({r['binary_executions']} executions across three required batches),
**{python_count} Python tests**, three Node vector suites, formatting, Clippy,
Ruff, mypy, frozen paper/schema checks, and **{pg}/{family_pg}/{kube_pg} actual SQL
storage/peer/restore groups** in the primary/family/Kubernetes batches.
Runtime failures, ignored and skipped tests: zero. The target/case manifest
matches the combined executed population exactly once, including zero-test
binaries. All **{len(h)} source files** remained unchanged from the pre-run
archive through finalization. Source/evidence hashes and source.zip pin the
tested implementation.

## Actual bounded paths

- A real SQL reservation must commit before the physical child can receive
  native authority. Actual native grant/claim, one-shot broker permit and
  original dispatch precede controller acceptance. Acceptance alone stays
  unresolved in the family aggregate.
- The actual least-privilege controller sends JSON Patch cordon (200), an
  original policy/v1 eviction rejected by the PDB (429), then another freshly
  authorized eviction after fixture availability recovers (201). These are
  three controller mutation requests; API reads and administrator fixture
  readiness/cleanup are separate. No direct delete or force fallback exists.
  Independent normalized observations verify our cordon and original pod absence,
  protected workload availability and remaining Ready nodes. This irreversible
  completion blocks SQL compensation and keeps original 2 forward/1 compensation
  costs held.
- Before any Pending mutation, permanent quiesce defeats advance. Positive
  accepted-with-no-effect closure permits a fresh independently admitted original
  SQL inverse with real barrier/applicability and target restore. Actual row
  version 243/free is asserted; the complete aggregate reports compensated and
  still holds both original costs. There is no physical inverse.
- Seven actual service-account RBAC cases pass: allowed fixed reads and dry-run
  target patch, plus five mutation/scope/secret refusals. The observer credential
  cannot patch or evict; the controller cannot patch another node, delete a pod
  directly or read secrets.
- Re-signed physical omission/current-epoch substitution, altered controller
  journal, malformed historical completion epoch and contradictory closed
  absence evidence refuse. Six separate shipping offline CLI processes replay
  serialized completed/unknown/failed/SDK and both physical aggregates. An
  additional separate CLI refuses the exact re-signed malformed historical epoch
  while the original current bytes pass.

## Retained interruptions and limits

The [first interrupted record](../rfc-m8-governed-kubernetes-drain-2026-10-23/README.md)
preserves the exact pre-repair source and an offline diagnostic that accepted a
malformed historical epoch. The source was preserved before repair; final source
adds strict historical epoch and contradictory absence checks with signed
regressions. The [second partial record](../rfc-m8-governed-kubernetes-drain-2026-10-23-interrupted-2/README.md)
preserves an externally interrupted overnight run of the repaired source. Its
handle/processes were confirmed absent before retry. Neither is a conformance
pass. The [failed fixture record](../rfc-m8-governed-kubernetes-drain-2026-10-23-budget-fixture-failure/README.md)
preserves the required runtime failures caused by a shared helper reducing the
legacy two-leaf compensation enrollment. Final source restores the original
default capacity; native production conservation remains unchanged.
Focused diagnostic gzip files preserve original-byte hashes; only the
required complete run qualifies final source.

The three Kubernetes nodes share one local VM. Pause pods and administrator
readiness gates establish fixture mechanics, not an application SLO or physical
node-failure behavior. Native/controller/observer roles are co-located Rust
tasks; generated signers and actual distinct Kubernetes service accounts do not
establish independent administrator custody. The host performs native orchestration;
shipping controller CLI/gateway/SDK drain execution is unqualified. Normalized
signed observations are historical intervals, not atomic cross-resource snapshots
or consensus proofs, and aggregates convey no current execution authority.

M8e2 shipping process/SDK, actual API reply loss, Pending SIGKILL/restart,
late acceptance versus absent closure, paused final-CAS stop races, recreated UID,
deferred expiry and broader physical evidence qualification remain open. M8e3
independently administered writers/custody, production maintenance, physical
failure and accepted SLO evidence remain external gates. Wider whole-saga,
authority-peer and release acceptance also remain open. **M8 is incomplete.**
''')

(out / 'requirements-audit.json').write_text(json.dumps({
    'scope': 'M8e1 bounded mechanical implementation only; complete M8/M8e qualification is not claimed',
    'source_files': len(h),
    'qualified': [
        'Exact named Level C contract; legacy generic fencing cannot inherit it; closed scope/schema/inventory vectors',
        'Actual native SQL predecessor, original grant/claim/one-shot permit/dispatch and controller acceptance',
        'Actual limited-SA JSON Patch cordon, PDB 429, freshly authorized policy/v1 eviction and independent observed completion',
        'Permanent quiesce before any Pending, accepted-no-effect closure and fresh original real SQL inverse with held costs',
        'Seven actual RBAC checks; complete serialized aggregate replay and re-signed historical-epoch refusal',
        'Complete exact Rust case manifest across primary/family/Kubernetes batches, Python, Node, SQL, lint and frozen inputs',
    ],
    'not_qualified_or_incomplete': [
        'Shipping controller CLI/gateway/SDK physical execution and separate-process timing',
        'Actual API effect followed by lost reply, Pending SIGKILL and query-only restart',
        'Positive absent-operation closure versus late acceptance; paused physical final-CAS root/phase races',
        'Actual recreated UID/resourceVersion refusal and protected deferred expiry',
        'Physical unknown operating-record ownership/on-call and incident escalation audit against whitepaper 05-execution.tex',
        'Deployment consequence/review metadata, independently administered custody/writers and production workload/SLO/node failure',
        'Independent whole-saga/authority peers and broader release acceptance',
    ],
    'execution_authority_from_evidence': False,
}, indent=2) + '\n')
shutil.copyfile(Path(__file__), out / 'finalize-evidence.py')
evidence = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file() and p.name not in ('final-source.json', 'SHA256SUMS')}
(out / 'final-source.json').write_text(json.dumps({'profile': 'KF-FINAL-SOURCE-0.1-draft', 'status': 'passed_final_source_unchanged', 'baseline_commit': s['baseline_commit'], 'source_sha256': h, 'evidence_sha256': evidence, 'observations': observations}, indent=2) + '\n')
(out / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out)}\n' for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'))
assert current() == h
(root / '.cache/m8-kube-drain-status.json').write_text(json.dumps({'stage': 'verified_ready_to_commit', 'source_freeze_active': True, 'output': str(out), 'source_files': len(h), 'rust': r, 'all_source_unchanged': True}, indent=2) + '\n')
print(json.dumps({'status': s['status'], 'rust': r, 'source_files': len(h), 'evidence_files': len(evidence)}))
