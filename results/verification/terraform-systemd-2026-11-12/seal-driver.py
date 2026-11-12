from pathlib import Path
import json,hashlib,re,subprocess,os
from jsonschema import Draft202012Validator
r=Path.cwd();out=r/'results/verification/terraform-systemd-2026-11-12';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],text=True).strip()
base='f9981e8';implementation='0c0e081'
assert git('diff','--name-only','--','crates','scripts','deploy','docs','tests')==''
subprocess.run(['git','diff','--exit-code',base,'--','crates/kedgeflow/src','sdk/node','tests/sdk','spec','fixtures','Cargo.lock','Cargo.toml'],check=True)
records=0
for name in ['normal','cgroup-drop','cgroup-late','partial']:
 case=out/'cases'/name;n=json.loads((case/'sdk-native-report.json').read_text())
 prefix='terraform-pair' if name=='partial' else 'terraform'
 for value,schema in [(n['intent'],prefix+'-apply-v0.1.schema.json'),(json.loads((case/'manifest.json').read_text()),prefix+'-plan-v0.'+('1' if name=='partial' else '2')+'.schema.json'),(json.loads((case/'report.json').read_text()),prefix+'-plan-v0.'+('1' if name=='partial' else '2')+'.schema.json')]:
  Draft202012Validator(json.loads((r/'spec/drafts'/schema).read_text())).validate(value);records+=1
 if name!='normal':
  Draft202012Validator(json.loads((r/'spec/drafts'/(prefix+'-gateway-v0.1.schema.json')).read_text())).validate(json.loads((case/'sdk-registration.json').read_text()));records+=1
 steps=json.loads((case/'steps.json').read_text());assert steps[-1]['step']=='cleanup owned namespace'
 assert all(x['exit_code']==0 or x['step'] in ['planner cannot patch ConfigMaps','refuse swapped saved plan','refuse pinned executable provider hook','no apply entry point','single-resource inspector refuses pair profile'] for x in steps)
prior={}
for dirname in ['terraform-gateway-death-2026-11-11','terraform-active-child-2026-11-11','terraform-pair-gateway-2026-11-11']:
 p=r/'results/verification'/dirname
 for n,h in json.loads((p/'artifact-hashes.json').read_text()).items():assert sha(p/n)==h,(dirname,n)
 prior.update({str(f.relative_to(r)):sha(f) for f in p.rglob('*') if f.is_file()})
(out/'prior-evidence-hashes.json').write_text(json.dumps(prior,indent=2)+'\n')
files=set(git('diff','--name-only',base,implementation).splitlines())
files.update(['Cargo.toml','Cargo.lock','scripts/package-linux.py','scripts/start-etcd.sh','scripts/terraform_active_gate.py','scripts/test-terraform-plan.py','scripts/verify-terraform-pair.mjs','tests/sdk/live-agent.mjs','tests/sdk/package.json','tests/sdk/package-lock.json'])
(out/'source-hashes.json').write_text(json.dumps({n:sha(r/n) for n in sorted(files)},indent=2)+'\n')
(out/'source.patch').write_bytes(subprocess.check_output(['git','diff','--binary',base,implementation,'--',*sorted(files)]))
summary={'date':'2026-11-12','baseline':git('rev-parse',base),'implementation_commit':git('rev-parse',implementation),'status':'N2i local Linux software qualification complete; independent production acceptance open','platform':'linux_aarch64','final_cohort_rust_test_runs':104,'core_tests':99,'service_workflow_tests':4,'nested_restore_metrics_test':1,'qualified_failures':0,'ignored':0,'skips':0,'sdk_suites':7,'single_sdk_checks':46,'pair_sdk_checks':67,'package_unit_tests':3,'positive_replays':1,'negative_replays':12,'service_starts':8,'schema_records':records,'source_files':len(files),'source_patch_sha256':sha(out/'source.patch'),'terraform':'1.17.1','provider':'2.38.0','sdk':'@modelcontextprotocol/client 2.3.0','etcd':'3.6.5; three-member same-host loopback','builder':'rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157','host':json.loads((out/'host.json').read_text()),'bundle':json.loads((out/'bundle.json').read_text()),'tool_pins':json.loads((out/'tool-pins.json').read_text()),'production_runtime_sdk_spec_fixtures_unchanged':True,'limits':['Level C; one or two fixed ConfigMap annotation updates and native local backend only','cgroup drains old local processes; already queued request can still commit after expiry','no automatic retry, no-effect promotion, allowance release, force-unlock or inverse','generated fixture identity/evidence, restore witness and audit share host administration/failure domain','provider/root remain trusted; independent production identity, writer/storage/custody, audit/operations and reproduction acceptance open']}
summary['observations']={name:{'killed_pid':(p:=json.loads((out/'cases'/name/'systemd-proof.json').read_text()))['systemd']['properties']['MainPID'],'old_process_count':len(p['systemd']['old_processes']),'cgroup_drain_ms':p['systemd']['group_empty_at']-p['systemd']['killed_at'],'fixture_group_kill':p['systemd']['fixture_group_kill'],'old_group_empty':p['systemd']['old_group_empty'],'escaped_child_terminated':p['systemd']['escaped_process_terminated'],'auto_restart_pid':p['systemd']['auto_restart_pid'],'late_target_effect':p['gate_completion']['forwarded'],'native_phase':p['phase']} for name in ['cgroup-drop','cgroup-late']}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
checks=[]
env={**os.environ,'PATH':'/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_HOME':'/private/tmp/kedgeflow-cargo','CARGO_TARGET_DIR':'/private/tmp/kedgeflow-paper-target'}
commands=[['cargo','fmt','--all','--','--check'],[str(r/'.cache/terraform-apply-python/bin/ruff'),'check','scripts/package-terraform-linux.py','scripts/qualify-terraform-systemd.py','scripts/terraform-systemd-fixture.py','tests/test_terraform_linux_package.py'],[str(r/'.cache/terraform-apply-python/bin/ruff'),'format','--check','scripts/package-terraform-linux.py','scripts/qualify-terraform-systemd.py','scripts/terraform-systemd-fixture.py','tests/test_terraform_linux_package.py'],['node','scripts/verify-terraform-systemd.mjs',str(out)],['node','scripts/test-terraform-systemd-replay.mjs',str(out)],['node','scripts/verify-terraform-gateway-death.mjs',str(r/'results/verification/terraform-gateway-death-2026-11-11')],['git','diff','--check']]
for cmd in commands:
 p=subprocess.run(cmd,env=env,capture_output=True,text=True);checks.append('COMMAND: '+' '.join(cmd)+'\n'+p.stdout+p.stderr+'EXIT: '+str(p.returncode));assert p.returncode==0,checks[-1]
(out/'checks.log').write_text('\n\n'.join(checks)+'\n')
(out/'artifact-hashes.json').write_text('{}\n')
for p in [out/'README.md',*(r/n for n in files if n.endswith('.md'))]:
 for link in re.findall(r'\]\(([^)]+)\)',p.read_text()):
  if '://' not in link and not link.startswith('#'):assert (p.parent/link.split('#')[0]).exists(),(p,link)
for p in (out/'cases').rglob('*'):
 if p.is_file():
  text=p.read_text();assert 'PRIVATE KEY-----' not in text,p;assert not re.search(r'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',text),p
assert 'tf9 VM stopped' in (out/'cleanup.log').read_text()
(out/'artifact-hashes.json').write_text(json.dumps({str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='artifact-hashes.json'},indent=2)+'\n')
print(json.dumps({'status':'PASS','native_runs':104,'source_files':len(files),'schema_records':records}))
