from pathlib import Path
import json,hashlib,subprocess,shutil,re,os
from jsonschema import Draft202012Validator
root=Path.cwd();out=root/'results/verification/terraform-active-child-2026-11-11';base=root/'.cache/terraform-active-final3';baseline='bb80b6b'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*a):return subprocess.check_output(['git',*a],text=True).splitlines()
out.mkdir(parents=True,exist_ok=True)
for name in ('provider-kill','terraform-kill','deadline-late','legacy-sdk','pair-partial'):
 src=base/name;shutil.copytree(src,out/'cases'/name,dirs_exist_ok=True)
 log=(src/'execution-diagnostic.log').read_text();assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in log and 'SKIP' not in log,name
 steps=json.loads((src/'steps.json').read_text());neg={'planner cannot patch ConfigMaps':1,'refuse swapped saved plan':1,'refuse pinned executable provider hook':1,'no apply entry point':2,'single-resource inspector refuses pair profile':1}
 for row in steps:assert row['exit_code']==neg.get(row['step'],0),(name,row)
 assert steps[-1]['step']=='cleanup owned namespace'
 n=json.loads((src/'sdk-native-report.json').read_text());state='committed' if name=='legacy-sdk' else 'unknown'
 assert n['native_state']==n['first']['state']==n['resumed']['state']==state
 for k in ('claims','permits','dispatches','intents','intent_requests','ordinary_outcomes'):assert n['counters'][k]==1,(name,k)
 assert n['counters']['intent_outcomes']==(0 if name=='deadline-late' else 1)
 for k in ('grant_expired_at_query','domain_revoked_at_query','broker_stopped_at_query','writer_absent_at_query','retained_history_unchanged'):assert n[k]
for src,dst in [
 (base/'regressions.log','regressions.log'),(root/'.cache/terraform-active-node.log','node-vectors.log'),(root/'.cache/terraform-active-clippy-final.log','clippy.log'),
 (root/'.cache/terraform-active-live3.log','live.log'),(root/'.cache/terraform-active-qualify3.py','qualification-driver.py'),
 (root/'.cache/start-terraform-active-env.py','environment-driver.py'),(root/'.cache/terraform-active-cleanup.py','cleanup-driver.py'),
 (root/'.cache/terraform-gateway-env/active-child-start.log','startup.log'),(root/'.cache/terraform-gateway-env/active-child-cleanup.log','cleanup.log'),
 (root/'.cache/terraform-gateway-env/active-child-kubernetes-version.json','kubernetes-version.json'),(root/'.cache/terraform-gateway-env/pair-apply-audit-policy.json','audit-policy.json'),(root/'.cache/terraform-gateway-env/pair-apply-kind.json','kind-config.json'),
 (root/'.cache/test-terraform-active-verifier.mjs','verifier-test-driver.mjs'),(root/'.cache/terraform-active-verifier-tests.json','verifier-tests.json'),
 (root/'.cache/terraform-active-mode-negatives.json','mode-negatives.json'),(root/'.cache/terraform-active-stage-cleanup.json','stage-cleanup.json'),
 (root/'.cache/terraform-active-pipes-final.log','pipe-regression-intermediate.log'),(root/'.cache/collect-terraform-active.py','collector.py')]:shutil.copyfile(src,out/dst)
for cohort,name in [('terraform-active-final','ca-leaf-first'),('terraform-active-final2','ca-leaf-traced')]:
 src=root/'.cache'/cohort/'provider-kill';dst=out/'preliminary'/name;dst.mkdir(parents=True,exist_ok=True)
 for file in ('steps.json','execution-diagnostic.log','gate-requests.json'):
  if (src/file).exists():shutil.copyfile(src/file,dst/file)
 shutil.copyfile(src.parent/'provider-kill.log',dst/'parent.log')
shutil.copyfile(root/'.cache/terraform-active-pipes.log',out/'preliminary/pipe-inspection-sandbox.log')
reg=(out/'regressions.log').read_text();counts=[int(x) for x in re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',reg)];assert counts==[20,20,7,11,5,14,7,3,12] and sum(counts)==99,counts
assert 'SKIP' not in reg and '"regressions": 0' in (out/'live.log').read_text()
node=(out/'node-vectors.log').read_text();assert len(re.findall('"status":"PASS"',node))==6 and 'Keycloak SDK PASS:' in node and '"checks":46' in node and '"checks":67' in node
assert 'Finished' in (out/'clippy.log').read_text() and 'error:' not in (out/'clippy.log').read_text()
assert 'PASS: owned cluster kf8-tfpa20261109 deleted and tf9 VM stopped' in (out/'cleanup.log').read_text()
tests=json.loads((out/'verifier-tests.json').read_text());assert tests['status']=='PASS' and len(tests['positive']['cases'])==3 and len(tests['negative'])==6
modes=json.loads((out/'mode-negatives.json').read_text());assert modes['status']=='PASS' and len(modes['cases'])==4
records=0
for name in ('provider-kill','terraform-kill','deadline-late'):
 src=out/'cases'/name;n=json.loads((src/'sdk-native-report.json').read_text());p=json.loads((src/'active-child-proof.json').read_text())
 for value in (n['intent'],p['initial_intent']):Draft202012Validator(json.loads((root/'spec/drafts/terraform-apply-v0.1.schema.json').read_text())).validate(value);records+=1
 Draft202012Validator(json.loads((root/'spec/drafts/terraform-gateway-v0.1.schema.json').read_text())).validate(json.loads((src/'sdk-registration.json').read_text()));records+=1
 v=Draft202012Validator(json.loads((root/'spec/drafts/terraform-plan-v0.2.schema.json').read_text()))
 for f in ('manifest.json','report.json'):v.validate(json.loads((src/f).read_text()));records+=1
for name,schema in [('legacy-sdk','terraform-apply-v0.1'),('pair-partial','terraform-pair-apply-v0.1')]:
 v=Draft202012Validator(json.loads((root/f'spec/drafts/{schema}.schema.json').read_text()));v.validate(json.loads((out/'cases'/name/'sdk-native-report.json').read_text())['intent']);records+=1
subprocess.run(['git','diff','--exit-code',baseline,'--','sdk/node','tests/sdk','spec','fixtures'],check=True)
prior={}
for dirname in ('terraform-pair-gateway-2026-11-11','terraform-pair-apply-2026-11-09','terraform-failure-2026-11-09'):
 p=root/'results/verification'/dirname
 for n,h in json.loads((p/'artifact-hashes.json').read_text()).items():assert sha(p/n)==h
 prior.update({str(f.relative_to(root)):sha(f) for f in p.rglob('*') if f.is_file()})
(out/'prior-evidence-hashes.json').write_text(json.dumps(prior,indent=2)+'\n')
files={p for p in git('diff','--name-only',baseline) if not p.startswith('results/')};files.update(p for p in git('ls-files','--others','--exclude-standard') if not p.startswith('results/'));files.update(['Cargo.toml','Cargo.lock','tests/sdk/package.json','tests/sdk/package-lock.json','scripts/start-etcd.sh']);files=sorted(files)
(out/'source-hashes.json').write_text(json.dumps({p:sha(root/p) for p in files},indent=2)+'\n')
tracked=set(git('ls-files','--',*files));patch=subprocess.check_output(['git','diff','--binary',baseline,'--',*sorted(tracked)])
for p in files:
 if p not in tracked:
  r=subprocess.run(['git','diff','--no-index','--binary','--','/dev/null',p],capture_output=True);assert r.returncode in (0,1);patch+=r.stdout
(out/'source.patch').write_bytes(patch)
summary={'date':'2026-11-11','baseline':git('rev-parse',baseline)[0],'intermediate_commit':'1ef7a12','status':'N2g bounded active-child cleanup/late-effect qualification complete; whole-service/cgroup and production gates open','platform':'darwin_arm64','final_cohort_rust_test_runs':104,'core_tests':99,'active_child_cases':3,'compatibility_live_cases':2,'qualified_failures':0,'ignored':0,'skips':0,'excluded_preliminary_live_failures':2,'excluded_preliminary_sandbox_inspection_failures':1,'auxiliary_pipe_regression':'passed; repeated in final core count','sdk_suites':7,'existing_single_sdk_checks':46,'existing_pair_sdk_checks':67,'positive_replays':3,'negative_replays':6,'mode_negatives':4,'schema_records':records,'source_files':len(files),'source_patch_sha256':sha(out/'source.patch'),'terraform':'1.17.1','provider':'2.38.0','sdk':'@modelcontextprotocol/client 2.3.0','etcd':'3.6.5; three-member loopback','provenance':'All five final live cases and core passed in final3; unit-only inherited-pipe regression added during the cohort; production cleanup implementation unchanged across final cohort. Preliminary attempts excluded.','tool_sha256':{n:sha(root/'.cache/terraform-tools-1.17.1'/n) for n in ('terraform','kubernetes')},'runtime_binary_sha256':{n:sha(Path('/private/tmp/kedgeflow-paper-target/debug')/n) for n in ('kf-proxy','kf-broker')},'limits':['Level C; no target atomicity or authoritative no-effect barrier','generated same-host roles and fixture-administered gate/audit, not independent attestation','gateway SIGKILL with live children and malicious group escape not contained','Linux cgroup/service isolation and production credentials, broader graphs and remote backends open','unknown remains held; no release/reapply/repair/inverse']}
summary['observations']={name:{'intervention_to_unknown_ms':(p:=json.loads((out/'cases'/name/'active-child-proof.json').read_text()))['ordinary_unknown_at']-p['intervention_at'],'backend_serial_at_boundary':p['backend_at_boundary']['serial'],'backend_serial_after':p['backend_after_release']['serial'],'gate_forwarded':p['gate_completion']['forwarded']} for name in ('provider-kill','terraform-kill','deadline-late')}
summary['versions']={n:subprocess.check_output(cmd,text=True).strip() for n,cmd in [('rustc',['/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc','--version']),('node',['node','--version']),('python',['python3','--version'])]}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
logs=[];env={**os.environ,'PATH':'/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_HOME':'/private/tmp/kedgeflow-cargo','CARGO_TARGET_DIR':'/private/tmp/kedgeflow-paper-target'}
for cmd in [['cargo','fmt','--all','--','--check'],[str(root/'.cache/terraform-apply-python/bin/ruff'),'check','scripts/test-terraform-plan.py','scripts/terraform_active_gate.py'],[str(root/'.cache/terraform-apply-python/bin/ruff'),'format','--check','scripts/test-terraform-plan.py','scripts/terraform_active_gate.py'],['node','--check','scripts/verify-terraform-active.mjs'],['node','scripts/verify-terraform-active.mjs',str(out)],['node','scripts/verify-terraform-pair-gateway.mjs',str(root/'results/verification/terraform-pair-gateway-2026-11-11')],['git','diff','--check']]:
 r=subprocess.run(cmd,capture_output=True,text=True,env=env);logs.append('COMMAND: '+' '.join(cmd)+'\n'+r.stdout+r.stderr+'EXIT: '+str(r.returncode));assert r.returncode==0,logs[-1]
(out/'checks.log').write_text('Checks in progress\n');(out/'artifact-hashes.json').write_text('{}\n')
for p in [out/'README.md',*(root/n for n in files if n.endswith('.md'))]:
 for link in re.findall(r'\]\(([^)]+)\)',p.read_text()):
  if '://' not in link and not link.startswith('#'):assert (p.parent/link.split('#')[0]).exists(),(p,link)
for p in (out/'cases').rglob('*'):
 if p.is_file():
  t=p.read_text();assert not re.search(r'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',t),p;assert 'PRIVATE KEY-----' not in t,p
logs.append('PASS: 104 final-cohort Rust runs; 7 SDK suites; 3 positive/6 negative local replays; 4 mode negatives; active real provider/TF/deadline checkpoints; late target effect after local cleanup; held original status; schemas, frozen SDK/spec/fixtures and prior evidence; source pins, links, credential scan and owned cleanup')
(out/'checks.log').write_text('\n\n'.join(logs)+'\n')
(out/'artifact-hashes.json').write_text(json.dumps({str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='artifact-hashes.json'},indent=2)+'\n')
print(json.dumps({'evidence':str(out),'source_files':len(files),'rust_runs':104,'schema_records':records}))
