from pathlib import Path
import json,hashlib,subprocess,shutil,re,os,copy
from jsonschema import Draft202012Validator
root=Path.cwd();out=root/'results/verification/terraform-pair-gateway-2026-11-11';base=root/'.cache/terraform-pair-gateway-final3';baseline='0fe6ad3'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],text=True).splitlines()
out.mkdir(parents=True,exist_ok=True)
for name in ('normal','lost','partial','partial-lost','legacy-sdk'):
 src=base/name;shutil.copytree(src,out/'cases'/name,dirs_exist_ok=True)
 log=(src/'execution-diagnostic.log').read_text();assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in log and 'SKIP' not in log,name
 steps=json.loads((src/'steps.json').read_text());neg={'planner cannot patch ConfigMaps':1,'refuse swapped saved plan':1,'refuse pinned executable provider hook':1,'no apply entry point':2,'single-resource inspector refuses pair profile':1}
 for step in steps:assert step['exit_code']==neg.get(step['step'],0),(name,step)
 assert steps[-1]['step']=='cleanup owned namespace'
 v=json.loads((src/'sdk-native-report.json').read_text());partial=name.startswith('partial')
 assert v['native_state']==v['first']['state']==v['resumed']['state']==('unknown' if partial else 'committed')
 if name!='legacy-sdk':
  assert v['intent']['state']==('partial_observed' if partial else 'applied') and v['pair']
  assert v['retained_history_unchanged'] and v['permissions_restored']==partial
  assert v['first']['lost_reply_injected']==name.endswith('lost')
  assert (v['first']['lost_reply_bytes']>0)==name.endswith('lost')
  assert v['audit_before_queries']==v['audit_after_queries']
 else:assert 'pair' not in v['intent'] and not v['pair']
 for key in ('claims','permits','dispatches','intents','intent_requests','intent_outcomes','ordinary_outcomes'):assert v['counters'][key]==1,(name,key)
 for key in ('grant_expired_at_query','domain_revoked_at_query','broker_stopped_at_query','writer_absent_at_query'):assert v[key]
for src,dst in [
 (root/'.cache/collect-terraform-pair-gateway.py','collector.py'),
 (base/'regressions.log','regressions.log'),(root/'.cache/terraform-pair-gateway-node.log','node-vectors.log'),(root/'.cache/terraform-pair-gateway-clippy-final.log','clippy.log'),
 (root/'.cache/terraform-pair-gateway-live3.log','live.log'),(root/'.cache/terraform-pair-gateway-qualify3.py','qualification-driver.py'),
 (root/'.cache/start-pair-gateway-env.py','environment-driver.py'),(root/'.cache/terraform-gateway-env/pair-gateway-start.log','startup.log'),
 (root/'.cache/terraform-gateway-env/pair-apply-cleanup.log','cleanup.log'),(root/'.cache/terraform-gateway-env/pair-apply-kubernetes-version.json','kubernetes-version.json'),
 (root/'.cache/terraform-gateway-env/pair-apply-audit-policy.json','audit-policy.json'),(root/'.cache/terraform-gateway-env/pair-apply-kind.json','kind-config.json'),
 (root/'.cache/test-terraform-pair-gateway-verifier.mjs','verifier-test-driver.mjs'),(root/'.cache/terraform-pair-gateway-verifier-tests.json','verifier-tests.json')]:shutil.copyfile(src,out/dst)
pre=out/'preliminary';pre.mkdir(exist_ok=True)
for src,name in [(root/'.cache/terraform-pair-gateway-build.log','compile-scopes.log'),(root/'.cache/terraform-pair-gateway-build2.log','host-space-build.log'),(root/'.cache/terraform-pair-gateway-environment-recovery.log','vm-recovery.log')]:shutil.copyfile(src,pre/name)
for cohort,name in [('terraform-pair-gateway-final','vm-read-only'),('terraform-pair-gateway-final2','missing-ledger')]:
 src=root/'.cache'/cohort/'normal';dst=pre/name;dst.mkdir(exist_ok=True)
 for filename in ('steps.json','execution-diagnostic.log'):
  if (src/filename).exists():shutil.copyfile(src/filename,dst/filename)
 shutil.copyfile(src.parent/'normal.log',dst/'parent.log')
reg=(out/'regressions.log').read_text();counts=[int(n) for n in re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',reg)]
assert counts==[19,20,7,11,5,14,7,3,12] and sum(counts)==98,counts
assert 'SKIP' not in reg and '"regressions": 0' in (out/'live.log').read_text()
node=(out/'node-vectors.log').read_text();assert len(re.findall('"status":"PASS"',node))==6 and 'Keycloak SDK PASS:' in node and '"checks":46' in node and '"checks":67' in node
assert 'Finished' in (out/'clippy.log').read_text() and 'error:' not in (out/'clippy.log').read_text()
assert 'PASS: owned cluster kf8-tfpa20261109 deleted and tf9 VM stopped' in (out/'cleanup.log').read_text()
tests=json.loads((out/'verifier-tests.json').read_text());assert tests['status']=='PASS' and len(tests['positive']['cases'])==4 and len(tests['negative'])==5
schema=json.loads((root/'spec/drafts/terraform-pair-gateway-v0.1.schema.json').read_text());Draft202012Validator.check_schema(schema);v=Draft202012Validator(schema)
records=0
for p in (root/'fixtures/terraform-pair-gateway').glob('*.json'):v.validate(json.loads(p.read_text()));records+=1
pair_apply=Draft202012Validator(json.loads((root/'spec/drafts/terraform-pair-apply-v0.1.schema.json').read_text()));pair_plan=Draft202012Validator(json.loads((root/'spec/drafts/terraform-pair-plan-v0.1.schema.json').read_text()))
for name in ('normal','lost','partial','partial-lost'):
 src=out/'cases'/name;v.validate(json.loads((src/'sdk-registration.json').read_text()));records+=1
 data=json.loads((src/'sdk-native-report.json').read_text());pair_apply.validate(data['intent']);records+=1
 for filename in ('manifest.json','report.json'):pair_plan.validate(json.loads((src/filename).read_text()));records+=1
 if name=='normal':
  c=data['first']['terminal_result']['structuredContent'];pair_apply.validate(c['kedgeflow_terraform_report']);records+=1
  metadata=c['kedgeflow_terraform_binding'];v.validate(metadata);records+=1
  v.validate({k:metadata[k] for k in ('profile','runner_profile','guard_level','target_atomic')});records+=1
old=Draft202012Validator(json.loads((root/'spec/drafts/terraform-apply-v0.1.schema.json').read_text()));old.validate(json.loads((out/'cases/legacy-sdk/sdk-native-report.json').read_text())['intent']);records+=1
for mutate in [lambda x:x.update({'profile':'KF-TERRAFORM-GATEWAY-0.1-draft'}),lambda x:x['members'][1].update({'command':'apply'})]:
 bad=copy.deepcopy(json.loads((out/'cases/normal/sdk-registration.json').read_text()));mutate(bad);assert list(v.iter_errors(bad))
subprocess.run(['git','diff','--exit-code',baseline,'--','sdk/node/terraform.mjs','fixtures/terraform-plan','spec/kedgeflow.schema.json','spec/drafts/terraform-gateway-v0.1.schema.json','spec/drafts/terraform-apply-v0.1.schema.json','spec/drafts/terraform-plan-v0.1.schema.json','spec/drafts/terraform-plan-v0.2.schema.json','spec/drafts/terraform-pair-apply-v0.1.schema.json','spec/drafts/terraform-pair-plan-v0.1.schema.json'],check=True)
prior={}
for dirname in ('terraform-pair-apply-2026-11-09','terraform-pair-plan-2026-11-09','terraform-gateway-2026-11-09'):
 p=root/'results/verification'/dirname
 for n,h in json.loads((p/'artifact-hashes.json').read_text()).items():assert sha(p/n)==h
 prior.update({str(f.relative_to(root)):sha(f) for f in p.rglob('*') if f.is_file()})
(out/'prior-evidence-hashes.json').write_text(json.dumps(prior,indent=2)+'\n')
files={p for p in git('diff','--name-only',baseline) if not p.startswith('results/')};files.update(p for p in git('ls-files','--others','--exclude-standard') if not p.startswith('results/'));files.update(['Cargo.toml','Cargo.lock','tests/sdk/package.json','tests/sdk/package-lock.json','scripts/start-etcd.sh','scripts/test-terraform-plan.py']);files=sorted(files)
(out/'source-hashes.json').write_text(json.dumps({p:sha(root/p) for p in files},indent=2)+'\n')
tracked=set(git('ls-files','--',*files));patch=subprocess.check_output(['git','diff','--binary',baseline,'--',*sorted(tracked)])
for p in files:
 if p not in tracked:
  r=subprocess.run(['git','diff','--no-index','--binary','--','/dev/null',p],capture_output=True);assert r.returncode in (0,1);patch+=r.stdout
(out/'source.patch').write_bytes(patch)
summary={'date':'2026-11-11','baseline':git('rev-parse',baseline)[0],'intermediate_commit':'bc55d94','status':'N2f3 bounded pair gateway/SDK binding complete; production/deployment gates open','platform':'darwin_arm64','rust_tests':103,'core_tests':98,'pair_gateway_cases':4,'legacy_sdk_cases':1,'qualified_failures':0,'ignored':0,'skips':0,'excluded_preliminary_compile_failures':2,'excluded_preliminary_wrapper_failures':2,'excluded_preliminary_skips':1,'sdk_vector_suites':7,'pair_sdk_checks':67,'existing_single_sdk_checks':46,'positive_evidence_replays':4,'negative_evidence_replays':5,'schema_records':records,'schema_negatives':2,'source_files':len(files),'source_patch_sha256':sha(out/'source.patch'),'terraform':'1.17.1','provider':'2.38.0','sdk':'@modelcontextprotocol/client 2.3.0','etcd':'3.6.5; three-member loopback','tool_sha256':{n:sha(root/'.cache/terraform-tools-1.17.1'/n) for n in ('terraform','kubernetes')},'runtime_binary_sha256':{n:sha(Path('/private/tmp/kedgeflow-paper-target/debug')/n) for n in ('kf-proxy','kf-broker','kf-terraform-pair-plan')},'limits':['Level C; no target atomicity','generated same-host identity/evidence roles and fixture-administered audit, not independent administration or attestation','no automatic repair/release/reapply/compensation','production writer custody, Linux service isolation, active-child termination, broader graphs and remote backends open']}
summary['versions']={n:subprocess.check_output(cmd,text=True).strip() for n,cmd in [('rustc',['/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc','--version']),('node',['node','--version']),('python',['python3','--version'])]}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
logs=[];env={**os.environ,'PATH':'/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_HOME':'/private/tmp/kedgeflow-cargo','CARGO_TARGET_DIR':'/private/tmp/kedgeflow-paper-target'}
for cmd in [['cargo','fmt','--all','--','--check'],['node','--check','sdk/node/terraform-pair.mjs'],['node','--check','sdk/node/agent-adapter.mjs'],['node','scripts/verify-terraform-pair-gateway.mjs',str(out)],['node','scripts/verify-terraform-pair.mjs',str(root/'results/verification/terraform-pair-apply-2026-11-09')],['git','diff','--check']]:
 r=subprocess.run(cmd,capture_output=True,text=True,env=env);logs.append('COMMAND: '+' '.join(cmd)+'\n'+r.stdout+r.stderr+'EXIT: '+str(r.returncode));assert r.returncode==0,logs[-1]
(out/'checks.log').write_text('Checks in progress\n')
(out/'artifact-hashes.json').write_text('{}\n')
for p in [out/'README.md',*(root/n for n in files if n.endswith('.md'))]:
 for link in re.findall(r'\]\(([^)]+)\)',p.read_text()):
  if '://' not in link and not link.startswith('#'):assert (p.parent/link.split('#')[0]).exists(),(p,link)
for p in (out/'cases').rglob('*'):
 if p.is_file():
  t=p.read_text();assert not re.search(r'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',t),p;assert 'PRIVATE KEY-----' not in t,p
logs.append('PASS: 103 Rust runs; 7 SDK suites; 4 positive/5 negative local evidence replays; actual ordered audit and get-only observations; frozen single-resource schemas/runtime; prior sealed evidence unchanged; source pins; links; credential scan; owned cleanup')
(out/'checks.log').write_text('\n\n'.join(logs)+'\n')
(out/'artifact-hashes.json').write_text(json.dumps({str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='artifact-hashes.json'},indent=2)+'\n')
print(json.dumps({'evidence':str(out),'source_files':len(files),'rust_tests':103,'schema_records':records}))
