from pathlib import Path
import json,hashlib,subprocess,shutil,re,os
from jsonschema import Draft202012Validator
root=Path.cwd();out=root/'results/verification/terraform-gateway-death-2026-11-11';base=root/'.cache/terraform-gateway-death-final';baseline='25bfbe7'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*a):return subprocess.check_output(['git',*a],text=True).splitlines()
out.mkdir(parents=True,exist_ok=True)
for name in ('gateway-kill-drop','gateway-kill-late','deadline-late','legacy-sdk'):
 src=base/name;shutil.copytree(src,out/'cases'/name,dirs_exist_ok=True)
 log=(src/'execution-diagnostic.log').read_text();assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in log and 'SKIP' not in log,name
 steps=json.loads((src/'steps.json').read_text());neg={'planner cannot patch ConfigMaps':1,'refuse swapped saved plan':1,'refuse pinned executable provider hook':1,'no apply entry point':2,'single-resource inspector refuses pair profile':1}
 for row in steps:assert row['exit_code']==neg.get(row['step'],0),(name,row)
 assert steps[-1]['step']=='cleanup owned namespace'
 n=json.loads((src/'sdk-native-report.json').read_text());crash=name.startswith('gateway-');state='dispatch_authorized' if crash else 'unknown' if name=='deadline-late' else 'committed'
 assert n['native_state']==n['resumed']['state']==state
 assert n['first']['state'] in ('unavailable','dispatch_authorized') if crash else n['first']['state']==state
 for k in ('claims','permits','dispatches','intents','intent_requests'):assert n['counters'][k]==1,(name,k)
 assert n['counters']['ordinary_outcomes']==(0 if crash else 1)
 assert n['counters']['intent_outcomes']==(1 if name=='legacy-sdk' else 0)
 for k in ('grant_expired_at_query','domain_revoked_at_query','broker_stopped_at_query','writer_absent_at_query','retained_history_unchanged'):assert n[k]
for src,dst in [
 (base/'regressions.log','regressions.log'),(root/'.cache/terraform-gateway-death-node.log','node-vectors.log'),(root/'.cache/terraform-gateway-death-clippy.log','clippy.log'),
 (root/'.cache/terraform-gateway-death-live.log','live.log'),(root/'.cache/terraform-gateway-death-qualify.py','qualification-driver.py'),
 (root/'.cache/start-terraform-gateway-death-env.py','environment-driver.py'),(root/'.cache/terraform-gateway-death-cleanup.py','cleanup-driver.py'),
 (root/'.cache/terraform-gateway-env/gateway-death-start.log','startup.log'),(root/'.cache/terraform-gateway-env/gateway-death-cleanup.log','cleanup.log'),
 (root/'.cache/terraform-gateway-env/gateway-death-kubernetes-version.json','kubernetes-version.json'),(root/'.cache/terraform-gateway-env/pair-apply-audit-policy.json','audit-policy.json'),(root/'.cache/terraform-gateway-env/pair-apply-kind.json','kind-config.json'),
 (root/'.cache/test-terraform-gateway-death-verifier.mjs','verifier-test-driver.mjs'),(root/'.cache/terraform-gateway-death-verifier-tests.json','verifier-tests.json'),
 (root/'.cache/terraform-gateway-death-mode-negatives.json','mode-negatives.json'),(root/'.cache/terraform-gateway-death-stage-cleanup.json','stage-cleanup.json'),(root/'.cache/collect-terraform-gateway-death.py','collector.py')]:shutil.copyfile(src,out/dst)
(out/'preliminary').mkdir(exist_ok=True);shutil.copyfile(root/'.cache/terraform-gateway-death-build.log',out/'preliminary/fixture-value-type-build.log')
reg=(out/'regressions.log').read_text();counts=[int(x) for x in re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',reg)];assert counts==[20,20,7,11,5,14,7,3,12] and sum(counts)==99,counts
assert 'SKIP' not in reg and '"regressions": 0' in (out/'live.log').read_text()
node=(out/'node-vectors.log').read_text();assert len(re.findall('"status":"PASS"',node))==6 and 'Keycloak SDK PASS:' in node and '"checks":46' in node and '"checks":67' in node
assert 'Finished' in (out/'clippy.log').read_text() and 'error:' not in (out/'clippy.log').read_text()
assert 'PASS: owned cluster kf8-tfpa20261109 deleted and tf9 VM stopped' in (out/'cleanup.log').read_text()
tests=json.loads((out/'verifier-tests.json').read_text());assert tests['status']=='PASS' and len(tests['positive']['cases'])==2 and len(tests['negative'])==6
modes=json.loads((out/'mode-negatives.json').read_text());assert modes['status']=='PASS' and len(modes['cases'])==4
records=0
for name in ('gateway-kill-drop','gateway-kill-late','deadline-late'):
 src=out/'cases'/name;n=json.loads((src/'sdk-native-report.json').read_text());p=json.loads((src/('gateway-death-proof.json' if name.startswith('gateway-') else 'active-child-proof.json')).read_text())
 for value in (n['intent'],p['initial_intent']):Draft202012Validator(json.loads((root/'spec/drafts/terraform-apply-v0.1.schema.json').read_text())).validate(value);records+=1
 Draft202012Validator(json.loads((root/'spec/drafts/terraform-gateway-v0.1.schema.json').read_text())).validate(json.loads((src/'sdk-registration.json').read_text()));records+=1
 v=Draft202012Validator(json.loads((root/'spec/drafts/terraform-plan-v0.2.schema.json').read_text()))
 for f in ('manifest.json','report.json'):v.validate(json.loads((src/f).read_text()));records+=1
v=Draft202012Validator(json.loads((root/'spec/drafts/terraform-apply-v0.1.schema.json').read_text()));v.validate(json.loads((out/'cases/legacy-sdk/sdk-native-report.json').read_text())['intent']);records+=1
subprocess.run(['git','diff','--exit-code',baseline,'--','crates/kedgeflow/src','sdk/node','tests/sdk','spec','fixtures'],check=True)
prior={}
for dirname in ('terraform-active-child-2026-11-11','terraform-pair-gateway-2026-11-11','terraform-failure-2026-11-09'):
 p=root/'results/verification'/dirname
 for n,h in json.loads((p/'artifact-hashes.json').read_text()).items():assert sha(p/n)==h
 prior.update({str(f.relative_to(root)):sha(f) for f in p.rglob('*') if f.is_file()})
(out/'prior-evidence-hashes.json').write_text(json.dumps(prior,indent=2)+'\n')
runtime={n:sha(Path('/private/tmp/kedgeflow-paper-target/debug')/n) for n in ('kf-proxy','kf-broker')}
old=json.loads((root/'results/verification/terraform-active-child-2026-11-11/summary.json').read_text())['runtime_binary_sha256'];assert runtime==old,(runtime,old)
files={p for p in git('diff','--name-only',baseline) if not p.startswith('results/')};files.update(p for p in git('ls-files','--others','--exclude-standard') if not p.startswith('results/'));files.update(['Cargo.toml','Cargo.lock','tests/sdk/package.json','tests/sdk/package-lock.json','scripts/start-etcd.sh','scripts/terraform_active_gate.py','scripts/verify-terraform-active.mjs','crates/kedgeflow/tests/support/terraform_gateway.rs']);files=sorted(files)
(out/'source-hashes.json').write_text(json.dumps({p:sha(root/p) for p in files},indent=2)+'\n')
tracked=set(git('ls-files','--',*files));patch=subprocess.check_output(['git','diff','--binary',baseline,'--',*sorted(tracked)])
for p in files:
 if p not in tracked:
  r=subprocess.run(['git','diff','--no-index','--binary','--','/dev/null',p],capture_output=True);assert r.returncode in (0,1);patch+=r.stdout
(out/'source.patch').write_bytes(patch)
summary={'date':'2026-11-11','baseline':git('rev-parse',baseline)[0],'intermediate_commit':'c567cab','status':'N2h bounded whole-gateway-death qualification complete; production descendant/cgroup containment remains open','platform':'darwin_arm64','final_cohort_rust_test_runs':103,'core_tests':99,'gateway_death_cases':2,'fresh_compatibility_live_cases':2,'qualified_failures':0,'ignored':0,'skips':0,'excluded_preliminary_compile_failures':1,'sdk_suites':7,'existing_single_sdk_checks':46,'existing_pair_sdk_checks':67,'positive_replays':2,'negative_replays':6,'mode_negatives':4,'schema_records':records,'source_files':len(files),'source_patch_sha256':sha(out/'source.patch'),'terraform':'1.17.1','provider':'2.38.0','sdk':'@modelcontextprotocol/client 2.3.0','etcd':'3.6.5; three-member loopback','tool_sha256':{n:sha(root/'.cache/terraform-tools-1.17.1'/n) for n in ('terraform','kubernetes')},'runtime_binary_sha256':runtime,'runtime_byte_identical_to_N2g':True,'limits':['Level C; no target atomicity, production containment or no-effect barrier','gateway SIGKILL leaves active descendants; fixture group cleanup is not a production mechanism','late captured request can commit after expiry even when local descendants have ended','same-host fixture-administered gate/identity/evidence/audit, not independent attestation','Linux cgroups/service custody, provider escape, production credentials, broader graphs and remote backends open','original phase stays held; no repair/release/retry/inverse']}
summary['observations']={name:{'gateway_exit_signal':(p:=json.loads((out/'cases'/name/'gateway-death-proof.json').read_text()))['gateway_exit_signal'],'children_alive_after_gateway_death':len(p['orphans_after_gateway_death']),'children_alive_at_expiry':len(p['group_at_expiry']),'fixture_group_kill':p['fixture_group_kill'],'backend_serial_after':p['backend_after_release']['serial'],'gate_forwarded':p['gate_completion']['forwarded']} for name in ('gateway-kill-drop','gateway-kill-late')}
summary['versions']={n:subprocess.check_output(cmd,text=True).strip() for n,cmd in [('rustc',['/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc','--version']),('node',['node','--version']),('python',['python3','--version'])]}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
logs=[];env={**os.environ,'PATH':'/Users/joehe/.rustup/toolchains/stable-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_HOME':'/private/tmp/kedgeflow-cargo','CARGO_TARGET_DIR':'/private/tmp/kedgeflow-paper-target'}
for cmd in [['cargo','fmt','--all','--','--check'],[str(root/'.cache/terraform-apply-python/bin/ruff'),'check','scripts/test-terraform-plan.py','scripts/terraform_active_gate.py'],[str(root/'.cache/terraform-apply-python/bin/ruff'),'format','--check','scripts/test-terraform-plan.py','scripts/terraform_active_gate.py'],['node','--check','scripts/verify-terraform-gateway-death.mjs'],['node','scripts/verify-terraform-gateway-death.mjs',str(out)],['node','scripts/verify-terraform-active.mjs',str(root/'results/verification/terraform-active-child-2026-11-11')],['git','diff','--check']]:
 r=subprocess.run(cmd,capture_output=True,text=True,env=env);logs.append('COMMAND: '+' '.join(cmd)+'\n'+r.stdout+r.stderr+'EXIT: '+str(r.returncode));assert r.returncode==0,logs[-1]
(out/'checks.log').write_text('Checks in progress\n');(out/'artifact-hashes.json').write_text('{}\n')
for p in [out/'README.md',*(root/n for n in files if n.endswith('.md'))]:
 for link in re.findall(r'\]\(([^)]+)\)',p.read_text()):
  if '://' not in link and not link.startswith('#'):assert (p.parent/link.split('#')[0]).exists(),(p,link)
for p in (out/'cases').rglob('*'):
 if p.is_file():
  t=p.read_text();assert not re.search(r'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',t),p;assert 'PRIVATE KEY-----' not in t,p
logs.append('PASS: 103 final-cohort Rust runs; 7 SDK suites; 2 positive/6 negative whole-death replays; 4 mode negatives; actual reaped gateway SIGKILL, surviving descendants and late target effect; held dispatch_authorized recovery; schemas; production runtime/SDK/spec/fixtures unchanged; byte-identical shipping runtime; prior evidence/source seals; links, credential scan and owned cleanup')
(out/'checks.log').write_text('\n\n'.join(logs)+'\n')
(out/'artifact-hashes.json').write_text(json.dumps({str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='artifact-hashes.json'},indent=2)+'\n')
print(json.dumps({'evidence':str(out),'source_files':len(files),'rust_runs':103,'schema_records':records}))
