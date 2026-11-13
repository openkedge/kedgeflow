from pathlib import Path
import hashlib,json,re,shutil,subprocess
from jsonschema import Draft202012Validator
r=Path.cwd();out=r/'results/verification/terraform-acceptance-2026-11-12';base='ba1a21d';implementation='214884f'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],text=True).strip()
out.mkdir(parents=True,exist_ok=True)
shutil.copytree(r/'.cache/terraform-acceptance-public',out/'synthetic',dirs_exist_ok=True)
for src,dst in [('.cache/terraform-acceptance-final.log','tests.log'),('.cache/terraform-acceptance-sdk.log','sdk-vectors.log'),('.cache/terraform-acceptance-schema.json','schema-checks.json'),('.cache/collect-terraform-acceptance.py','collector.py'),('.cache/check-terraform-acceptance-schema.py','schema-check-driver.py')]:shutil.copyfile(r/src,out/dst)
log=(out/'tests.log').read_text();assert 'tests 55' in log and 'pass 55' in log and 'fail 0' in log and 'skipped 0' in log
sdk=(out/'sdk-vectors.log').read_text();assert sdk.count('"status":"PASS"')==6 and 'Keycloak SDK PASS:' in sdk
v=Draft202012Validator(json.loads((r/'spec/drafts/terraform-deployment-acceptance-v0.1.schema.json').read_text()));records=[]
for name in ['deployment.json','trust.json','evidence.json','approvals.json']:
 body=json.loads((out/'synthetic'/name).read_text());records.append(body)
 if name=='evidence.json':records.extend(body['gates'])
 if name=='approvals.json':records.extend(body['approvals'])
for body in records:v.validate(body)
assert len(records)==18
# A pending request uses only synthetic input. It supplies no observation/signoff.
if not (out/'pending-request').exists():
 p=subprocess.run(['node','scripts/prepare-terraform-acceptance.mjs','--deployment',str(out/'synthetic/deployment.json'),'--output',str(out/'pending-request')],capture_output=True,text=True,check=True)
 (out/'prepare-report.json').write_text(p.stdout)
assert json.loads((out/'prepare-report.json').read_text())['state']=='awaiting_deployed_evidence_and_owners'
assert json.loads((out/'pending-request/approvals.json').read_text())['approvals']==[]
requirements=json.loads(subprocess.check_output(['node','--input-type=module','-e',"import {GATES} from './scripts/terraform-acceptance-records.mjs'; console.log(JSON.stringify(GATES));"],text=True))
(out/'pending-inputs.json').write_text(json.dumps({'state':'requires_approved_deployment_inputs','production_gap_closed':False,'production_qualified':False,'execution_authority':False,'fresh_deployment_measurements':0,'actual_owner_approvals':0,'missing_external_references':['approved deployment identity and exact current source/archive/configuration/action/writer-inventory pins','approved owner trust file and externally pinned SHA-256','current deployed observations and retained artifacts for all gates','seven independently authorized owner acceptance records'],'required_gates':requirements,'existing_linux_record':'../terraform-systemd-2026-11-12','existing_linux_record_is_owner_acceptance':False},indent=2)+'\n')
checks=[]
commands=[['node','--check',n] for n in ['scripts/terraform-acceptance-records.mjs','scripts/verify-terraform-acceptance.mjs','scripts/prepare-terraform-acceptance.mjs','tests/test_terraform_acceptance.mjs']]
commands += [['git','diff','--exit-code',base,'--','crates/kedgeflow/src','sdk/node','tests/sdk','fixtures','spec/kedgeflow.schema.json','deploy'],['git','diff','--check']]
for cmd in commands:
 p=subprocess.run(cmd,capture_output=True,text=True);checks.append('COMMAND: '+' '.join(cmd)+'\n'+p.stdout+p.stderr+'EXIT: '+str(p.returncode));assert p.returncode==0
# Replay frozen synthetic records at their declared synthetic test clock only.
code="""import {evaluate} from './scripts/terraform-acceptance-records.mjs';import {readFile} from 'node:fs/promises';import {join} from 'node:path';const root=process.argv[1];const e=JSON.parse(await readFile(join(root,'expected.json'),'utf8'));const report=await evaluate(root,{...e,trustFile:join(root,'trust.json')});if(report.state!=='owner_records_verified'||report.production_qualified||report.execution_authority)process.exit(1);console.log(JSON.stringify({synthetic_only:true,report},null,2));"""
p=subprocess.run(['node','--input-type=module','-e',code,str(out/'synthetic')],capture_output=True,text=True,check=True);(out/'synthetic-replay.json').write_text(p.stdout)
prior={}
old=r/'results/verification/terraform-systemd-2026-11-12'
for n,h in json.loads((old/'artifact-hashes.json').read_text()).items():assert sha(old/n)==h,n
for p in old.rglob('*'):
 if p.is_file():prior[str(p.relative_to(r))]=sha(p)
(out/'prior-evidence-hashes.json').write_text(json.dumps(prior,indent=2)+'\n')
files=set(git('diff','--name-only',base,implementation).splitlines());files.add('sdk/node/records.mjs')
(out/'source-hashes.json').write_text(json.dumps({n:sha(r/n) for n in sorted(files)},indent=2)+'\n')
(out/'source.patch').write_bytes(subprocess.check_output(['git','diff','--binary',base,implementation,'--',*sorted(files)]))
(out/'summary.json').write_text(json.dumps({'date':'2026-11-12','baseline':git('rev-parse',base),'implementation_commit':git('rev-parse',implementation),'status':'administrative acceptance checker qualified; actual production deployment/owner inputs absent','new_node_tests':55,'qualified_failures':0,'skips':0,'existing_sdk_suites':7,'schema_positive_records':18,'schema_negative_records':8,'synthetic_gate_checks':sum(len(g['checks']) for g in requirements.values()),'required_owner_roles':len(requirements),'synthetic_historical_replays':1,'fresh_live_terraform_workflows':0,'actual_owner_approvals':0,'production_gap_closed':False,'production_qualified':False,'execution_authority':False,'accepted_runtime_sdk_spec_and_deployment_unchanged':True,'source_files':len(files),'source_patch_sha256':sha(out/'source.patch'),'node':subprocess.check_output(['node','--version'],text=True).strip(),'limits':['synthetic random in-memory test signers; no deployed measurement or independent approval','externally approved current trust, clock, administration independence and factual observations remain owner responsibilities','offline verifier does not inspect live installed state or discover trust withdrawal','report is not runtime execution authority and package production qualification stays false']},indent=2)+'\n')
(out/'checks.log').write_text('\n\n'.join(checks)+'\nPASS: frozen synthetic replay; 18 schema records; prior Linux artifact seals; runtime/SDK/frozen schema/deployment unchanged\n')
(out/'artifact-hashes.json').write_text('{}\n')
for p in [out/'README.md',*(r/n for n in files if n.endswith('.md'))]:
 for link in re.findall(r'\]\(([^)]+)\)',p.read_text()):
  if '://' not in link and not link.startswith('#'):assert (p.parent/link.split('#')[0]).exists(),(p,link)
for p in out.rglob('*'):
 if p.is_file() and p.name not in ['source.patch']:
  text=p.read_text();assert not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]',text),p
(out/'artifact-hashes.json').write_text(json.dumps({str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='artifact-hashes.json'},indent=2)+'\n')
print(json.dumps({'status':'PASS','node_tests':55,'schema_records':18,'actual_owner_approvals':0,'production_gap_closed':False}))
