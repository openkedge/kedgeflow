from pathlib import Path
import json,shutil,hashlib,re,subprocess
r=Path.cwd();base=r/'.cache/terraform-systemd-qualified';out=r/'results/verification/terraform-systemd-2026-11-12'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
out.mkdir(parents=True,exist_ok=True)
for name,dest in [('normal','normal'),('cgroup-drop','cgroup-drop'),('cgroup-late','cgroup-late'),('pair-partial','partial')]:
 src=base/name
 log=(src/'execution-diagnostic.log').read_text();assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in log and 'SKIP' not in log,name
 shutil.copytree(src,out/'cases'/dest,dirs_exist_ok=True)
 shutil.copyfile(base/(name+'.log'),out/(dest+'.log'))
for name in ['host.json','service-starts.jsonl','cleanup.json','live.log']:shutil.copyfile(base/name,out/name)
reg=(r/'.cache/terraform-linux-build/core-complete.log').read_text();end=reg.index('{"status":"PASS"')
reg=reg[:end];counts=[int(x) for x in re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',reg)]
assert counts==[20,20,7,11,5,14,7,3,12],counts
(out/'regressions.log').write_text(reg)
for src,dst in [('sdk-qualified.log','node-vectors.log'),('clippy.log','clippy.log'),('metrics-test.log','metrics-test.log'),('package-tests.log','package-tests.log'),('lint.log','lint.log'),('clean-cluster.log','cluster-start.log'),('runtime-systemd.log','linux-build.log')]:shutil.copyfile(r/'.cache/terraform-linux-build'/src,out/dst)
for src,dst in [('.cache/terraform-linux-tools/pins.json','tool-pins.json'),('.cache/terraform-linux-release/bundle.json','bundle.json'),('.cache/terraform-linux-release/verification.json','bundle-verification.json'),('.cache/terraform-gateway-env/pair-apply-audit-policy.json','audit-policy.json'),('.cache/terraform-gateway-env/pair-apply-kind.json','kind-config.json'),('.cache/collect-terraform-systemd.py','collector.py'),('.cache/resume-terraform-systemd-qualified.py','invocation-driver.py'),('.cache/run-terraform-linux-core.py','core-driver.py'),('.cache/package-terraform-linux.py','package-driver.py'),('.cache/reset-terraform-linux-cluster.py','cluster-driver.py')]:shutil.copyfile(r/src,out/dst)
pre=[]
for dirname in ['first','second','third','fourth','fifth','sixth','seventh']:
 for p in (r/('.cache/terraform-systemd-'+dirname)).rglob('execution-diagnostic.log'):
  pre.append({'attempt':dirname,'case':p.parent.name,'sha256':sha(p),'passed':'test result: ok.' in p.read_text()})
(out/'preliminary').mkdir(exist_ok=True)
(out/'preliminary/diagnostics.json').write_text(json.dumps({'excluded_from_final_denominator':True,'attempt_records':pre,'causes':['guest data disk full; expanded owned disk before final run','missing runtime source-root override','systemctl short-option property spelling in fixture helper','missing libatomic1 dependency for official Node Linux runtime','nested restore transactions omitted by original test counter','old unit handle dropped replacement with reused unit name','old disposable cluster audit line corrupted during earlier disk-full event; replaced entire cluster','core selector initially included full governance suite; aborted, then selected exact 99 tests','VM login umask0002 made private test directories group writable; reran with umask077','SDK historical public fixture JSON initially absent; copied unchanged original bundle/trust vectors','initial Linux build setup lacked platform crates, migration inputs and embedded public vectors; completed pinned dependencies before qualification']},indent=2)+'\n')
print(out)
