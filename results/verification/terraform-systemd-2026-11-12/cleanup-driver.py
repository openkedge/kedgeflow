from pathlib import Path
import subprocess,json,os,shlex
r=Path.cwd();e={**os.environ,**json.loads((r/'.cache/terraform-gateway-env/environment.json').read_text())};t=r/'.cache/m8-kube-tools/bin';cfg=r/'.cache/terraform-gateway-env';ssh=['ssh','-F','/private/tmp/kftf9-lima/colima-tf9/ssh.config','lima-colima-tf9']
log=r/'.cache/terraform-linux-build/cleanup.log'
with log.open('w') as f:
 k=[str(t/'kubectl'),'--kubeconfig',str(cfg/'pair-apply-kubeconfig'),'--context','kind-kf8-tfpa20261109','--request-timeout=15s']
 p=subprocess.run([*k,'get','namespaces','-o','json'],env=e,capture_output=True,text=True,check=True,timeout=25)
 assert not any(x['metadata']['name'].startswith('kf-tf-plan-') for x in json.loads(p.stdout)['items'])
 f.write('PASS: all owned Terraform namespaces removed by case cleanup\n');f.flush()
 p=subprocess.run([*k,'version','-o','json'],env=e,capture_output=True,text=True,check=True,timeout=25)
 (r/'.cache/terraform-linux-build/kubernetes-version.json').write_text(p.stdout)
 program=r'''
import subprocess,json,shutil
from pathlib import Path
bases=[Path('/run/kf-tflinux-'+n) for n in ['20261111a','20261111b','20261111c','20261112d','20261112e','20261112f','20261112g','20261112h','20261112i']]
units=subprocess.check_output(['systemctl','list-units','--all','--no-legend','kf-tfi-*.service'],text=True)
assert not units.strip(),units
assert not list(Path('/etc/sudoers.d').glob('kf-tfi-*'))
assert not [x for x in Path('/etc/passwd').read_text().splitlines() if x.startswith(('kftg026','kfta026'))]
for base in bases:
 work=base/'work'
 if subprocess.run(['mountpoint','-q',str(work)]).returncode==0:subprocess.run(['umount',str(work)],check=True)
 if base.exists():shutil.rmtree(base)
for name in ['kf-tfi-fixture-20261111a','kf-tfi-fixture-20261111b','kf-tfi-fixture-20261111c','kf-tfi-fixture-20261112d','kf-tfi-fixture-20261112e','kf-tfi-fixture-20261112f','kf-tfi-fixture-20261112g','kf-tfi-fixture-20261112h','kf-tfi-fixture-20261112i','kf-tfi-release-20261112']:
 path=Path('/mnt/lima-colima-tf9')/name
 if path.exists():shutil.rmtree(path)
key=Path('/opt/kf-tfi-input-20261111/kubeconfig')
if key.exists():key.unlink()
core=Path('/opt/kf-tfi-core-20261112')
if core.exists():shutil.rmtree(core)
source=Path('/source')
if source.is_symlink() and str(source.readlink())=='/opt/kf-tfi-input-20261111/source':source.unlink()
print('PASS: fixture units/users/sudo removed; all private work mounts, retained SDK/service credentials and admin kubeconfig removed')
'''
 subprocess.run([*ssh,'sudo python3 -'],input=program,text=True,stdout=f,stderr=subprocess.STDOUT,check=True,timeout=120)
 subprocess.run([str(t/'kind'),'delete','cluster','--name','kf8-tfpa20261109','--kubeconfig',str(cfg/'pair-apply-kubeconfig')],env=e,stdout=f,stderr=subprocess.STDOUT,check=True,timeout=120)
 # Remove only labelled build containers and their two task-owned target/cache volumes.
 docker=str(t/'docker')
 p=subprocess.run([docker,'ps','-a','--filter','label=org.openkedge.fixture=terraform-linux-20261111','--format','{{.ID}}'],env=e,capture_output=True,text=True,check=True)
 ids=p.stdout.split()
 subprocess.run([*ssh,'sudo umount /target'],stdout=f,stderr=subprocess.STDOUT,check=True)
 if ids:subprocess.run([docker,'rm',*ids],env=e,stdout=f,stderr=subprocess.STDOUT,check=True)
 subprocess.run([docker,'volume','rm','kf-tfi-target-20261111','kf-tfi-cargo-20261111'],env=e,stdout=f,stderr=subprocess.STDOUT,check=True)
 subprocess.run([str(t/'colima'),'ssh','--profile','tf9','--','sudo','fstrim','--all','--verbose'],env=e,stdout=f,stderr=subprocess.STDOUT,check=True,timeout=60)
 subprocess.run([str(t/'colima'),'stop','--profile','tf9'],env=e,stdout=f,stderr=subprocess.STDOUT,check=True,timeout=120)
 f.write('PASS: owned audited kind cluster deleted; task-labelled build containers/volumes removed; tf9 VM stopped; other profiles untouched\n')
print(log)
