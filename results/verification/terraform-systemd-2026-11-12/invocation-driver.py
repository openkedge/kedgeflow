from pathlib import Path
import subprocess,shlex,io,tarfile,re
r=Path.cwd();ssh=['ssh','-F','/private/tmp/kftf9-lima/colima-tf9/ssh.config','lima-colima-tf9']
def vm(args,**kw):return subprocess.run([*ssh,shlex.join(list(map(str,args)))],check=True,timeout=120,**kw)
# Refresh fixture-only Python; native binaries are the completed Linux build.
payload=io.BytesIO()
with tarfile.open(fileobj=payload,mode='w',dereference=True) as tf:
 for n in ['scripts','deploy/linux/terraform','docs/TERRAFORM_LINUX_DEPLOYMENT.md']:tf.add(r/n,arcname=n)
vm(['sudo','tar','-xf','-','-C','/opt/kf-tfi-input-20261111/source'],input=payload.getvalue())
gov=re.search(r'Executable tests/governance.rs \(([^)]+)\)',(r/'.cache/terraform-linux-build/runtime-final.log').read_text())[1]
vm(['sudo','ln','-sf',gov,'/target/debug/governance-test'])
base='/run/kf-tflinux-20261112i';i='/opt/kf-tfi-input-20261111'
command=['sudo','python3',i+'/source/scripts/qualify-terraform-systemd.py','--ephemeral-host','--base',base,'--source',i+'/source','--bin-dir','/target/debug','--tools',i+'/tools','--kubeconfig',i+'/kubeconfig','--context','kind-kf8-tfpa20261109','--node-dir',i+'/node/bin','--etcd',i+'/tools/etcd','--work-disk','/mnt/lima-colima-tf9/kf-tfi-fixture-20261112i']
with (r/'.cache/terraform-linux-build/systemd-run.log').open('w') as f:p=subprocess.run([*ssh,shlex.join(command)],stdout=f,stderr=subprocess.STDOUT,timeout=1800)
out=r/'.cache/terraform-systemd-qualified';out.mkdir(exist_ok=True)
v=subprocess.run([*ssh,shlex.join(['sudo','tar','-cf','-','-C',base+'/output','.'])],capture_output=True,timeout=60)
if v.returncode==0:
 with tarfile.open(fileobj=io.BytesIO(v.stdout)) as tf:tf.extractall(out,filter='data')
print('qualification exit',p.returncode,flush=True)
raise SystemExit(p.returncode)
