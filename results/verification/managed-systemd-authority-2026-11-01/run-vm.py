import argparse,io,json,subprocess,tarfile
from pathlib import Path
root=Path.cwd()
p=argparse.ArgumentParser()
for key in ('input','bundle','postgres-bindir','output'):p.add_argument('--'+key,type=Path,required=True)
p.add_argument('--managed',action='store_true');a=p.parse_args();assert a.managed
ssh=['ssh','-F','/tmp/kf8-01a12982-lima/colima-kfmlp20261101/ssh.config','lima-colima-kfmlp20261101']
def run(args,**kw):return subprocess.run(ssh+args,capture_output=True,timeout=270,check=False,**kw)
r=run(['mktemp','-d','/tmp/kf-managed-source.XXXXXX']);assert r.returncode==0,r.stderr
stage=r.stdout.decode().strip();assert Path(stage).parent==Path('/tmp') and Path(stage).name.startswith('kf-managed-source.')
try:
 data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w') as t:
  for name in ['scripts/qualify-systemd-authority.py','scripts/pilot-systemd-role.py','scripts/package-linux.py','scripts/verify-linux-package.py','scripts/start-etcd.sh','migrations/postgres','fixtures','sdk/node','tests/sdk']:
   t.add(root/name,arcname='source/'+name)
  t.add(a.input,arcname='private')
  t.add(a.bundle,arcname='spire-bundle.json')
  t.add(root/'.cache/linux-sql-runtime/postgres',arcname='postgres')
  t.add(root/'.cache/linux-managed-release/bins/governance-test',arcname='governance-test')
  t.add(root/'dist/linux-readiness-final/kedgeflow-core-0.9.0-alpha.1-linux-aarch64-22c3fbfe206bc010.tar.gz',arcname='bundle.tar.gz')
  t.add(root/'.cache/linux-managed-tools/runtime/node-v25.2.1-linux-arm64',arcname='node')
  t.add(root/'.cache/linux-managed-tools/runtime/etcd-v3.6.5-linux-arm64/etcd',arcname='etcd')
 r=run(['tar','-xf','-','-C',stage],input=data.getvalue());assert r.returncode==0,r.stderr
 r=run(['chmod','755',stage]);assert r.returncode==0,r.stderr
 command=['sudo','env','PATH='+stage+'/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','python3',stage+'/source/scripts/qualify-systemd-authority.py','--ephemeral-host','--input',stage+'/private','--bundle',stage+'/spire-bundle.json','--postgres-bindir',stage+'/postgres/bin','--output',stage+'/output','--package',stage+'/bundle.tar.gz','--sha256','59dac3a300e0c1ece9294b9f8bc128a005bcbaf0c98c2c3e73a73489706c15f5','--test-binary',stage+'/governance-test','--etcd',stage+'/etcd']
 r=run(command)
 (a.output/'systemd-runner.stderr').write_bytes(r.stderr)
 result=run(['sudo','tar','-cf','-','-C',stage+'/output','.'])
 if result.returncode==0:
  with tarfile.open(fileobj=io.BytesIO(result.stdout)) as t:t.extractall(a.output,filter='data')
 if r.returncode:raise RuntimeError('Linux managed fixture failed; see systemd-runner.stderr and shipping-sql.log')
 report=json.loads(r.stdout)
 (a.output/'systemd-workflow.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report))
finally:
 r=run(['sudo','rm','-rf','--',stage]);assert r.returncode==0,r.stderr
