from pathlib import Path
import subprocess,shlex,re,io,tarfile
r=Path.cwd();ssh=['ssh','-F','/private/tmp/kftf9-lima/colima-tf9/ssh.config','lima-colima-tf9']
def vm(args,**kw):return subprocess.run([*ssh,shlex.join(args)],check=True,timeout=180,**kw)
i='/opt/kf-tfi-input-20261111'
vm(['sudo','mkdir','-p',i+'/source/crates/kedgeflow'])
# /source is already linked to the task fixture input.
bins=re.findall(r'Executable .*? \((/target/[^)]+)\)',(r/'.cache/terraform-linux-build/runtime-resized.log').read_text())
bins=[b for b in bins if '/governance-' not in b]
s='set -eu\numask 077\n'+''.join(shlex.join([b,'--test-threads=1'])+'\n' for b in bins)
s+='for f in agent-vectors lease-vectors family-saga-vectors managed-drain-vectors keycloak-vectors terraform-vectors terraform-pair-vectors; do '+i+'/node/bin/node '+i+'/source/tests/sdk/$f.mjs; done\n'
vm(['sudo','tee',i+'/core.sh'],input=s.encode(),stdout=subprocess.DEVNULL)
cmd=['env','TMPDIR=/opt/kf-tfi-core-20261112','ETCD_BINARY='+i+'/tools/etcd','KF_ETCD_CLIENT_PORTS=14379,24379,34379','KF_ETCD_PEER_PORTS=14380,24380,34380','bash',i+'/source/scripts/start-etcd.sh','--','bash',i+'/core.sh']
with (r/'.cache/terraform-linux-build/core-complete.log').open('w') as f:vm(cmd,stdout=f,stderr=subprocess.STDOUT)
print('Linux core and SDK suites passed')
