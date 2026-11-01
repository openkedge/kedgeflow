import hashlib
import json
import os
import secrets
import subprocess
from pathlib import Path

root = Path.cwd()
output = root / '.cache/linux-readiness-release'
env = dict(os.environ, DOCKER_CONFIG=str(root / '.cache/pilot-linux-docker'), DOCKER_HOST='unix:///tmp/kf8-01a12982-colima/kfmlp20261101/docker.sock')
docker = str(root / '.cache/m8-kube-tools/bin/docker')
image = 'rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157'
binaries = ['kf-proxy','kf-control','kf-broker','kf-postgres-target','kf-recover','kf-supervise','kf-outcomes','kf-governance','kf-restore']
command = 'tar -xf /tmp/source.tar -C /source && rustc --version && cargo --version && cargo build --locked --offline --release --jobs 2 ' + ' '.join('--bin ' + name for name in binaries)
def run(args, **kwargs):
    return subprocess.run([docker, *args], env=env, check=True, **kwargs)
name = 'kf-mlp-readiness-build-' + secrets.token_hex(4)
container = run(['create','--name',name,'--label','org.openkedge.fixture=mlp-linux-readiness-build','--memory','4g','--cpus','2','--pids-limit','512','--mount','type=volume,source=kf-mlp-linux-cargo-20261101,target=/usr/local/cargo/registry','--mount','type=volume,source=kf-mlp-linux-target-20261101,target=/target','--workdir','/source','--env','CARGO_HOME=/usr/local/cargo','--env','CARGO_TARGET_DIR=/target',image,'sh','-ec',command],capture_output=True,text=True).stdout.strip()
metadata = {'container':container,'name':name,'vm':'kfmlp20261101','image':image,'docker_host':env['DOCKER_HOST'],'command':command,'binaries':binaries,'volumes':{'cargo':'kf-mlp-linux-cargo-20261101','target':'kf-mlp-linux-target-20261101'}}
(output/'build.json').write_text(json.dumps(metadata,indent=2)+'\n')
print('container',container,flush=True)
run(['cp',str(output/'source.tar'),container+':/tmp/source.tar'],capture_output=True)
with (output/'build.log').open('wb') as log:
    result = subprocess.run([docker,'start','--attach',container],env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
inspection = json.loads(run(['inspect',container],capture_output=True,text=True).stdout)[0]
metadata.update(state=inspection['State'],image_id=inspection['Image'],host_config={k:inspection['HostConfig'].get(k) for k in ['Privileged','Memory','PidsLimit','NetworkMode','PortBindings']})
assert not metadata['state']['Running']
assert metadata['state']['ExitCode']==0 and result.returncode==0, (metadata['state'],result.returncode)
directory=output/'bins';directory.mkdir()
for binary in binaries:run(['cp',container+':/target/release/'+binary,str(directory/binary)],capture_output=True)
sources=json.loads((output/'source.json').read_text());metadata['source_unchanged']=all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in sources.items());assert metadata['source_unchanged']
metadata['binary_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir())}
(output/'build-final.json').write_text(json.dumps(metadata,indent=2)+'\n')
print('exit',metadata['state']['ExitCode'],'binaries',len(metadata['binary_sha256']),'source_unchanged',True,flush=True)
