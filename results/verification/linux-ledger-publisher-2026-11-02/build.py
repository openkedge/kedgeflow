import hashlib,json,os,runpy,secrets,subprocess
from pathlib import Path
root=Path.cwd();out=root/'.cache/linux-credentials-release-final-serial'
env=dict(os.environ,DOCKER_CONFIG=str(root/'.cache/pilot-linux-docker'),DOCKER_HOST='unix:///tmp/kf8-01a12982-colima/kfmlp20261101/docker.sock')
docker=str(root/'.cache/m8-kube-tools/bin/docker')
image='rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157'
binaries=runpy.run_path(str(root/'scripts/package-linux.py'))['BINARIES']
command='tar -xf /tmp/source.tar -C /source && rustc --version && cargo --version && cargo build --locked --offline --release --jobs 1 '+' '.join('--bin '+name for name in binaries)
def run(args):return subprocess.run([docker,*args],env=env,check=True,capture_output=True,text=True)
name='kf-ledger-release-'+secrets.token_hex(4)
cid=run(['create','--name',name,'--label','org.openkedge.fixture=ledger-credentials-build','--memory','4g','--cpus','2','--pids-limit','512','--mount','type=volume,source=kf-mlp-linux-cargo-20261101,target=/usr/local/cargo/registry','--mount','type=volume,source=kf-mlp-linux-target-20261101,target=/target','--workdir','/source','--env','CARGO_HOME=/usr/local/cargo','--env','CARGO_TARGET_DIR=/target',image,'sh','-ec',command]).stdout.strip()
meta={'container':cid,'name':name,'image':image,'command':command,'binaries':binaries,'source_sha256':json.loads((out/'source.json').read_text())}
(out/'build.json').write_text(json.dumps(meta,indent=2)+'\n');print('build started',name,flush=True)
try:
 run(['cp',str(out/'source.tar'),cid+':/tmp/source.tar'])
 with (out/'build.log').open('wb') as log:subprocess.run([docker,'start','--attach',cid],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
 (out/'bins').mkdir(exist_ok=True)
 for binary in binaries:run(['cp',cid+':/target/release/'+binary,str(out/'bins'/binary)])
 assert all(hashlib.sha256((root/n).read_bytes()).hexdigest()==d for n,d in meta['source_sha256'].items())
 meta.update(source_unchanged=True,binary_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (out/'bins').iterdir()})
 print('all ten binaries built; source unchanged',flush=True)
finally:
 inspection=json.loads(run(['inspect',cid]).stdout)[0];meta.update(state=inspection['State'],image_id=inspection['Image'])
 run(['rm','-f',cid]);meta['container_removed']=True
 (out/'build.json').write_text(json.dumps(meta,indent=2)+'\n')
