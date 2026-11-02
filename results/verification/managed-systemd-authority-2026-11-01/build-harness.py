import hashlib,json,os,secrets,subprocess,time
from pathlib import Path
root=Path.cwd();out=root/'.cache/linux-managed-release'
env=dict(os.environ,DOCKER_CONFIG=str(root/'.cache/pilot-linux-docker'),DOCKER_HOST='unix:///tmp/kf8-01a12982-colima/kfmlp20261101/docker.sock')
docker=str(root/'.cache/m8-kube-tools/bin/docker')
image='rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157'
command='tar -xf /tmp/source.tar -C /source && rustc --version && cargo --version && cargo rustc --package kedgeflow --locked --offline --release --jobs 1 --features selfhosted-pilot-tests --test governance --message-format=json -- -C lto=thin -C codegen-units=16 -C opt-level=1'
def run(args):return subprocess.run([docker,*args],env=env,check=True,capture_output=True,text=True)
name='kf-managed-harness-'+secrets.token_hex(4)
cid=run(['create','--name',name,'--label','org.openkedge.fixture=mlp-linux-harness-build','--memory','4g','--cpus','2','--pids-limit','512','--mount','type=volume,source=kf-mlp-linux-cargo-20261101,target=/usr/local/cargo/registry','--mount','type=volume,source=kf-mlp-linux-target-20261101,target=/target','--workdir','/source','--env','CARGO_HOME=/usr/local/cargo','--env','CARGO_TARGET_DIR=/target',image,'sh','-ec',command]).stdout.strip()
meta={'container':cid,'name':name,'image':image,'command':command,'source_sha256':json.loads((out/'source.json').read_text())}
(out/'harness-build.json').write_text(json.dumps(meta,indent=2)+'\n');print('container',cid,flush=True)
run(['cp',str(out/'source.tar'),cid+':/tmp/source.tar'])
artifact=None;stopped=False
with (out/'harness-build.log').open('wb') as log:
 child=subprocess.Popen([docker,'start','--attach',cid],env=env,stdout=log,stderr=subprocess.STDOUT)
 while True:
  for line in (out/'harness-build.log').read_text().splitlines():
   if line.startswith('{'):
    try:item=json.loads(line)
    except json.JSONDecodeError:continue
    if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')=='governance' and item.get('executable'):artifact=item
  if artifact:
   (out/'bins').mkdir(exist_ok=True)
   run(['cp',cid+':'+artifact['executable'],str(out/'bins/governance-test')])
   if child.poll() is None:run(['stop','--time','10',cid]);stopped=True
   child.wait(timeout=20);break
  if child.poll() is not None:raise RuntimeError('harness compilation failed; see harness-build.log')
  time.sleep(1)
inspection=json.loads(run(['inspect',cid]).stdout)[0]
assert artifact['profile']['test'] is True
assert all(hashlib.sha256((root/n).read_bytes()).hexdigest()==d for n,d in meta['source_sha256'].items())
meta.update(harness_compiler_artifact=artifact,harness_sha256=hashlib.sha256((out/'bins/governance-test').read_bytes()).hexdigest(),source_unchanged=True,unused_automatic_cli_builds_stopped=stopped,state=inspection['State'],image_id=inspection['Image'])
(out/'harness-build.json').write_text(json.dumps(meta,indent=2)+'\n');print('selected harness compiled and source verified',flush=True)
