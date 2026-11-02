import hashlib,json,secrets,subprocess,tarfile
from pathlib import Path
root=Path.cwd();out=root/'.cache/linux-credentials-release-final-serial'
ssh=['ssh','-F','/tmp/kf8-01a12982-lima/colima-kfmlp20261101/ssh.config','lima-colima-kfmlp20261101']
stage='/tmp/kf-ledger-qualification-'+secrets.token_hex(8)
inputs=[root/'scripts/qualify-ledger-credentials.py',*(root/'deploy/linux/credentials').iterdir()]
inputs=[p for p in inputs if p.is_file()]
hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
archive=out/'qualification-inputs.tar'
with tarfile.open(archive,'w') as tar:
 for p in inputs:tar.add(p,arcname=str(p.relative_to(root)))
 tar.add(out/'qualifier-publisher',arcname='publisher')
 etcd=next((root/'.cache/linux-managed-tools/runtime').glob('*/etcd'));tar.add(etcd,arcname='etcd')
subprocess.run([*ssh,'mkdir -m 755 '+stage],check=True)
try:
 with archive.open('rb') as source:subprocess.run([*ssh,'tar -xf - -C '+stage],stdin=source,check=True)
 command='sudo /usr/bin/python3 '+stage+'/scripts/qualify-ledger-credentials.py --ephemeral-host --binary '+stage+'/publisher --etcd '+stage+'/etcd'
 with (out/'qualification.json').open('wb') as log,(out/'qualification.stderr').open('wb') as errors:
  result=subprocess.run([*ssh,command],stdout=log,stderr=errors,timeout=180)
 assert all(hashlib.sha256((root/n).read_bytes()).hexdigest()==h for n,h in hashes.items())
 (out/'qualification-provenance.json').write_text(json.dumps({'command':command,'source_sha256':hashes,'source_unchanged':True,'exit_code':result.returncode,'binary_sha256':hashlib.sha256((out/'qualifier-publisher').read_bytes()).hexdigest()},indent=2)+'\n')
 print('qualification exit',result.returncode,flush=True)
 if result.returncode:print((out/'qualification.stderr').read_text());raise SystemExit(1)
 print((out/'qualification.json').read_text())
finally:subprocess.run([*ssh,'sudo rm -rf -- '+stage],check=True)
