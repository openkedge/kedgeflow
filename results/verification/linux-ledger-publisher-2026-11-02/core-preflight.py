import hashlib,json,secrets,subprocess,tarfile
from pathlib import Path
root=Path.cwd();out=root/'.cache/linux-credentials-release-final-serial'
ssh=['ssh','-F','/tmp/kf8-01a12982-lima/colima-kfmlp20261101/ssh.config','lima-colima-kfmlp20261101']
stage='/tmp/kf-credential-core-'+secrets.token_hex(8)
inputs=[root/'scripts/qualify-linux-package.py',root/'scripts/linux-preflight-fixture.py',*(root/'deploy/linux').rglob('*'),*(root/'config').rglob('*')]
inputs=[p for p in inputs if p.is_file()]
hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
with tarfile.open(out/'core-inputs.tar','w') as tar:
 for p in inputs:tar.add(p,arcname=str(p.relative_to(root)))
 for p in (out/'bins').iterdir():tar.add(p,arcname='bins/'+p.name)
subprocess.run([*ssh,'mkdir -m 755 '+stage],check=True)
try:
 with (out/'core-inputs.tar').open('rb') as source:subprocess.run([*ssh,'tar -xf - -C '+stage],stdin=source,check=True)
 with (out/'core-preflight.json').open('wb') as log,(out/'core-preflight.stderr').open('wb') as errors:
  result=subprocess.run([*ssh,'sudo /usr/bin/python3 '+stage+'/scripts/qualify-linux-package.py --ephemeral-host --binary-dir '+stage+'/bins'],stdout=log,stderr=errors,timeout=180)
 assert all(hashlib.sha256((root/n).read_bytes()).hexdigest()==h for n,h in hashes.items())
 (out/'core-provenance.json').write_text(json.dumps({'source_sha256':hashes,'source_unchanged':True,'exit_code':result.returncode},indent=2)+'\n')
 print('core preflight exit',result.returncode)
 if result.returncode:print((out/'core-preflight.stderr').read_text());raise SystemExit(1)
 data=json.loads((out/'core-preflight.json').read_text());print(data['status']);print('native checks',len(data['native_preflights']))
finally:subprocess.run([*ssh,'sudo rm -rf -- '+stage],check=True)
