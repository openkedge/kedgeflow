from pathlib import Path
import subprocess,json,shlex,hashlib
r=Path.cwd();ssh=['ssh','-F','/private/tmp/kftf9-lima/colima-tf9/ssh.config','lima-colima-tf9'];out=r/'.cache/terraform-linux-release';out.mkdir(exist_ok=True)
cmd=['sudo','python3','/opt/kf-tfi-input-20261111/source/scripts/package-terraform-linux.py','--binary-dir','/target/debug','--output','/mnt/lima-colima-tf9/kf-tfi-release-20261112']
p=subprocess.run([*ssh,shlex.join(cmd)],capture_output=True,text=True,check=True,timeout=150);meta=json.loads(p.stdout)
p2=subprocess.run([*ssh,shlex.join(cmd)],capture_output=True,text=True,check=True,timeout=150);assert p2.stdout==p.stdout
source=meta['archive'];archive=out/Path(source).name
with archive.open('wb') as f:subprocess.run([*ssh,shlex.join(['sudo','cat',source])],stdout=f,check=True,timeout=120)
assert hashlib.sha256(archive.read_bytes()).hexdigest()==meta['sha256']
meta['archive']=str(archive);meta['deterministic_rebuild']=True
(out/'bundle.json').write_text(json.dumps(meta,indent=2)+'\n')
p=subprocess.run(['python3','scripts/package-terraform-linux.py','--verify',str(archive),'--sha256',meta['sha256']],capture_output=True,text=True,check=True);(out/'verification.json').write_text(p.stdout)
print(json.dumps(meta))
