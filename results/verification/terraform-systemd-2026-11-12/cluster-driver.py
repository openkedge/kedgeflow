from pathlib import Path
import subprocess,os,json,shlex
r=Path.cwd();e={**os.environ,**json.loads((r/'.cache/terraform-gateway-env/environment.json').read_text())};t=r/'.cache/m8-kube-tools/bin';cfg=r/'.cache/terraform-gateway-env';ssh=['ssh','-F','/private/tmp/kftf9-lima/colima-tf9/ssh.config','lima-colima-tf9']
with (r/'.cache/terraform-linux-build/clean-cluster.log').open('w') as f:
 subprocess.run([str(t/'kind'),'delete','cluster','--name','kf8-tfpa20261109','--kubeconfig',str(cfg/'pair-apply-kubeconfig')],env=e,stdout=f,stderr=subprocess.STDOUT,timeout=120,check=True)
 subprocess.run([str(t/'kind'),'create','cluster','--name','kf8-tfpa20261109','--image','kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5','--config',str(cfg/'pair-apply-kind.json'),'--kubeconfig',str(cfg/'pair-apply-kubeconfig'),'--wait','180s'],env=e,stdout=f,stderr=subprocess.STDOUT,timeout=240,check=True)
subprocess.run([*ssh,shlex.join(['sudo','tee','/opt/kf-tfi-input-20261111/kubeconfig'])],input=(cfg/'pair-apply-kubeconfig').read_bytes(),stdout=subprocess.DEVNULL,check=True)
subprocess.run([*ssh,'sudo chmod 600 /opt/kf-tfi-input-20261111/kubeconfig'],check=True)
print('clean owned audited cluster ready')
