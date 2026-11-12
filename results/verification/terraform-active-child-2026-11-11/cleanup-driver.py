from pathlib import Path
import json,os,subprocess
r=Path.cwd();e={**os.environ,**json.loads((r/'.cache/terraform-gateway-env/environment.json').read_text())}
tools=r/'.cache/m8-kube-tools/bin';kube=[str(tools/'kubectl'),'--kubeconfig',str(r/'.cache/terraform-gateway-env/pair-apply-kubeconfig'),'--context','kind-kf8-tfpa20261109','--request-timeout=15s']
with (r/'.cache/terraform-gateway-env/active-child-cleanup.log').open('w') as f:
 result=subprocess.run([*kube,'get','namespaces','-o','json'],env=e,capture_output=True,text=True,timeout=25,check=True)
 namespaces=json.loads(result.stdout)['items']
 assert not any(n['metadata']['name'].startswith('kf-tf-plan-') for n in namespaces),'fixture namespaces remain'
 f.write('PASS: no Terraform fixture namespaces remain\n');f.flush()
 result=subprocess.run([*kube,'version','-o','json'],env=e,capture_output=True,text=True,timeout=25,check=True)
 (r/'.cache/terraform-gateway-env/active-child-kubernetes-version.json').write_text(result.stdout)
 subprocess.run([str(tools/'kind'),'delete','cluster','--name','kf8-tfpa20261109','--kubeconfig',str(r/'.cache/terraform-gateway-env/pair-apply-kubeconfig')],env=e,stdout=f,stderr=subprocess.STDOUT,timeout=120,check=True)
 subprocess.run([str(tools/'colima'),'ssh','--profile','tf9','--','sudo','fstrim','--all','--verbose'],env=e,stdout=f,stderr=subprocess.STDOUT,timeout=60,check=True)
 subprocess.run([str(tools/'colima'),'stop','--profile','tf9'],env=e,stdout=f,stderr=subprocess.STDOUT,timeout=120,check=True)
 f.write('PASS: owned cluster kf8-tfpa20261109 deleted and tf9 VM stopped; other user profiles and contexts untouched\n')
