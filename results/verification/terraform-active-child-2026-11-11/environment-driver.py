from pathlib import Path
import json,os,subprocess
r=Path.cwd();envdir=r/'.cache/terraform-gateway-env';env={**os.environ,**json.loads((envdir/'environment.json').read_text())}
policy={'apiVersion':'audit.k8s.io/v1','kind':'Policy','omitStages':['RequestReceived'],'rules':[{'level':'Metadata','resources':[{'group':'','resources':['configmaps']}]},{'level':'None'}]}
(envdir/'pair-apply-audit-policy.json').write_text(json.dumps(policy))
patch={'kind':'ClusterConfiguration','apiServer':{'extraArgs':[{'name':'audit-log-path','value':'/var/log/kubernetes/kube-apiserver-audit.log'},{'name':'audit-policy-file','value':'/etc/kubernetes/policies/audit-policy.json'},{'name':'audit-log-mode','value':'blocking'}],'extraVolumes':[{'name':'audit-policies','hostPath':'/etc/kubernetes/policies','mountPath':'/etc/kubernetes/policies','readOnly':True,'pathType':'DirectoryOrCreate'},{'name':'audit-logs','hostPath':'/var/log/kubernetes','mountPath':'/var/log/kubernetes','readOnly':False,'pathType':'DirectoryOrCreate'}]}}
config={'kind':'Cluster','apiVersion':'kind.x-k8s.io/v1alpha4','networking':{'apiServerAddress':'127.0.0.1','podSubnet':'10.249.0.0/16','serviceSubnet':'10.97.0.0/16'},'nodes':[{'role':'control-plane','kubeadmConfigPatches':[json.dumps(patch)],'extraMounts':[{'hostPath':'/private/tmp/kf-pair-apply-policy/audit-policy.json','containerPath':'/etc/kubernetes/policies/audit-policy.json','readOnly':True}]}]}
(envdir/'pair-apply-kind.json').write_text(json.dumps(config))
t=r/'.cache/m8-kube-tools/bin'
with (envdir/'active-child-start.log').open('w') as f:
 subprocess.run([str(t/'colima'),'start','--profile','tf9','--cpus','4','--memory','6','--disk','8','--root-disk','4','--activate=false','--ssh-config=false','--mount','none','--vm-type','vz'],env=env,stdout=f,stderr=subprocess.STDOUT,timeout=240,check=True)
 subprocess.run([str(t/'colima'),'ssh','--profile','tf9','--','sudo','fstrim','--all','--verbose'],env=env,stdout=f,stderr=subprocess.STDOUT,timeout=30,check=True)
 policy_path=Path('/private/tmp/kf-pair-apply-policy/audit-policy.json');policy_path.parent.mkdir(exist_ok=True);policy_path.write_bytes((envdir/'pair-apply-audit-policy.json').read_bytes())
 subprocess.run([str(t/'colima'),'ssh','--profile','tf9','--','sudo','mkdir','-p',str(policy_path.parent)],env=env,stdout=f,stderr=subprocess.STDOUT,timeout=25,check=True)
 subprocess.run([str(t/'colima'),'ssh','--profile','tf9','--','sudo','tee',str(policy_path)],input=policy_path.read_bytes(),env=env,stdout=f,stderr=subprocess.STDOUT,timeout=25,check=True)
 subprocess.run([str(t/'kind'),'create','cluster','--name','kf8-tfpa20261109','--image','kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5','--config',str(envdir/'pair-apply-kind.json'),'--kubeconfig',str(envdir/'pair-apply-kubeconfig'),'--wait','180s','--retain'],env=env,stdout=f,stderr=subprocess.STDOUT,timeout=240,check=True)
