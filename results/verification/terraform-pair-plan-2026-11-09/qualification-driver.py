from pathlib import Path
import subprocess,json
r=Path.cwd();base=r/'.cache/terraform-pair-final';base.mkdir(exist_ok=False)
common=['python3','scripts/test-terraform-plan.py','--terraform','.cache/terraform-tools-1.17.1/terraform','--provider','.cache/terraform-tools-1.17.1/kubernetes','--kubectl','.cache/m8-kube-tools/bin/kubectl','--kubeconfig','.cache/terraform-gateway-env/pair-kubeconfig','--context','kind-kf8-tfp20261109','--inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-plan']
for name,args in [
 ('pair',['--pair-inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-pair-plan']),
 ('single-readonly',[]),
 ('normal-sdk',['--expect-effect','--execution-command','cargo','test','--locked','--offline','--test','governance','terraform_apply::gateway::official_sdk_shipping_gateway_and_broker_apply_then_cold_query','--','--exact','--nocapture','--test-threads=1']),
]:
 with (base/(name+'.log')).open('w') as f:result=subprocess.run([*common,'--output',str(base/name),*args],stdout=f,stderr=subprocess.STDOUT,timeout=300)
 print(json.dumps({'case':name,'exit':result.returncode}),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
with (base/'regressions.log').open('w') as f:result=subprocess.run(['cargo','test','--locked','--offline','--lib','--test','config','--test','contracts','--test','custody','--test','admission','--test','gateway','--test','terraform_plan','--test','terraform_pair','--','--nocapture','--test-threads=1'],stdout=f,stderr=subprocess.STDOUT,timeout=300)
print(json.dumps({'regressions':result.returncode}),flush=True)
raise SystemExit(result.returncode)
