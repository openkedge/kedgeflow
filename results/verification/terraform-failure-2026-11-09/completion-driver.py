from pathlib import Path
import subprocess,json
base=Path('.cache/terraform-failure-completion');base.mkdir(exist_ok=False)
cases=[('suspension','fault::sigstop_resume_after_grant_expiry_cannot_apply',False,False),('normal-regression','official_sdk_shipping_gateway_and_broker_apply_then_cold_query',True,False)]
for name,test,effect,external in cases:
 cmd=['python3','scripts/test-terraform-plan.py','--terraform','.cache/terraform-tools-1.17.1/terraform','--provider','.cache/terraform-tools-1.17.1/kubernetes','--kubectl','.cache/m8-kube-tools/bin/kubectl','--kubeconfig','.cache/terraform-gateway-env/kubeconfig','--context','kind-kf8-tf20261109','--inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-plan','--output',str(base/name)]
 if effect:cmd+=['--expect-effect']
 if external:cmd+=['--expect-external-revision','external']
 cmd+=['--execution-command','cargo','test','--locked','--offline','--test','governance','terraform_apply::gateway::'+test,'--','--exact','--nocapture','--test-threads=1']
 with (base/(name+'.log')).open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 print(json.dumps({'case':name,'exit':r.returncode}),flush=True)
 if r.returncode:raise SystemExit(r.returncode)
cmd=['cargo','test','--locked','--offline','--test','config','--test','contracts','--test','custody','--test','admission','--test','gateway','--test','terraform_plan','--','--nocapture','--test-threads=1']
with (base/'regressions.log').open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
print(json.dumps({'regressions':r.returncode}),flush=True)
if r.returncode:raise SystemExit(r.returncode)
with (base/'legacy-sdk.log').open('w') as f:r=subprocess.run(['cargo','test','--locked','--offline','--test','governance','live_agent::official_agent_lost_execution_reply_resolves_without_second_effect','--','--exact','--nocapture','--test-threads=1'],stdout=f,stderr=subprocess.STDOUT,timeout=90)
print(json.dumps({'legacy_sdk':r.returncode}),flush=True)
raise SystemExit(r.returncode)
