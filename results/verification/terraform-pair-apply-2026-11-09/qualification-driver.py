from pathlib import Path
import subprocess,json
r=Path.cwd();base=r/'.cache/terraform-pair-apply-final4';base.mkdir(exist_ok=False)
common=['python3','scripts/test-terraform-plan.py','--terraform','.cache/terraform-tools-1.17.1/terraform','--provider','.cache/terraform-tools-1.17.1/kubernetes','--kubectl','.cache/m8-kube-tools/bin/kubectl','--kubeconfig','.cache/terraform-gateway-env/pair-apply-kubeconfig','--context','kind-kf8-tfpa20261109','--inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-plan']
cases=[('partial','partial','terraform_pair_execution::partial_pair_keeps_unknown_after_permission_restored'),('normal','normal','terraform_pair_execution::normal_pair_apply_and_original_cold_query'),('partial-lost','partial','terraform_pair_execution::partial_pair_lost_reply_recovers_without_reapply'),('legacy-cli',None,'terraform_apply::native_real_plan_original_apply_and_lost_reply'),('legacy-sdk',None,'terraform_apply::gateway::official_sdk_shipping_gateway_and_broker_apply_then_cold_query')]
for name,mode,test in cases:
 cmd=[*common,'--output',str(base/name)]
 if mode:cmd+=['--pair-inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-pair-plan','--pair-execution',mode,'--docker','.cache/m8-kube-tools/bin/docker','--audit-node','kf8-tfpa20261109-control-plane']
 else:cmd+=['--expect-effect']
 cmd+=['--execution-command','cargo','test','--locked','--offline','--test','governance',test,'--','--exact','--nocapture','--test-threads=1']
 with (base/(name+'.log')).open('w') as f:result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 print(json.dumps({'case':name,'exit':result.returncode}),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
with (base/'regressions.log').open('w') as f:result=subprocess.run(['cargo','test','--locked','--offline','--lib','--test','config','--test','contracts','--test','custody','--test','admission','--test','gateway','--test','terraform_plan','--test','terraform_pair','--test','terraform_pair_apply','--','--nocapture','--test-threads=1'],stdout=f,stderr=subprocess.STDOUT,timeout=300)
print(json.dumps({'regressions':result.returncode}),flush=True)
raise SystemExit(result.returncode)
