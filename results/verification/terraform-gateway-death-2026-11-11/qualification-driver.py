from pathlib import Path
import subprocess,json
base=Path('.cache/terraform-gateway-death-final');base.mkdir(exist_ok=False)
common=['python3','scripts/test-terraform-plan.py','--terraform','.cache/terraform-tools-1.17.1/terraform','--provider','.cache/terraform-tools-1.17.1/kubernetes','--kubectl','.cache/m8-kube-tools/bin/kubectl','--kubeconfig','.cache/terraform-gateway-env/pair-apply-kubeconfig','--context','kind-kf8-tfpa20261109','--inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-plan']
cases=[('gateway-kill-drop','active::death::whole_gateway_sigkill_leaves_live_children_and_held_original'),('gateway-kill-late','active::death::captured_request_after_gateway_sigkill_and_expiry_keeps_original_phase'),('deadline-late','active::dispatch_deadline_stops_local_group_but_does_not_bar_late_effect'),('legacy-sdk','official_sdk_shipping_gateway_and_broker_apply_then_cold_query')]
for name,test in cases:
 cmd=[*common,'--output',str(base/name)]
 if name!='legacy-sdk':cmd+=['--active-child',name,'--docker','.cache/m8-kube-tools/bin/docker','--audit-node','kf8-tfpa20261109-control-plane']
 if name in ('gateway-kill-late','deadline-late','legacy-sdk'):cmd+=['--expect-effect']
 cmd+=['--execution-command','cargo','test','--locked','--offline','--test','governance','terraform_apply::gateway::'+test,'--','--exact','--nocapture','--test-threads=1']
 with (base/(name+'.log')).open('w') as f:result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 print(json.dumps({'case':name,'exit':result.returncode}),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
with (base/'regressions.log').open('w') as f:result=subprocess.run(['cargo','test','--locked','--offline','--lib','--test','config','--test','contracts','--test','custody','--test','admission','--test','gateway','--test','terraform_plan','--test','terraform_pair','--test','terraform_pair_apply','--','--nocapture','--test-threads=1'],stdout=f,stderr=subprocess.STDOUT,timeout=300)
print(json.dumps({'regressions':result.returncode}),flush=True)
raise SystemExit(result.returncode)
