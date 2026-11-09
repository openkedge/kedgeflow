from pathlib import Path
import subprocess,json
base=Path('.cache/terraform-gateway-final');base.mkdir(exist_ok=False)
for name,test,effect in [('lost','terraform_apply::gateway::official_sdk_lost_apply_reply_never_repeats_effect',True),('missing-writer','terraform_apply::gateway::official_sdk_missing_writer_preserves_unknown_after_restart',False),('legacy-cli','terraform_apply::native_real_plan_original_apply_and_lost_reply',True)]:
 cmd=['python3','scripts/test-terraform-plan.py','--terraform','.cache/terraform-tools-1.17.1/terraform','--provider','.cache/terraform-tools-1.17.1/kubernetes','--kubectl','.cache/m8-kube-tools/bin/kubectl','--kubeconfig','.cache/terraform-gateway-env/kubeconfig','--context','kind-kf8-tf20261109','--inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-plan','--output',str(base/name)]
 if effect:cmd+=['--expect-effect']
 cmd+=['--execution-command','cargo','test','--locked','--offline','--test','governance',test,'--','--exact','--nocapture','--test-threads=1']
 with (base/(name+'.log')).open('w') as f:result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 print(json.dumps({'case':name,'exit':result.returncode}),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
cmd=['cargo','test','--locked','--offline','--test','config','--test','contracts','--test','custody','--test','admission','--test','gateway','--test','terraform_plan','--','--nocapture','--test-threads=1']
with (base/'regressions.log').open('w') as f:result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
print(json.dumps({'regressions':result.returncode}),flush=True)
if result.returncode:raise SystemExit(result.returncode)
for test in ['live_agent::official_agent_acquires_live_admission_and_resolves_expired_status_after_restart','live_agent::official_agent_lost_execution_reply_resolves_without_second_effect']:
 with (base/(test.split('::')[-1]+'.log')).open('w') as f:result=subprocess.run(['cargo','test','--locked','--offline','--test','governance',test,'--','--exact','--nocapture','--test-threads=1'],stdout=f,stderr=subprocess.STDOUT,timeout=90)
 print(json.dumps({'legacy_sdk':test,'exit':result.returncode}),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
