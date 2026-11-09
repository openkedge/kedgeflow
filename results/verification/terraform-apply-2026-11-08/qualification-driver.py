from pathlib import Path
import json
import subprocess
base=Path('.cache/terraform-apply-final-20261108');base.mkdir(exist_ok=False)
cases=[('lost-reply','native_real_plan_original_apply_and_lost_reply',True),('revoked','native_real_plan_revocation_before_intent_refuses',False),('backend-drift','native_real_plan_changed_backend_refuses_before_intent',False),('missing-writer','native_real_plan_missing_writer_keeps_unknown_without_retry',False),('backend-locked','native_real_plan_backend_lock_keeps_unknown_without_reapply',False)]
for name,test,effect in cases:
 cmd=['python3','scripts/test-terraform-plan.py','--terraform','.cache/terraform-tools-1.17.1/terraform','--provider','.cache/terraform-tools-1.17.1/kubernetes','--kubectl','.cache/m8-kube-tools/bin/kubectl','--kubeconfig','.cache/m8-kube-env/kubeconfig','--context','kind-kf8-01a12982','--inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-plan','--output',str(base/name)]
 if effect: cmd+=['--expect-effect']
 cmd+=['--execution-command','cargo','test','--locked','--offline','--test','governance','terraform_apply::'+test,'--','--exact','--nocapture','--test-threads=1']
 with (base/(name+'.log')).open('w') as f:
  result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=360)
 print(json.dumps({'case':name,'exit':result.returncode}),flush=True)
 if result.returncode: raise SystemExit(result.returncode)
cmd=['cargo','test','--locked','--offline','--test','terraform_plan','--test','custody','--test','admission','--test','gateway','--test','config','--test','contracts','--','--nocapture','--test-threads=1']
with (base/'regressions.log').open('w') as f:
 result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=360)
print(json.dumps({'regressions':result.returncode}),flush=True)
raise SystemExit(result.returncode)
