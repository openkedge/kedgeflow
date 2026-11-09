from pathlib import Path
import json,subprocess
base=Path('.cache/terraform-backend-final2');base.mkdir(exist_ok=False)
cases=[
('lock','backend::local_backend_lock_refusal_is_retained_after_lock_release',False),
('precheck','backend::backend_drift_before_runner_check_refuses_without_intent',False),
('serial','backend::backend_serial_change_after_intent_refuses_stale_saved_plan',False),
('lineage','backend::backend_lineage_change_after_intent_refuses_saved_plan',False),
('normal','official_sdk_shipping_gateway_and_broker_apply_then_cold_query',True),
('after-intent','fault::gateway_sigkill_after_intent_before_reply_is_query_only',False),
('after-effect','fault::gateway_sigkill_after_effect_before_intent_outcome_stays_unresolved',True),
('before-publication','fault::gateway_sigkill_before_ordinary_publication_does_not_promote_intent',True),
('revocation','fault::domain_revocation_at_intent_cas_refuses_effect',False),
('target-drift','fault::independent_target_drift_after_dispatch_is_detected_before_intent',False),
('suspension','fault::sigstop_resume_after_grant_expiry_cannot_apply',False),
]
for name,test,effect in cases:
 cmd=['python3','scripts/test-terraform-plan.py','--terraform','.cache/terraform-tools-1.17.1/terraform','--provider','.cache/terraform-tools-1.17.1/kubernetes','--kubectl','.cache/m8-kube-tools/bin/kubectl','--kubeconfig','.cache/terraform-gateway-env/backend-kubeconfig','--context','kind-kf8-tfb20261109','--inspector','/private/tmp/kedgeflow-paper-target/debug/kf-terraform-plan','--output',str(base/name)]
 if effect:cmd+=['--expect-effect']
 if name=='target-drift':cmd+=['--expect-external-revision','external']
 cmd+=['--execution-command','cargo','test','--locked','--offline','--test','governance','terraform_apply::gateway::'+test,'--','--exact','--nocapture','--test-threads=1']
 with (base/(name+'.log')).open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 print(json.dumps({'case':name,'exit':r.returncode}),flush=True)
 if r.returncode:raise SystemExit(r.returncode)
for name,cmd in [
 ('regressions',['cargo','test','--locked','--offline','--lib','--test','config','--test','contracts','--test','custody','--test','admission','--test','gateway','--test','terraform_plan','--','--nocapture','--test-threads=1']),
 ('legacy-sdk',['cargo','test','--locked','--offline','--test','governance','live_agent::official_agent_lost_execution_reply_resolves_without_second_effect','--','--exact','--nocapture','--test-threads=1']),
]:
 with (base/(name+'.log')).open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 print(json.dumps({name:r.returncode}),flush=True)
 if r.returncode:raise SystemExit(r.returncode)
