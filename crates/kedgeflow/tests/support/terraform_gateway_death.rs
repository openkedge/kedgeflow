//! Whole gateway SIGKILL while a real original provider request is outstanding.
//! Explicit test cleanup is recorded; no production descendant containment claim.
use super::*;
use std::os::unix::process::ExitStatusExt;

pub(super) fn crash(mode: &str) -> bool {
    matches!(mode, "kill-active-drop" | "kill-active-late")
}
pub(super) struct Boundary {
    pub gate: PathBuf,
    pub entry: Value,
    pub gateway_pid: i32,
    pub terraform: Process,
    pub provider: Process,
    pub initial_intent: Value,
    pub before: Value,
    pub backend_before: Value,
    pub intervention_at: i64,
    pub key: String,
    pub grant: Grant,
    pub grant_digest: String,
}
struct OwnedGroup(Option<rustix::process::Pid>);
impl Drop for OwnedGroup {
    fn drop(&mut self) {
        if let Some(group) = self.0.take() {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
    }
}
async fn group_members(group: i32) -> Vec<Process> {
    processes()
        .await
        .into_iter()
        .filter(|p| p.group == group && live(p))
        .collect()
}
async fn wait_empty(group: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !group_members(group).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("owned orphan group did not stop after fixture cleanup");
}
fn summary(rows: &[Process]) -> Value {
    json!(rows.iter().map(|p| json!({"pid":p.pid,"parent":p.parent,"group":p.group,"state":p.state,"name":Path::new(&p.name).file_name().unwrap().to_string_lossy()})).collect::<Vec<_>>())
}
pub(super) async fn intervene(
    mode: &str,
    n: &Native,
    h: &Harness,
    gateway: &mut tokio::process::Child,
    m: &Manifest,
    b: Boundary,
) -> Value {
    let late = mode == "kill-active-late";
    let mut owned = OwnedGroup(Some(
        rustix::process::Pid::from_raw(b.terraform.group).unwrap(),
    ));
    gateway.kill().await.unwrap();
    let status = gateway.wait().await.unwrap();
    assert_eq!(status.signal(), Some(9));
    let gateway_dead_at = SystemClock.now_ms();
    assert!(
        gateway_dead_at < b.grant.expires_at,
        "gateway death masked by expiry"
    );
    let orphans = group_members(b.terraform.group).await;
    for expected in [b.terraform.pid, b.provider.pid] {
        assert!(
            orphans.iter().any(|p| p.pid == expected),
            "actual child did not survive gateway death: {orphans:?}"
        );
    }
    let orphan_observed_at = SystemClock.now_ms();
    assert_eq!(n.intent_outcomes.load(Ordering::SeqCst), 0);
    assert_eq!(n.outcomes.load(Ordering::SeqCst), 0);
    let phase = h
        .ledger
        .execution_status(&b.grant, &b.grant_digest)
        .await
        .unwrap();
    assert_eq!(phase.state, "dispatch_authorized");
    let mut fixture_group_kill = false;
    if !late {
        rustix::process::kill_process_group(owned.0.unwrap(), rustix::process::Signal::KILL)
            .unwrap();
        fixture_group_kill = true;
        wait_empty(b.terraform.group).await;
    }
    let delay = (b.grant.expires_at - SystemClock.now_ms()).max(0) as u64 + 25;
    assert!(delay < 25000);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    let at_expiry = group_members(b.terraform.group).await;
    let release_path = b.gate.join("release.tmp");
    std::fs::write(
        &release_path,
        serde_json::to_vec(&json!({"action":if late {"forward"}else{"drop"}})).unwrap(),
    )
    .unwrap();
    std::fs::rename(release_path, b.gate.join("release.json")).unwrap();
    let completed = wait_file(&b.gate.join("completed.json")).await;
    assert_eq!(completed["forwarded"], late);
    if late {
        assert_eq!(completed["upstream_status"], 200);
    }
    // Allow the actual orphaned tool to finish on its existing response. Any
    // fixture cleanup is explicit and cannot be credited to the dead gateway.
    if late {
        for _ in 0..100 {
            if group_members(b.terraform.group).await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if !group_members(b.terraform.group).await.is_empty() {
            rustix::process::kill_process_group(owned.0.unwrap(), rustix::process::Signal::KILL)
                .unwrap();
            fixture_group_kill = true;
        }
        wait_empty(b.terraform.group).await;
    }
    owned.0 = None;
    let group_empty_at = SystemClock.now_ms();
    let after = fault::kube(m, false).await;
    assert_eq!(after["metadata"]["uid"], m.target.uid);
    assert_eq!(
        after["metadata"]["annotations"][terraform_plan::ANNOTATION],
        if late {
            m.after_revision.as_str()
        } else {
            m.before_revision.as_str()
        }
    );
    let backend_after = backend_snapshot(m);
    if !late {
        assert_eq!(backend_after, b.backend_before);
    }
    let intent: Value =
        serde_json::from_slice(&h.ledger.read_key(&b.key).await.unwrap().unwrap()).unwrap();
    assert_eq!(intent, b.initial_intent);
    assert_eq!(
        h.ledger
            .execution_status(&b.grant, &b.grant_digest)
            .await
            .unwrap()
            .state,
        "dispatch_authorized"
    );
    assert_eq!(n.intent_outcomes.load(Ordering::SeqCst), 0);
    assert_eq!(n.outcomes.load(Ordering::SeqCst), 0);
    let proof = json!({"profile":"KF-TERRAFORM-GATEWAY-DEATH-EVIDENCE-0.1-test","initial_intent":b.initial_intent,"gateway_pid":b.gateway_pid,"terraform_pid":b.terraform.pid,"provider_pid":b.provider.pid,"terraform_parent":b.terraform.parent,"provider_parent":b.provider.parent,"terraform_state":b.terraform.state,"provider_state":b.provider.state,"process_group":b.terraform.group,"active_request":b.entry,"intervention_at":b.intervention_at,"gateway_dead_at":gateway_dead_at,"gateway_exit_signal":9,"orphans_observed_at":orphan_observed_at,"orphans_after_gateway_death":summary(&orphans),"grant_expires_at":b.grant.expires_at,"group_at_expiry":summary(&at_expiry),"gate_completion":completed,"fixture_group_kill":fixture_group_kill,"group_empty_at":group_empty_at,"no_live_group_at_fixture_end":true,"backend_at_boundary":b.backend_before,"backend_after_release":backend_after,"target_before_release":b.before,"target_after_release":after,"native_phase_after_effect":"dispatch_authorized","native_outcome_publications":0});
    let out = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
    std::fs::write(
        out.join("gateway-death-proof.json"),
        serde_json::to_vec_pretty(&proof).unwrap(),
    )
    .unwrap();
    proof
}
#[tokio::test]
async fn whole_gateway_sigkill_leaves_live_children_and_held_original() {
    run("kill-active-drop").await;
}
#[tokio::test]
async fn captured_request_after_gateway_sigkill_and_expiry_keeps_original_phase() {
    run("kill-active-late").await;
}
