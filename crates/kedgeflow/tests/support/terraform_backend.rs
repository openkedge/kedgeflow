//! Controlled local-backend contention and drift. The target remains unchanged;
//! release/restoration never authorizes a second apply of the original plan.
use super::*;
use rustix::fs::{FlockOperation, flock};
use std::fs::OpenOptions;

fn active(mode: &str) -> bool {
    matches!(
        mode,
        "backend-lock" | "backend-serial" | "backend-lineage" | "backend-before-check"
    )
}
pub(super) async fn inject(mode: &str, boundary: &fault::Boundary, m: &Manifest) -> Value {
    let path = m.backend_state_path.as_ref().unwrap();
    let original = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&original)),
        m.files["state.json"]
    );
    let before: Value = serde_json::from_slice(&original).unwrap();
    if mode == "backend-lock" {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        flock(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert_eq!(
            flock(&probe, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        *boundary.backend_lock.lock().await = Some(file);
        return json!({"os_lock_acquired":true,"independent_lock_probe_refused":true,"sha256":hex::encode(Sha256::digest(&original)),"serial":before["serial"],"lineage":before["lineage"]});
    }
    let mut changed = before.clone();
    if mode == "backend-lineage" {
        changed["lineage"] = json!("00000000-0000-4000-8000-000000000001");
        assert_ne!(before["lineage"], changed["lineage"]);
    } else {
        changed["serial"] = json!(before["serial"].as_u64().unwrap() + 1);
    }
    let bytes = serde_json::to_vec_pretty(&changed).unwrap();
    std::fs::write(path, &bytes).unwrap();
    assert_ne!(hex::encode(Sha256::digest(&bytes)), m.files["state.json"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap(),
        changed
    );
    json!({"sha256":hex::encode(Sha256::digest(&bytes)),"before_serial":before["serial"],"serial":changed["serial"],"before_lineage":before["lineage"],"lineage":changed["lineage"],"resources_unchanged":before["resources"]==changed["resources"]})
}
pub(super) async fn complete(
    mode: &str,
    n: &Native,
    injection: &Value,
    m: &Manifest,
    expires_at: i64,
) {
    if !active(mode) {
        return;
    }
    assert!(
        SystemClock.now_ms() < expires_at,
        "backend refusal was masked by expiry"
    );
    let path = m.backend_state_path.as_ref().unwrap();
    let hash = hex::encode(Sha256::digest(std::fs::read(path).unwrap()));
    assert_eq!(hash, injection["backend_intervention"]["sha256"]);
    let mut proof = json!({"backend_sha256":hash,"grant_still_valid_at_refusal":true,"backend_unchanged_after_injection":true});
    if mode == "backend-lock" {
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert_eq!(
            flock(&probe, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        proof["lock_held_through_refusal"] = json!(true);
        drop(n.boundary.backend_lock.lock().await.take().unwrap());
        flock(&probe, FlockOperation::NonBlockingLockExclusive).unwrap();
        proof["lock_available_after_holder_release"] = json!(true);
    }
    let out = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
    std::fs::write(
        out.join("backend-completion.json"),
        serde_json::to_vec_pretty(&proof).unwrap(),
    )
    .unwrap();
}
pub(super) fn certify(mode: &str, intent: &Value) {
    let diagnostic = match mode {
        "backend-lock" => "apply state lock refused",
        "backend-serial" => "apply saved plan stale",
        "backend-lineage" => "apply state lineage refused",
        _ => return,
    };
    assert_eq!(intent["state"], "unknown");
    assert_eq!(
        intent["last_error"],
        format!("authority refused: Terraform plan: {diagnostic}")
    );
    assert!(intent["backend_after_sha256"].is_null());
    assert!(intent["observed_after_digest"].is_null());
}
#[tokio::test]
async fn local_backend_lock_refusal_is_retained_after_lock_release() {
    run("backend-lock").await;
}
#[tokio::test]
async fn backend_drift_before_runner_check_refuses_without_intent() {
    run("backend-before-check").await;
}
#[tokio::test]
async fn backend_serial_change_after_intent_refuses_stale_saved_plan() {
    run("backend-serial").await;
}
#[tokio::test]
async fn backend_lineage_change_after_intent_refuses_saved_plan() {
    run("backend-lineage").await;
}
