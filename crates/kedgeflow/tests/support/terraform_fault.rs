//! Test-only native request/reply barriers, real process signals and independent
//! target observations. No production fault hook or outcome repair is added.
use super::*;
use axum::http::StatusCode;
use std::{os::unix::process::ExitStatusExt, sync::atomic::AtomicBool};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    None,
    AfterIntent,
    BeforeIntentOutcome,
    BeforePublish,
    BeforeIntent,
    AfterDispatch,
}
pub(super) struct Boundary {
    point: Point,
    armed: AtomicBool,
    entered: Notify,
    released: Notify,
    abort: AtomicBool,
    proof: Mutex<Value>,
    pub(super) backend_lock: Mutex<Option<std::fs::File>>,
}
pub(super) fn expected(mode: &str) -> Option<&'static str> {
    match mode {
        "active-provider-kill" | "active-terraform-kill" | "active-deadline-late" => {
            Some("unknown")
        }
        "kill-after-intent" | "kill-after-effect" | "kill-before-publish" => {
            Some("dispatch_authorized")
        }
        "revoke-at-intent"
        | "target-drift"
        | "backend-before-check"
        | "backend-lock"
        | "backend-serial"
        | "backend-lineage" => Some("unknown"),
        "suspend" => Some("not_dispatched"),
        _ => None,
    }
}
pub(super) fn killed(mode: &str) -> bool {
    mode.starts_with("kill-")
}
pub(super) fn has_write(v: &Value, state: &str) -> bool {
    v["success"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("request_put"))
        .any(|p| {
            let key =
                String::from_utf8(STANDARD.decode(p["key"].as_str().unwrap()).unwrap()).unwrap();
            let value = STANDARD.decode(p["value"].as_str().unwrap()).unwrap();
            if (key.contains("/terraform/") || key.contains("/terraform-pair/"))
                && key.ends_with("/intent")
            {
                serde_json::from_slice::<Value>(&value).unwrap()["state"] == state
            } else {
                key.contains("/outbox/") && value == state.as_bytes()
            }
        })
}
impl Boundary {
    pub(super) fn new(mode: &str) -> Self {
        Self {
            point: match mode {
                "kill-after-intent" | "backend-lock" | "backend-serial" | "backend-lineage" => {
                    Point::AfterIntent
                }
                "kill-after-effect" => Point::BeforeIntentOutcome,
                "kill-before-publish" => Point::BeforePublish,
                "revoke-at-intent" => Point::BeforeIntent,
                "target-drift" | "suspend" | "backend-before-check" => Point::AfterDispatch,
                _ => Point::None,
            },
            armed: AtomicBool::new(true),
            entered: Notify::new(),
            released: Notify::new(),
            abort: AtomicBool::new(false),
            proof: Mutex::new(Value::Null),
            backend_lock: Mutex::new(None),
        }
    }
    async fn hold(&self, v: &Value, committed: bool) -> std::result::Result<(), StatusCode> {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        *self.proof.lock().await = json!({"point":format!("{:?}",self.point),"transaction_digest":kedgeflow::contracts::digest("fixture-native-transaction",v).unwrap(),"committed_before_intervention":committed,"request_not_forwarded":!committed});
        self.entered.notify_one();
        self.released.notified().await;
        if self.abort.load(Ordering::SeqCst) {
            Err(StatusCode::SERVICE_UNAVAILABLE)
        } else {
            Ok(())
        }
    }
    pub(super) async fn before(&self, v: &Value) -> std::result::Result<(), StatusCode> {
        if match self.point {
            Point::BeforeIntentOutcome => has_write(v, "applied"),
            Point::BeforePublish => has_write(v, "committed"),
            Point::BeforeIntent => has_write(v, "started"),
            _ => false,
        } {
            self.hold(v, false).await?;
        }
        Ok(())
    }
    pub(super) async fn forwarding(&self, v: &Value) {
        if !matches!(
            self.point,
            Point::BeforeIntent | Point::BeforeIntentOutcome | Point::BeforePublish
        ) {
            return;
        }
        let mut proof = self.proof.lock().await;
        if proof["transaction_digest"]
            == kedgeflow::contracts::digest("fixture-native-transaction", v).unwrap()
        {
            proof["request_not_forwarded"] = json!(false);
        }
    }
    pub(super) async fn after(
        &self,
        v: &Value,
        answer: &Value,
    ) -> std::result::Result<(), StatusCode> {
        if self.point == Point::BeforeIntent
            && has_write(v, "started")
            && !self.armed.load(Ordering::SeqCst)
        {
            self.proof.lock().await["compare_succeeded"] = json!(answer["succeeded"] == true);
        }
        if answer["succeeded"] == true
            && match self.point {
                Point::AfterIntent => has_write(v, "started"),
                Point::AfterDispatch => has_write(v, "dispatch_authorized"),
                _ => false,
            }
        {
            self.hold(v, true).await?;
        }
        Ok(())
    }
    pub(super) async fn record(&self) -> Value {
        self.proof.lock().await.clone()
    }
}
pub(super) fn counters(n: &Native) -> Value {
    json!({"claims":n.claims.load(Ordering::SeqCst),"permits":n.permits.load(Ordering::SeqCst),"dispatches":n.dispatches.load(Ordering::SeqCst),"intents":n.intents.load(Ordering::SeqCst),"intent_requests":n.intent_requests.load(Ordering::SeqCst),"intent_outcomes":n.intent_outcomes.load(Ordering::SeqCst),"ordinary_outcomes":n.outcomes.load(Ordering::SeqCst)})
}
pub(super) fn retained(root: &Path) -> Value {
    std::fs::read_dir(root.join("operations"))
        .unwrap()
        .find_map(|e| {
            let p = e.unwrap().path();
            p.extension()
                .is_some_and(|s| s == "json")
                .then(|| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
        })
        .unwrap()
}
pub(super) async fn kube(m: &Manifest, patch: bool) -> Value {
    let context = std::env::var("KF_TERRAFORM_CONTEXT").unwrap();
    assert!(context.starts_with("kind-kf8-"));
    let mut c = tokio::process::Command::new(std::env::var("KF_TERRAFORM_KUBECTL").unwrap());
    c.args([
        "--kubeconfig",
        &std::env::var("KF_TERRAFORM_KUBECONFIG").unwrap(),
        "--context",
        &context,
        "--request-timeout=10s",
    ]);
    if patch {
        c.args([
            "patch",
            "configmap",
            &m.target.name,
            "-n",
            &m.target.namespace,
            "--type=merge",
            "--field-manager=kf-external-fixture",
            "-p",
            r#"{"metadata":{"annotations":{"kedgeflow.dev/revision":"external"}}}"#,
            "-o",
            "json",
        ]);
    } else {
        c.args([
            "get",
            "configmap",
            &m.target.name,
            "-n",
            &m.target.namespace,
            "-o",
            "json",
        ]);
    }
    let output = tokio::time::timeout(Duration::from_secs(12), c.kill_on_drop(true).output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "owned fixture observation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
pub(super) async fn intervene(
    mode: &str,
    n: &Native,
    h: &Harness,
    gateway: &mut tokio::process::Child,
    root: &Path,
    m: &Manifest,
) -> Value {
    tokio::time::timeout(Duration::from_secs(15), n.boundary.entered.notified())
        .await
        .expect("declared native boundary was not reached");
    assert!(gateway.try_wait().unwrap().is_none());
    let stored = retained(root);
    let verified = GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify_retained(stored["grant"].as_str().unwrap().as_bytes())
    .unwrap();
    let g = &verified.grant;
    let before = kube(m, false).await;
    let backend = std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap();
    let backend_state: Value = serde_json::from_slice(&backend).unwrap();
    let source: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("KF_TERRAFORM_CAPSULE").unwrap() + "/state.json").unwrap(),
    )
    .unwrap();
    let effect = matches!(mode, "kill-after-effect" | "kill-before-publish");
    assert_eq!(before["metadata"]["uid"], m.target.uid);
    assert_eq!(
        before["metadata"]["annotations"][terraform_plan::ANNOTATION].as_str(),
        if effect {
            Some(m.after_revision.as_str())
        } else {
            Some(m.before_revision.as_str())
        }
    );
    if effect {
        assert_eq!(backend_state["lineage"], source["lineage"]);
        assert!(backend_state["serial"].as_u64().unwrap() > source["serial"].as_u64().unwrap());
        assert_ne!(
            before["metadata"]["resourceVersion"],
            m.target.resource_version
        );
    } else {
        assert_eq!(hex::encode(Sha256::digest(&backend)), m.files["state.json"]);
        assert_eq!(
            before["metadata"]["resourceVersion"],
            m.target.resource_version
        );
    }
    let mut proof = json!({"gateway_pid":gateway.id(),"target_at_boundary":before,"backend_at_boundary":{"sha256":hex::encode(Sha256::digest(&backend)),"lineage":backend_state["lineage"],"serial":backend_state["serial"]},"target_effect_observed":effect,"grant_valid_at_boundary":SystemClock.now_ms()<g.expires_at});
    assert!(
        SystemClock.now_ms() + 2000 < g.expires_at,
        "boundary validity exhausted before certified intervention"
    );
    match mode {
        "kill-after-intent" | "kill-after-effect" | "kill-before-publish" => {
            if mode != "kill-after-intent" {
                n.boundary.abort.store(true, Ordering::SeqCst);
            }
            gateway.kill().await.unwrap();
            let status = gateway.wait().await.unwrap();
            assert_eq!(status.signal(), Some(9));
            proof["gateway_sigkill_certified"] = json!(true);
        }
        "revoke-at-intent" => {
            let revoked = h.revoke(RevocationTarget::Domain).await;
            proof["revocation_digest"] = json!(revoked.digest);
        }
        "target-drift" => {
            let changed = kube(m, true).await;
            assert_eq!(changed["metadata"]["uid"], m.target.uid);
            assert_ne!(
                changed["metadata"]["resourceVersion"],
                before["metadata"]["resourceVersion"]
            );
            assert_eq!(
                changed["metadata"]["annotations"][terraform_plan::ANNOTATION],
                "external"
            );
            proof["external_target_change"] = changed;
        }
        "suspend" => {
            let pid = gateway.id().unwrap();
            let process = rustix::process::Pid::from_raw(pid as i32).unwrap();
            rustix::process::kill_process(process, rustix::process::Signal::STOP).unwrap();
            let mut stopped = false;
            for _ in 0..20 {
                let state = tokio::process::Command::new("/bin/ps")
                    .args(["-p", &pid.to_string(), "-o", "stat="])
                    .output()
                    .await
                    .unwrap();
                if String::from_utf8_lossy(&state.stdout).contains('T') {
                    stopped = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(stopped, "gateway SIGSTOP was not observed");
            let wait = (g.expires_at - SystemClock.now_ms()).max(0) as u64 + 25;
            assert!(wait < 25000);
            tokio::time::sleep(Duration::from_millis(wait)).await;
            assert!(SystemClock.now_ms() >= g.expires_at);
            rustix::process::kill_process(process, rustix::process::Signal::CONT).unwrap();
            proof["sigstop_observed"] = json!(true);
            proof["sigcont_after_grant_expiry"] = json!(true);
        }
        "backend-lock" | "backend-serial" | "backend-lineage" | "backend-before-check" => {
            proof["backend_intervention"] = backend::inject(mode, &n.boundary, m).await;
        }
        _ => unreachable!(),
    }
    if mode != "suspend" {
        assert!(
            SystemClock.now_ms() < g.expires_at,
            "intervention was masked by grant expiry"
        );
    }
    n.boundary.released.notify_one();
    proof
}
pub(super) fn certify(mode: &str, n: &Native, intent: &Value) {
    let expected_intent = match mode {
        "backend-lock" | "backend-serial" | "backend-lineage" => Some("unknown"),
        "kill-before-publish" => Some("applied"),
        "kill-after-intent" | "kill-after-effect" => Some("started"),
        _ => None,
    };
    if let Some(state) = expected_intent {
        assert_eq!(intent["state"], state);
    } else {
        assert!(intent.is_null());
    }
    assert_eq!(
        n.outcomes.load(Ordering::SeqCst),
        usize::from(!killed(mode))
    );
    assert_eq!(
        n.intent_outcomes.load(Ordering::SeqCst),
        usize::from(matches!(
            mode,
            "kill-before-publish" | "backend-lock" | "backend-serial" | "backend-lineage"
        ))
    );
    assert_eq!(
        n.intent_requests.load(Ordering::SeqCst),
        usize::from(!matches!(
            mode,
            "target-drift" | "suspend" | "backend-before-check"
        ))
    );
}
pub(super) fn verify_checkpoint(mode: &str, record: &Value) {
    let committed = matches!(
        mode,
        "kill-after-intent"
            | "target-drift"
            | "suspend"
            | "backend-lock"
            | "backend-serial"
            | "backend-lineage"
            | "backend-before-check"
    );
    let aborted = matches!(mode, "kill-after-effect" | "kill-before-publish");
    assert_eq!(record["committed_before_intervention"], committed);
    assert_eq!(record["request_not_forwarded"], aborted);
    if mode == "revoke-at-intent" {
        assert_eq!(record["compare_succeeded"], false);
    }
}
#[tokio::test]
async fn gateway_sigkill_after_intent_before_reply_is_query_only() {
    run("kill-after-intent").await;
}
#[tokio::test]
async fn gateway_sigkill_after_effect_before_intent_outcome_stays_unresolved() {
    run("kill-after-effect").await;
}
#[tokio::test]
async fn gateway_sigkill_before_ordinary_publication_does_not_promote_intent() {
    run("kill-before-publish").await;
}
#[tokio::test]
async fn domain_revocation_at_intent_cas_refuses_effect() {
    run("revoke-at-intent").await;
}
#[tokio::test]
async fn independent_target_drift_after_dispatch_is_detected_before_intent() {
    run("target-drift").await;
}
#[tokio::test]
async fn sigstop_resume_after_grant_expiry_cannot_apply() {
    run("suspend").await;
}
