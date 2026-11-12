//! Certified real provider request held by a test-only pinned loopback API gate.
//! Process disappearance never establishes that an accepted request had no effect.
use super::*;
#[path = "terraform_gateway_death.rs"]
mod death;

pub(super) fn active(mode: &str) -> bool {
    matches!(
        mode,
        "active-provider-kill"
            | "active-terraform-kill"
            | "active-deadline-late"
            | "kill-active-drop"
            | "kill-active-late"
    )
}
#[derive(Clone, Debug)]
struct Process {
    pid: i32,
    parent: i32,
    group: i32,
    state: String,
    name: String,
}
async fn processes() -> Vec<Process> {
    let output = tokio::process::Command::new("/bin/ps")
        .args(["-ww", "-axo", "pid=,ppid=,pgid=,stat=,comm="])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some(Process {
                pid: fields.next()?.parse().ok()?,
                parent: fields.next()?.parse().ok()?,
                group: fields.next()?.parse().ok()?,
                state: fields.next()?.into(),
                name: fields.next()?.into(),
            })
        })
        .collect()
}
fn live(p: &Process) -> bool {
    !p.state.starts_with('Z')
}
async fn read(path: &Path) -> Value {
    serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap()
}
async fn wait_file(path: &Path) -> Value {
    tokio::time::timeout(Duration::from_secs(35), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        read(path).await
    })
    .await
    .expect("active-child checkpoint missing")
}
fn backend_snapshot(m: &Manifest) -> Value {
    let bytes = std::fs::read(m.backend_state_path.as_ref().unwrap()).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let meta = &value["resources"][0]["instances"][0]["attributes"]["metadata"][0];
    json!({"sha256":hex::encode(Sha256::digest(bytes)),"lineage":value["lineage"],"serial":value["serial"],"target_uid":meta["uid"],"target_version":meta["resource_version"],"revision":meta["annotations"][terraform_plan::ANNOTATION]})
}
pub(super) async fn intervene(
    mode: &str,
    n: &Native,
    h: &Harness,
    gateway: &mut tokio::process::Child,
    root: &Path,
    m: &Manifest,
) -> Value {
    let gate = PathBuf::from(std::env::var("KF_TERRAFORM_ACTIVE_GATE_DIR").unwrap());
    assert!(gate.is_absolute() && gate.ends_with("active-gate"));
    let entry = tokio::time::timeout(Duration::from_secs(35), async {
        while !gate.join("entered.json").exists() {
            assert_eq!(
                n.outcomes.load(Ordering::SeqCst),
                0,
                "execution failed before active checkpoint; counts={}",
                fault::counters(n)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        read(&gate.join("entered.json")).await
    })
    .await
    .expect("actual provider request checkpoint missing");
    assert_eq!(
        entry["path"],
        format!(
            "/api/v1/namespaces/{}/configmaps/{}",
            m.target.namespace, m.target.name
        )
    );
    assert_eq!(entry["forwarded"], false);
    let gateway_pid = gateway.id().unwrap() as i32;
    let rows = processes().await;
    let terraform = rows
        .iter()
        .find(|p| p.parent == gateway_pid && p.name.ends_with("/terraform") && live(p))
        .expect("actual active Terraform child missing")
        .clone();
    let provider = rows
        .iter()
        .find(|p| {
            p.parent == terraform.pid
                && p.name.contains("terraform-provider-kubernetes_v2.38.0_x5")
                && live(p)
        })
        .expect("actual active provider child missing")
        .clone();
    assert_eq!(terraform.group, terraform.pid);
    assert_eq!(provider.group, terraform.group);
    let stored = fault::retained(root);
    let verified = GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify_retained(stored["grant"].as_str().unwrap().as_bytes())
    .unwrap();
    assert!(
        SystemClock.now_ms() + 2000 < verified.grant.expires_at,
        "active boundary was masked by expiry"
    );
    let manifest_digest =
        kedgeflow::contracts::digest("terraform-plan-manifest", &json!(m)).unwrap();
    let key = format!(
        "{}/terraform/{manifest_digest}/intent",
        h.ledger.namespace()
    );
    let initial_intent: Value =
        serde_json::from_slice(&h.ledger.read_key(&key).await.unwrap().unwrap()).unwrap();
    assert_eq!(initial_intent["state"], "started");
    assert_eq!(counts(n), [1, 1, 1, 1]);
    let before = fault::kube(m, false).await;
    let backend_before = backend_snapshot(m);
    assert_eq!(backend_before["sha256"], m.files["state.json"]);
    let intervention_at = SystemClock.now_ms();
    if death::crash(mode) {
        return death::intervene(
            mode,
            n,
            h,
            gateway,
            m,
            death::Boundary {
                gate,
                entry,
                gateway_pid,
                terraform,
                provider,
                initial_intent,
                before,
                backend_before,
                intervention_at,
                key,
                grant: verified.grant,
                grant_digest: verified.digest,
            },
        )
        .await;
    }
    if mode != "active-deadline-late" {
        let pid = if mode == "active-provider-kill" {
            provider.pid
        } else {
            terraform.pid
        };
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(pid).unwrap(),
            rustix::process::Signal::KILL,
        )
        .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(28), async {
        while n.outcomes.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("ordinary unknown publication missing");
    let outcome_at = SystemClock.now_ms();
    if mode == "active-terraform-kill" {
        assert!(
            outcome_at - intervention_at < 5000,
            "dead Terraform left provider pipes open until deadline"
        );
    }
    let state = h
        .ledger
        .execution_status(&verified.grant, &verified.digest)
        .await
        .unwrap();
    assert_eq!(state.state, "unknown");
    let backend_after_cleanup = backend_snapshot(m);
    let remaining: Vec<_> = processes()
        .await
        .into_iter()
        .filter(|p| p.group == terraform.group && live(p))
        .collect();
    assert!(
        remaining.is_empty(),
        "tool group remains live: {remaining:?}"
    );
    assert!(
        gateway.try_wait().unwrap().is_none(),
        "test killed gateway instead of its active child"
    );
    if mode == "active-deadline-late" {
        assert!(outcome_at >= verified.grant.expires_at);
    }
    // Forward the already captured original request only after local cleanup
    // and ordinary unknown publication. This is an in-flight server action,
    // never another Terraform invocation or newly acquired credential.
    let action = if mode == "active-deadline-late" {
        "forward"
    } else {
        "drop"
    };
    let release = gate.join("release.tmp");
    std::fs::write(
        &release,
        serde_json::to_vec(&json!({"action":action})).unwrap(),
    )
    .unwrap();
    std::fs::rename(release, gate.join("release.json")).unwrap();
    let completed = wait_file(&gate.join("completed.json")).await;
    assert_eq!(completed["forwarded"], mode == "active-deadline-late");
    if action == "forward" {
        assert_eq!(completed["upstream_status"], 200);
    }
    let after = fault::kube(m, false).await;
    let backend_after_release = backend_snapshot(m);
    assert_eq!(backend_after_cleanup, backend_after_release);
    if action == "forward" {
        assert_eq!(backend_after_release, backend_before);
    }
    let wanted = if action == "forward" {
        &m.after_revision
    } else {
        &m.before_revision
    };
    assert_eq!(
        after["metadata"]["annotations"][terraform_plan::ANNOTATION],
        *wanted
    );
    assert_eq!(after["metadata"]["uid"], m.target.uid);
    let proof = json!({"initial_intent":initial_intent,"terraform_state":terraform.state,"provider_state":provider.state,"backend_at_boundary":backend_before,"backend_after_cleanup":backend_after_cleanup,"backend_after_release":backend_after_release,"gateway_pid":gateway_pid,"terraform_pid":terraform.pid,"provider_pid":provider.pid,"process_group":terraform.group,"terraform_parent":terraform.parent,"provider_parent":provider.parent,"active_request":entry,"intervention_at":intervention_at,"ordinary_unknown_at":outcome_at,"grant_expires_at":verified.grant.expires_at,"signal":if action=="forward" {Value::Null}else{json!(9)},"signal_target":if mode=="active-provider-kill" {"provider"}else if mode=="active-terraform-kill" {"terraform"}else{"dispatch_deadline"},"gateway_alive":true,"no_live_group_at_release":true,"gate_completion":completed,"target_before_release":before,"target_after_release":after});
    let out = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
    std::fs::write(
        out.join("active-child-proof.json"),
        serde_json::to_vec_pretty(&proof).unwrap(),
    )
    .unwrap();
    proof
}
pub(super) fn certify(mode: &str, n: &Native, intent: &Value) {
    if death::crash(mode) {
        assert_eq!(intent["state"], "started");
        assert_eq!(n.intents.load(Ordering::SeqCst), 1);
        assert_eq!(n.intent_outcomes.load(Ordering::SeqCst), 0);
        assert_eq!(n.outcomes.load(Ordering::SeqCst), 0);
        return;
    }
    assert_eq!(
        intent["state"],
        if mode == "active-deadline-late" {
            "started"
        } else {
            "unknown"
        }
    );
    assert_eq!(n.intents.load(Ordering::SeqCst), 1);
    assert_eq!(
        n.intent_outcomes.load(Ordering::SeqCst),
        usize::from(mode != "active-deadline-late")
    );
    assert_eq!(n.outcomes.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn provider_sigkill_during_real_request_retains_unknown() {
    run("active-provider-kill").await;
}
#[tokio::test]
async fn terraform_sigkill_stops_live_provider_without_pipe_deadline() {
    run("active-terraform-kill").await;
}
#[tokio::test]
async fn dispatch_deadline_stops_local_group_but_does_not_bar_late_effect() {
    run("active-deadline-late").await;
}
