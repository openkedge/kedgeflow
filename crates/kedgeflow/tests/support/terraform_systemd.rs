//! Linux-only disposable-host adapter; the root helper never ships as a service.
use super::*;
use std::os::unix::process::ExitStatusExt;
pub(super) fn enabled() -> bool {
    std::env::var_os("KF_TERRAFORM_SYSTEMD_STATE").is_some()
}
pub(super) fn command(action: &str, material: &Path, extra: &[&str]) -> std::io::Result<Value> {
    let output = std::process::Command::new("sudo")
        .args([
            "-n",
            "/usr/bin/python3",
            &std::env::var("KF_TERRAFORM_SYSTEMD_HELPER").unwrap(),
            "--state",
            &std::env::var("KF_TERRAFORM_SYSTEMD_STATE").unwrap(),
            "--action",
            action,
            "--material",
            material.to_str().unwrap(),
        ])
        .args(extra)
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(std::io::Error::other)
}
pub(super) async fn async_command(
    action: &str,
    material: &Path,
    extra: &[&str],
) -> std::io::Result<Value> {
    let output = tokio::process::Command::new("sudo")
        .args([
            "-n",
            "/usr/bin/python3",
            &std::env::var("KF_TERRAFORM_SYSTEMD_HELPER").unwrap(),
            "--state",
            &std::env::var("KF_TERRAFORM_SYSTEMD_STATE").unwrap(),
            "--action",
            action,
            "--material",
            material.to_str().unwrap(),
        ])
        .args(extra)
        .output()
        .await?;
    if !output.status.success() {
        return Err(std::io::Error::other(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(std::io::Error::other)
}
pub(super) enum ProcessHandle {
    Native(tokio::process::Child),
    Unit { root: PathBuf, pid: u32 },
}
impl ProcessHandle {
    pub(super) fn id(&self) -> Option<u32> {
        match self {
            Self::Native(p) => p.id(),
            Self::Unit { pid, .. } => Some(*pid),
        }
    }
    pub(super) fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        match self {
            Self::Native(p) => p.try_wait(),
            Self::Unit { root, .. } => {
                let v = command("status", root, &[])?;
                if v["active"] == true {
                    Ok(None)
                } else {
                    Ok(Some(std::process::ExitStatus::from_raw(0)))
                }
            }
        }
    }
    pub(super) async fn kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Native(p) => p.kill().await,
            Self::Unit { root, .. } => {
                command("stop", root, &[])?;
                Ok(())
            }
        }
    }
    pub(super) async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match self {
            Self::Native(p) => p.wait().await,
            Self::Unit { .. } => Ok(std::process::ExitStatus::from_raw(0)),
        }
    }
}
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if let Self::Unit { root, pid } = self {
            // A replacement can reuse the unit name. Dropping the old handle
            // must never stop the newly started process.
            if command("status", root, &[]).is_ok_and(|v| {
                v["properties"]["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    == Some(*pid)
            }) {
                let _ = command("stop", root, &[]);
            }
        }
    }
}
pub(super) async fn witness(
    p: &support::Pki,
) -> (
    kedgeflow::restore::RestoreGate,
    live_agent::Running,
    String,
    String,
) {
    async fn relay(State(origin): State<String>, Json(v): Json<Value>) -> Json<Value> {
        Json(
            reqwest::Client::new()
                .post(format!("{origin}/v3/kv/txn"))
                .json(&v)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap(),
        )
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", l.local_addr().unwrap());
    let prefix = format!("/kf-tfi-witness/{}", rand::random::<u64>());
    let server = serve(
        l,
        p,
        Router::new()
            .route("/v3/kv/txn", post(relay))
            .with_state(std::env::var("ETCD_ENDPOINT").unwrap()),
    )
    .await;
    let client = tls::pinned_http_client_pem(
        p.ca.as_bytes(),
        p.client.as_bytes(),
        p.client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let gate =
        kedgeflow::restore::RestoreGate::new(EtcdLedger::new(client, &url, &prefix).unwrap())
            .unwrap();
    (gate, server, url, prefix)
}
pub(super) async fn intervene(
    mode: &str,
    n: &Native,
    h: &Harness,
    gateway: &mut ProcessHandle,
    root: &Path,
    m: &Manifest,
) -> Value {
    let gate = PathBuf::from(std::env::var("KF_TERRAFORM_ACTIVE_GATE_DIR").unwrap());
    tokio::time::timeout(Duration::from_secs(35), async {
        while !gate.join("entered.json").exists() {
            assert_eq!(
                n.outcomes.load(Ordering::SeqCst),
                0,
                "systemd apply failed before request"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let stored = fault::retained(root);
    let g = GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify_retained(stored["grant"].as_str().unwrap().as_bytes())
    .unwrap();
    assert!(SystemClock.now_ms() + 2000 < g.grant.expires_at);
    let capture = async_command("kill-main", root, &[]).await.unwrap();
    assert_eq!(capture["exit_status"], 9);
    assert_eq!(capture["old_group_empty"], true);
    assert_eq!(capture["escaped_process_terminated"], true);
    assert_eq!(n.outcomes.load(Ordering::SeqCst), 0);
    assert_eq!(n.intent_outcomes.load(Ordering::SeqCst), 0);
    let delay = (g.grant.expires_at - SystemClock.now_ms()).max(0) as u64 + 30;
    assert!(delay < 25000);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    let action = if mode == "systemd-kill-late" {
        "forward"
    } else {
        "drop"
    };
    let temp = gate.join("release.tmp");
    std::fs::write(
        &temp,
        serde_json::to_vec(&json!({"action":action})).unwrap(),
    )
    .unwrap();
    std::fs::rename(temp, gate.join("release.json")).unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while !gate.join("completed.json").exists() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let completed: Value =
        serde_json::from_slice(&std::fs::read(gate.join("completed.json")).unwrap()).unwrap();
    assert_eq!(completed["forwarded"], action == "forward");
    assert_eq!(
        h.ledger
            .execution_status(&g.grant, &g.digest)
            .await
            .unwrap()
            .state,
        "dispatch_authorized"
    );
    let after = fault::kube(m, false).await;
    assert_eq!(
        after["metadata"]["annotations"][terraform_plan::ANNOTATION],
        if action == "forward" {
            m.after_revision.as_str()
        } else {
            m.before_revision.as_str()
        }
    );
    let proof = json!({"systemd":capture,"gate_completion":completed,"target_after":after,"phase":"dispatch_authorized","native_counts":fault::counters(n),"grant_expires_at":g.grant.expires_at});
    write(
        &PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap()),
        "systemd-proof.json",
        serde_json::to_vec_pretty(&proof).unwrap(),
    );
    let _ = gateway;
    proof
}
#[tokio::test]
async fn service_cgroup_stops_escaped_child_and_original_query() {
    run("systemd-kill-drop").await;
}
#[tokio::test]
async fn service_cgroup_cleanup_still_retains_late_effect() {
    run("systemd-kill-late").await;
}
