//! Shipping managed controller, actual SQL/native source and independent audit.
use super::supervisor::{Process as SupervisorProcess, SinkServer};
use super::*;
use kedgeflow::managed_drain_evidence as proof;
const OUTCOME: &str = "owned-managed-controller-outcome-credential-0000000";
struct Process {
    directory: tempfile::TempDir,
    config: PathBuf,
    endpoint: String,
    gateway: reqwest::Client,
    outcome: reqwest::Client,
    gateway_transport: kedgeflow::tls::PinnedClient,
    query_tls: (String, String, String),
}
impl Process {
    fn new(
        r: &Ready,
        source: &SourceProcess,
        identity: &[support::Pki],
        listen: std::net::SocketAddr,
    ) -> Self {
        Self::with_broker(r, source, identity, listen, "https://broker.test/exchange")
    }
    fn with_broker(
        r: &Ready,
        source: &SourceProcess,
        identity: &[support::Pki],
        listen: std::net::SocketAddr,
        broker: &str,
    ) -> Self {
        Self::with_broker_endpoint(r, source, identity, listen, broker, None)
    }
    fn with_broker_endpoint(
        r: &Ready,
        source: &SourceProcess,
        identity: &[support::Pki],
        listen: std::net::SocketAddr,
        broker: &str,
        external: Option<&str>,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory.path().canonicalize().unwrap();
        let write = |name: &str, raw: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, raw).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let incoming: Vec<_> = if broker == "https://broker.test/exchange" {
            support::pki_for_workloads(&[
                "spiffe://test/drain-controller",
                "spiffe://test/gateway",
                "spiffe://test/outcome",
            ])
        } else {
            // The combined gateway uses one independently held gateway identity
            // across native, broker and controller transports. No controller,
            // source or observer private key is copied into its process root.
            [0, 6, 7].into_iter().map(|i| identity[i].clone()).collect()
        };
        let ca = write("native-ca.pem", identity[0].ca.as_bytes());
        let cert = write("controller-client.pem", identity[0].client.as_bytes());
        let key = write("controller-client.key", identity[0].client_key.as_bytes());
        let native_token = write("native.token", CONTROLLER_ETCD.as_bytes());
        let source_token = write("source.token", QUERY.as_bytes());
        let query_token = write("outcome.token", OUTCOME.as_bytes());
        let api_ca = write("api-ca.pem", &r.api_ca);
        let api_token = write(
            "mutator.token",
            &std::fs::read(
                Path::new(&std::env::var("KF_KUBE_FIXTURE").unwrap()).join("mutator.token"),
            )
            .unwrap(),
        );
        let signer = write("controller.key", STANDARD.encode([47; 32]).as_bytes());
        let server_ca = write("workload-ca.pem", incoming[0].ca.as_bytes());
        let server = write("server.pem", incoming[0].server.as_bytes());
        let server_key = write("server.key", incoming[0].server_key.as_bytes());
        let endpoint = external
            .map(str::to_owned)
            .unwrap_or_else(|| format!("https://{listen}"));
        let config = write("managed-controller.json", &canonical(&json!({
            "profile": kedgeflow::managed_drain::PROFILE,
            "controller": {
                "material_root":dir,"family":{"registration":r.r,"etcd_endpoint":source._relay.url,
                    "etcd_prefix":r.r.namespace,"etcd_ca":ca,"etcd_certificate":cert,
                    "etcd_private_key":key,"etcd_token_file":native_token,"restore_gate":null},
                "child_id":"child-1","api":{"material_root":dir,"ca_file":api_ca,"token_file":api_token},
                "controller_key_id":"key-47","controller_key_file":signer,
                "token_issuer":broker,"target_keys":public(29),
                "gateway_workload":"spiffe://test/gateway","query_workload":"spiffe://test/outcome",
                "target_audience":format!("{endpoint}/accept"),"target_scope":"node:drain",
                "query_token_file":query_token,"listen":listen,"dispatch_url":format!("{endpoint}/accept"),
                "query_url":format!("{endpoint}/query"),"certificate":server,"private_key":server_key,"workload_ca":server_ca
            },
            "current_sql":{"ca_file":ca,"certificate_file":cert,"private_key_file":key,"token_file":source_token}
        })).unwrap());
        let client = |p: &support::Pki| {
            kedgeflow::tls::pinned_http_client_pem(
                p.ca.as_bytes(),
                p.client.as_bytes(),
                p.client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap()
        };
        Self {
            directory,
            config,
            endpoint,
            gateway: client(&incoming[1]),
            outcome: client(&incoming[2]),
            query_tls: (
                incoming[2].ca.clone(),
                incoming[2].client.clone(),
                incoming[2].client_key.clone(),
            ),
            gateway_transport: kedgeflow::tls::pinned_client_pem(
                incoming[1].ca.as_bytes(),
                incoming[1].client.as_bytes(),
                incoming[1].client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap(),
        }
    }
    fn command(&self, action: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-managed-kube-drain"));
        c.arg("--material-root")
            .arg(self.directory.path().canonicalize().unwrap())
            .arg("--config")
            .arg(&self.config)
            .arg(action)
            .kill_on_drop(true);
        c
    }
    async fn json(&self, action: &str) -> Value {
        let out = self.command(action).output().await.unwrap();
        assert!(
            out.status.success(),
            "managed controller {action}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("controller.log")).unwrap_or_default()
    }
    async fn start(&self) -> tokio::process::Child {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.path().join("controller.log"))
            .unwrap();
        let mut child = self
            .command("serve")
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            assert!(child.try_wait().unwrap().is_none(), "{}", self.log());
            if self
                .outcome
                .post(format!("{}/query", self.endpoint))
                .bearer_auth(OUTCOME)
                .json(&json!({"attempt_id":"startup-probe"}))
                .send()
                .await
                .is_ok_and(|response| response.status() != reqwest::StatusCode::BAD_GATEWAY)
            {
                break;
            }
            assert!(std::time::Instant::now() < until, "{}", self.log());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        child
    }
    async fn rejects(&self, value: Value, legacy: bool) {
        let path = self
            .directory
            .path()
            .canonicalize()
            .unwrap()
            .join("rejected.json");
        std::fs::write(&path, canonical(&value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let binary = if legacy {
            env!("CARGO_BIN_EXE_kf-kube-drain")
        } else {
            env!("CARGO_BIN_EXE_kf-managed-kube-drain")
        };
        let out = tokio::process::Command::new(binary)
            .arg("--material-root")
            .arg(self.directory.path().canonicalize().unwrap())
            .arg("--config")
            .arg(path)
            .arg("check")
            .output()
            .await
            .unwrap();
        assert!(
            !out.status.success(),
            "managed controller configuration must refuse substituted enrollment/material"
        );
    }
    async fn negatives(&self, identity: &[support::Pki]) {
        let value: Value = serde_json::from_slice(&std::fs::read(&self.config).unwrap()).unwrap();
        for (pointer, replacement) in [
            ("/profile", json!("KF-MANAGED-KUBE-DRAIN-0.1-draft")),
            ("/controller/child_id", json!("child-0")),
            (
                "/controller/target_audience",
                json!("https://substituted.test/accept"),
            ),
            ("/controller/target_scope", json!("other:scope")),
            (
                "/controller/gateway_workload",
                json!("spiffe://test/physical-supervisor"),
            ),
            (
                "/controller/query_workload",
                json!("spiffe://test/evidence-assembler"),
            ),
            ("/controller/api/material_root", json!("/private/tmp")),
            ("/controller/controller_key_id", json!("key-94")),
            ("/current_sql", Value::Null),
            (
                "/current_sql/token_file",
                value["controller"]["query_token_file"].clone(),
            ),
            (
                "/current_sql/private_key_file",
                json!(self.directory.path().join("../outside.key")),
            ),
        ] {
            let mut v = value.clone();
            *v.pointer_mut(pointer).unwrap() = replacement;
            self.rejects(v, false).await;
        }
        for n in [91, 92, 94, 95] {
            let mut v = value.clone();
            v["controller"]["target_keys"] = json!(public(n));
            self.rejects(v, false).await;
        }
        let mut v = value.clone();
        v["current_sql"]["endpoint"] = json!("https://caller.test/current");
        self.rejects(v, false).await;
        let mut v = value.clone();
        v["unknown"] = json!(true);
        self.rejects(v, false).await;
        self.rejects(value["controller"].clone(), true).await;
        self.rejects(value["controller"].clone(), false).await;
        let dir = self.directory.path().canonicalize().unwrap();
        for (name, raw) in [
            ("wrong.pem", identity[4].client.as_bytes()),
            ("wrong.key", identity[4].client_key.as_bytes()),
        ] {
            let p = dir.join(name);
            std::fs::write(&p, raw).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        for (cert, key) in [
            ("etcd_certificate", "etcd_private_key"),
            ("certificate_file", "private_key_file"),
        ] {
            let mut v = value.clone();
            let target = if cert == "etcd_certificate" {
                &mut v["controller"]["family"]
            } else {
                &mut v["current_sql"]
            };
            target[cert] = json!(dir.join("wrong.pem"));
            target[key] = json!(dir.join("wrong.key"));
            self.rejects(v, false).await;
        }
        let secret = dir.join("controller.key");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o640)).unwrap();
        self.rejects(value, false).await;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    async fn query(&self, attempt: &str) -> kedgeflow::ledger::AuthoritativeObservation {
        let response = self
            .outcome
            .post(format!("{}/query", self.endpoint))
            .bearer_auth(OUTCOME)
            .json(&json!({"attempt_id":attempt}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.json().await.unwrap()
    }
}
#[tokio::test]
async fn kube_drain_real_managed_controller_shipping_acceptance_restart_and_complete_audit() {
    let sink = SinkServer::new(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let (mut r, identity, source, mut source_child) = Box::pin(setup_source_for(
        Some(sink.policy(30000, 16)),
        format!("https://{listen}/accept"),
    ))
    .await;
    let process = Process::new(&r, &source, &identity, listen);
    let supervisor = SupervisorProcess::new(&r, &source, &identity, &sink);
    assert_eq!(process.json("check").await["validated"], true);
    assert_eq!(process.json("state").await, Value::Null);
    process.negatives(&identity).await;
    drop(listener);
    let mut child = process.start().await;
    for (client, path, token) in [
        (&process.gateway, "query", OUTCOME),
        (&process.outcome, "accept", OUTCOME),
    ] {
        let response = client
            .post(format!("{}/{path}", process.endpoint))
            .bearer_auth(token)
            .json(&json!({"attempt_id":"probe"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    eprintln!("shipping controller: protected configuration and incoming role refusals passed");
    source.pending_pause.armed.store(true, Ordering::SeqCst);
    let before = sql_rows(&r).await;
    let (record, candidate, token) = Box::pin(supervisor::authorize(&mut r, &source)).await;
    let response = process
        .gateway
        .post(format!("{}/accept", process.endpoint))
        .bearer_auth(token)
        .json(&kedgeflow::kube_drain_http::Accept {
            profile: kedgeflow::managed_drain::PROFILE.into(),
            operation: "accept".into(),
            signed_grant: URL_SAFE_NO_PAD.encode(record.signed_grant.as_bytes()),
            attempt_id: candidate.attempt_id.clone(),
            parameters: r.physical.f.proposal["parameters"].clone(),
        })
        .send()
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.bytes().await.unwrap();
    if status != reqwest::StatusCode::OK {
        let status = Store::new(r.physical.ledger.clone())
            .unwrap()
            .status()
            .await
            .unwrap();
        let state = r.controller.state().await;
        panic!(
            "shipping acceptance refused: {}; log={}; elapsed_since_dispatch={}ms; operating={}; controller={state:?}",
            String::from_utf8_lossy(&bytes),
            process.log(),
            now() - candidate.grant.issued_at,
            json!(status)
        );
    }
    // The owned transport barrier holds the FIRST Pending transaction before
    // actual native I/O. This keeps the restart boundary deterministic without
    // suppressing the shipping scheduler or treating lost authorization as applied.
    let barrier_until = std::time::Instant::now() + Duration::from_secs(6);
    while source.pending_pause.intercepted.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < barrier_until,
            "Pending CAS barrier not reached: {}",
            process.log()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    source.pending_pause.armed.store(false, Ordering::SeqCst);
    source.pending_pause.release.notify_one();
    eprintln!("shipping controller: original HTTP acceptance retained");
    let accepted: proof::Acceptance = serde_json::from_slice(&bytes).unwrap();
    let store = Store::new(r.physical.ledger.clone()).unwrap();
    accepted
        .controller
        .verify("controller_state", &store.context.physical.controller)
        .unwrap();
    accepted
        .proof
        .verify("controller_cas", &store.context.physical.controller)
        .unwrap();
    assert_eq!(accepted.profile, kedgeflow::managed_drain::PROFILE);
    assert_eq!(
        accepted.enrollment_digest,
        store.context.enrollment.digest().unwrap()
    );
    assert!(accepted.controller.body.steps.is_empty());
    Box::pin(seal_acceptance(
        &r,
        &record,
        &candidate,
        &accepted.controller,
    ))
    .await;
    let retained = r.controller.state().await.unwrap().unwrap();
    assert!(
        retained.body.steps.is_empty(),
        "restart boundary must precede Pending"
    );
    assert_eq!(retained.body.accepted.attempt_id, candidate.attempt_id);
    Box::pin(refresh(&r.physical)).await;
    eprintln!("shipping controller: restarting retained original acceptance before Pending");
    child = process.start().await;
    let until = std::time::Instant::now() + Duration::from_secs(28);
    loop {
        assert!(child.try_wait().unwrap().is_none(), "{}", process.log());
        let state = match r.controller.state().await {
            Ok(Some(state)) => Some(state),
            Err(kedgeflow::error::Error::Unavailable(message))
                if message == "invalid guarded proof read" =>
            {
                // A mutation changed the native epoch during this read-only
                // snapshot. Retry only the query, inside the original wait.
                None
            }
            other => panic!("original controller query refused: {other:?}"),
        };
        if state.as_ref().is_some_and(|state| {
            state.body.steps.len() == 2
                && state.body.steps.iter().all(|step| {
                    step.response
                        .as_ref()
                        .is_some_and(|response| (200..300).contains(&response.http_status))
                })
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "{}; {}; {}",
            process.log(),
            supervisor.log(),
            json!(state)
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let observation = process.query(&candidate.attempt_id).await;
    assert_eq!(observation.status, "committed");
    assert_eq!(observation.attempt_id, candidate.attempt_id);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let observed = supervisor.json("observe").await;
    assert_eq!(
        observed["operating"]["observation"]["resolution"],
        "observed_completed"
    );
    let retained = process.json("state").await;
    assert_eq!(
        retained["body"]["accepted"]["attempt_id"],
        candidate.attempt_id
    );
    let (bundle, trust) = supervisor::export(&supervisor, &r).await;
    let verified = bundle.verify(&trust).unwrap();
    assert_eq!(
        verified["physical"]["physical_status"],
        "observed_completed"
    );
    assert_eq!(verified["operating"]["send_checks"], 2);
    assert_eq!(verified["controller_proofs"], 5);
    assert_eq!(verified["source_claims"], 4);
    assert!(
        bundle.evidence.source.events.iter().any(|event| matches!(
            &event.change,
            kedgeflow::managed_drain_journal::Change::QueryUnavailable { number: 2, reason }
                if reason == "interrupted"
        )),
        "the killed pre-Pending query must remain consumed and expire as interrupted"
    );
    assert_eq!(source.pending_pause.intercepted.load(Ordering::SeqCst), 1);
    assert_eq!(before, sql_rows(&r).await);
    supervisor::save(
        "managed-controller-completed",
        &bundle,
        &trust,
        json!({"shipping_controller":true,"shipping_source":true,"shipping_supervisor":true,"restart_same_original":true,"native_committed_is_acceptance":true,"physical_requests":2,"source_claims":4,"paused_before_native_pending_cas":true,"interrupted_query_claim_remains_consumed":true,"sql_rows_unchanged":true}),
    );
    source_child.kill().await.unwrap();
    source_child.wait().await.unwrap();
}

async fn closure(accepted: bool) {
    let sink = SinkServer::new(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let (mut r, identity, source, mut source_child) = Box::pin(setup_source_for(
        Some(sink.policy(30000, 8)),
        format!("https://{listen}/accept"),
    ))
    .await;
    let process = Process::new(&r, &source, &identity, listen);
    let supervisor = SupervisorProcess::new(&r, &source, &identity, &sink);
    let loaded = kedgeflow::managed_drain_controller_config::Config::load(
        &process.directory.path().canonicalize().unwrap(),
        &process.config,
    )
    .await
    .unwrap();
    let before = sql_rows(&r).await;
    let (record, candidate, token) = Box::pin(supervisor::authorize(&mut r, &source)).await;
    let original = process
        .directory
        .path()
        .canonicalize()
        .unwrap()
        .join("original-grant.json");
    std::fs::write(&original, &record.signed_grant).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
    if accepted {
        let state = loaded
            .controller
            .accept(
                record.signed_grant.clone(),
                candidate.attempt_id.clone(),
                r.physical.f.proposal["parameters"].clone(),
                &token,
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "protected managed acceptance refused: {e}; elapsed_since_issuance={}ms",
                    now() - candidate.grant.issued_at
                )
            });
        assert!(state.body.steps.is_empty());
        loaded
            .controller
            .acceptance_result(state.clone())
            .await
            .unwrap();
        Box::pin(seal_acceptance(&r, &record, &candidate, &state)).await;
        assert!(
            !process
                .command("close-unstarted")
                .output()
                .await
                .unwrap()
                .status
                .success(),
            "an open family cannot close the step gate"
        );
    } else {
        let out = process
            .command("close-absent")
            .arg("--signed-grant")
            .arg(&original)
            .arg("--attempt")
            .arg(&candidate.attempt_id)
            .output()
            .await
            .unwrap();
        assert!(
            !out.status.success(),
            "an open family cannot close the acceptance gate"
        );
    }
    Box::pin(owner_now(&r.saga, IntentAction::Quiesce, 3)).await;
    let closed = if accepted {
        process.json("close-unstarted").await
    } else {
        let out = process
            .command("close-absent")
            .arg("--signed-grant")
            .arg(&original)
            .arg("--attempt")
            .arg(&candidate.attempt_id)
            .output()
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    if accepted {
        assert!(closed["body"]["steps"].as_array().unwrap().is_empty());
        assert!(closed["body"]["closed"].is_object());
        assert_eq!(process.json("close-unstarted").await, closed);
    } else {
        assert_eq!(closed["body"]["attempt_id"], candidate.attempt_id);
        assert_eq!(process.json("state").await, Value::Null);
        // The public original grant is still subject to the managed root boundary.
        let out = process
            .command("close-absent")
            .arg("--signed-grant")
            .arg(process.directory.path().join("../outside-grant.json"))
            .arg("--attempt")
            .arg(&candidate.attempt_id)
            .output()
            .await
            .unwrap();
        assert!(!out.status.success());
    }
    assert!(
        loaded
            .controller
            .accept(
                record.signed_grant.clone(),
                candidate.attempt_id.clone(),
                r.physical.f.proposal["parameters"].clone(),
                &token
            )
            .await
            .is_err()
    );
    let observation = supervisor.json("observe").await;
    let expected = if accepted {
        "no_physical_effect"
    } else {
        "no_physical_dispatch"
    };
    assert_eq!(
        observation["operating"]["observation"]["resolution"],
        expected
    );
    let (bundle, trust) = supervisor::export(&supervisor, &r).await;
    let verified = bundle.verify(&trust).unwrap();
    assert_eq!(verified["physical"]["physical_status"], expected);
    assert_eq!(verified["operating"]["send_checks"], 0);
    assert_eq!(verified["controller_proofs"], if accepted { 2 } else { 1 });
    assert_eq!(before, sql_rows(&r).await);
    supervisor::save(
        if accepted {
            "managed-controller-closed-unstarted"
        } else {
            "managed-controller-closed-absence"
        },
        &bundle,
        &trust,
        json!({"shipping_controller_configuration":true,"shipping_closure_cli":true,
            "shipping_source":true,"shipping_supervisor":true,"physical_requests":0,
            "accepted":accepted,"closed_gate":closed,"sql_rows_unchanged":true}),
    );
    source_child.kill().await.unwrap();
    source_child.wait().await.unwrap();
}
#[tokio::test]
async fn kube_drain_real_managed_controller_positive_closed_absence_cli_and_pending_audit() {
    Box::pin(closure(false)).await;
}
#[tokio::test]
async fn kube_drain_real_managed_controller_positive_closed_unstarted_cli_and_complete_audit() {
    Box::pin(closure(true)).await;
}

#[path = "kube_drain_managed_agent.rs"]
mod agent;

#[path = "kube_drain_managed_races.rs"]
mod races;
