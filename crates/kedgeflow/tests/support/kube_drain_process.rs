//! Shipping controller and actual etcd/Kubernetes process-failure qualification.
use super::*;
use axum::{Extension, Json, Router, http::HeaderMap, routing::post};
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{auth::WorkloadIdentity, kube_drain_journal::State, kube_drain_proof::Signed};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};
use tokio::{process::Child, sync::Notify};

const ETCD_TOKEN: &str = "generated-owned-controller-etcd-role-000000000000";
const QUERY_TOKEN: &str = "generated-owned-controller-query-role-00000000000";

#[derive(Default)]
struct PendingGate {
    pending: Notify,
    release: Notify,
    requests: AtomicUsize,
    successful: AtomicUsize,
}

#[derive(Clone, Copy)]
enum Pause {
    PassThrough,
    BeforeCas,
    AfterCas,
    BeforeAcceptCas,
}

struct ProcessFixture {
    directory: tempfile::TempDir,
    config: PathBuf,
    endpoint: String,
    gateway: reqwest::Client,
    query: reqwest::Client,
    gateway_transport: kedgeflow::tls::PinnedClient,
    gate: Arc<PendingGate>,
    _relay: support::HttpsServer,
}

struct ProcessOutcome {
    client: reqwest::Client,
    endpoint: String,
}
#[async_trait::async_trait]
impl kedgeflow::ledger::OutcomeQuerier for ProcessOutcome {
    async fn query(
        &self,
        attempt: &str,
    ) -> kedgeflow::error::Result<kedgeflow::ledger::AuthoritativeObservation> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(QUERY_TOKEN)
            .json(&json!({"attempt_id":attempt}))
            .send()
            .await?;
        if !response.status().is_success() {
            // Even a real 404 remains unknown in native outcome history.
            return Err(kedgeflow::error::Error::Unavailable(
                "original acceptance absent; no effect unknown".into(),
            ));
        }
        Ok(response.json().await?)
    }
}
impl ProcessFixture {
    async fn new(r: &Ready) -> Self {
        Self::with_pause(r, Pause::AfterCas).await
    }
    async fn with_pause(r: &Ready, pause: Pause) -> Self {
        Self::with_broker(r, pause, "https://broker.test/exchange").await
    }
    async fn with_broker(r: &Ready, pause: Pause, broker: &str) -> Self {
        let identities = support::pki_for_workloads(&[
            "spiffe://test/drain-controller",
            "spiffe://test/gateway",
            "spiffe://test/outcome",
        ]);
        let gate = Arc::new(PendingGate::default());
        let target_key = format!(
            "{}/family/drain/{}/state",
            r.r.namespace,
            r.r.composition.as_ref().unwrap().nodes[1].operation_key
        );
        let relay_gate = gate.clone();
        let backend = std::env::var("ETCD_ENDPOINT").unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post(
                move |Extension(workload): Extension<WorkloadIdentity>,
                      headers: HeaderMap,
                      Json(v): Json<Value>| {
                    let gate = relay_gate.clone();
                    let backend = backend.clone();
                    let key = target_key.clone();
                    let client = client.clone();
                    async move {
                        assert_eq!(workload.as_str(), "spiffe://test/drain-controller");
                        assert_eq!(headers["authorization"], ETCD_TOKEN);
                        let pending = v["success"].as_array().unwrap().iter().any(|op| {
                            let p = &op["request_put"];
                            p["key"]
                                .as_str()
                                .and_then(|s| STANDARD.decode(s).ok())
                                .as_deref()
                                == Some(key.as_bytes())
                                && p["value"]
                                    .as_str()
                                    .and_then(|s| STANDARD.decode(s).ok())
                                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                                    .is_some_and(|s| {
                                        s["kind"] == "controller_state"
                                            && s["body"]["steps"].as_array().is_some_and(|a| {
                                                if matches!(pause, Pause::BeforeAcceptCas) {
                                                    a.is_empty() && s["body"]["closed"].is_null()
                                                } else {
                                                    a.last()
                                                        .is_some_and(|x| x["response"].is_null())
                                                }
                                            })
                                    })
                        });
                        if pending {
                            let previous = gate.requests.fetch_add(1, Ordering::SeqCst);
                            if !matches!(pause, Pause::PassThrough) {
                                assert_eq!(previous, 0, "another paused Pending CAS was attempted");
                            }
                            if matches!(pause, Pause::BeforeCas | Pause::BeforeAcceptCas) {
                                gate.pending.notify_one();
                                tokio::time::timeout(
                                    Duration::from_secs(8),
                                    gate.release.notified(),
                                )
                                .await
                                .unwrap();
                            }
                        }
                        let response: Value = client
                            .post(format!("{backend}/v3/kv/txn"))
                            .json(&v)
                            .send()
                            .await
                            .unwrap()
                            .json()
                            .await
                            .unwrap();
                        if pending && response["succeeded"] == true {
                            gate.successful.fetch_add(1, Ordering::SeqCst);
                            // The original Pending exists in real etcd, but the
                            // process cannot pass txn().await and send Kubernetes.
                            if matches!(pause, Pause::AfterCas) {
                                gate.pending.notify_one();
                                tokio::time::timeout(
                                    Duration::from_secs(8),
                                    gate.release.notified(),
                                )
                                .await
                                .unwrap();
                            }
                        }
                        Json(response)
                    }
                },
            ),
        );
        let relay = support::serve_tls(&identities[0], router).await;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = directory.path().canonicalize().unwrap();
        let write = |name: &str, raw: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, raw).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let fixture = PathBuf::from(std::env::var("KF_KUBE_FIXTURE").unwrap());
        let ca = write("kube-ca.pem", &r.api_ca);
        let token = write(
            "mutator.token",
            &std::fs::read(fixture.join("mutator.token")).unwrap(),
        );
        let sign = write("controller.key", STANDARD.encode([47; 32]).as_bytes());
        let etcd_ca = write("etcd-ca.pem", identities[0].ca.as_bytes());
        let etcd_cert = write("etcd-client.pem", identities[0].client.as_bytes());
        let etcd_key = write("etcd-client.key", identities[0].client_key.as_bytes());
        let etcd_token = write("etcd.token", ETCD_TOKEN.as_bytes());
        let certificate = write("server.pem", identities[0].server.as_bytes());
        let private_key = write("server.key", identities[0].server_key.as_bytes());
        let query_token = write("query.token", QUERY_TOKEN.as_bytes());
        write("query-client.pem", identities[2].client.as_bytes());
        write("query-client.key", identities[2].client_key.as_bytes());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        drop(listener);
        let endpoint = format!("https://{listen}");
        let config = write("controller.json", &serde_json::to_vec(&json!({
            "material_root":dir,"family":{"registration":r.r,"etcd_endpoint":relay.url,
                "etcd_prefix":r.r.namespace,"etcd_ca":etcd_ca,"etcd_certificate":etcd_cert,
                "etcd_private_key":etcd_key,"etcd_token_file":etcd_token,"restore_gate":null},
            "child_id":"child-1","api":{"material_root":dir,"ca_file":ca,"token_file":token},
            "controller_key_id":"key-47","controller_key_file":sign,
            "token_issuer":broker,"target_keys":public(29),
            "gateway_workload":"spiffe://test/gateway","query_workload":"spiffe://test/outcome",
            "target_audience":format!("{endpoint}/accept"),"target_scope":"node:drain",
            "query_token_file":query_token,"listen":listen,"dispatch_url":format!("{endpoint}/accept"),
            "query_url":format!("{endpoint}/query"),"certificate":certificate,
            "private_key":private_key,"workload_ca":etcd_ca
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
            gateway_transport: kedgeflow::tls::pinned_client_pem(
                identities[1].ca.as_bytes(),
                identities[1].client.as_bytes(),
                identities[1].client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap(),
            directory,
            config,
            endpoint,
            gateway: client(&identities[1]),
            query: client(&identities[2]),
            gate,
            _relay: relay,
        }
    }
    fn command(&self, action: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-kube-drain"));
        c.arg("--material-root")
            .arg(self.directory.path().canonicalize().unwrap())
            .arg("--config")
            .arg(&self.config)
            .arg(action)
            .kill_on_drop(true);
        c
    }
    async fn start(&self) -> Child {
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.path().join("process.log"))
            .unwrap();
        let mut child = self
            .command("serve")
            .stdout(std::process::Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "shipping controller exited: {}",
                std::fs::read_to_string(self.directory.path().join("process.log")).unwrap()
            );
            if let Ok(response) = self
                .query
                .post(format!("{}/query", self.endpoint))
                .bearer_auth(QUERY_TOKEN)
                .json(&json!({"attempt_id":"startup-probe"}))
                .send()
                .await
                && response.status() == reqwest::StatusCode::NOT_FOUND
            {
                break;
            }
            assert!(
                std::time::Instant::now() < until,
                "controller startup timed out"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        child
    }
    async fn verify_roles(&self) {
        for (client, path, token) in [
            (&self.gateway, "query", QUERY_TOKEN),
            (&self.query, "accept", "generated-invalid-reference-token"),
        ] {
            let response = client
                .post(format!("{}/{path}", self.endpoint))
                .bearer_auth(token)
                .json(&json!({"attempt_id":"role-probe"}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.json::<Value>().await.unwrap()["error"],
                "invalid_workload"
            );
        }
    }
}

#[path = "kube_drain_boundaries.rs"]
mod boundaries;

#[path = "kube_drain_agent.rs"]
mod agent;

async fn accept_original(
    r: &mut Ready,
    process: &ProcessFixture,
) -> (
    kedgeflow::ledger::IssuanceRecord,
    kedgeflow::recovery::Candidate,
    Signed<State>,
) {
    let target = format!("{}/accept", process.endpoint);
    let (record, candidate, token) =
        Box::pin(authorize_physical_for(&mut r.physical, &target)).await;
    let response = process
        .gateway
        .post(&target)
        .bearer_auth(&token)
        .json(&kedgeflow::kube_drain_http::Accept {
            profile: kd::PROFILE.into(),
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
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let accepted: Signed<State> = serde_json::from_slice(&bytes).unwrap();
    accepted
        .verify(
            "controller_state",
            &r.r.composition.as_ref().unwrap().nodes[1]
                .physical
                .as_ref()
                .unwrap()
                .controller,
        )
        .unwrap();
    assert!(accepted.body.steps.is_empty());
    (record, candidate, accepted)
}

/// Selected TLS transport fault in front of the actual owned Kubernetes API.
/// The API server, service-account authorization and target effect stay real.
struct LostApiReply {
    contract: kd::Contract,
    ca: Vec<u8>,
    mutations: Arc<AtomicUsize>,
    backend_status: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for LostApiReply {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl LostApiReply {
    async fn new() -> Self {
        use axum::{
            body::{Body, to_bytes},
            response::{IntoResponse, Response},
        };
        let directory = PathBuf::from(std::env::var("KF_KUBE_FIXTURE").unwrap());
        let original =
            kd::Contract::decode(&std::fs::read(directory.join("contract.json")).unwrap()).unwrap();
        let actual_ca = std::fs::read(directory.join("ca.pem")).unwrap();
        let mut allowed = Vec::<[u8; 32]>::new();
        for role in ["mutator", "observer"] {
            let token = std::fs::read_to_string(directory.join(format!("{role}.token"))).unwrap();
            allowed.push(Sha256::digest(format!("Bearer {}", token.trim()).as_bytes()).into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&actual_ca).unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mutations = Arc::new(AtomicUsize::new(0));
        let backend_status = Arc::new(AtomicUsize::new(0));
        let count = mutations.clone();
        let status = backend_status.clone();
        let origin = original.api_origin.clone();
        let node_path = format!("/api/v1/nodes/{}", original.node.name);
        let router = Router::new().fallback(move |request: axum::extract::Request| {
            let client = client.clone();
            let count = count.clone();
            let status = status.clone();
            let origin = origin.clone();
            let allowed = allowed.clone();
            let node_path = node_path.clone();
            async move {
                let Some(authorization) = request.headers().get("authorization").cloned() else {
                    return reqwest::StatusCode::UNAUTHORIZED.into_response();
                };
                let supplied: [u8; 32] = Sha256::digest(authorization.as_bytes()).into();
                if !allowed.contains(&supplied) {
                    return reqwest::StatusCode::UNAUTHORIZED.into_response();
                }
                let method = request.method().clone();
                let path = request.uri().path().to_owned();
                let target = format!(
                    "{}{}",
                    origin.trim_end_matches('/'),
                    request.uri().path_and_query().unwrap()
                );
                let content_type = request.headers().get("content-type").cloned();
                let body = to_bytes(request.into_body(), 1 << 20).await.unwrap();
                let mut outbound = client
                    .request(method.clone(), target)
                    .header("authorization", authorization)
                    .body(body);
                if let Some(value) = content_type {
                    outbound = outbound.header("content-type", value);
                }
                let mutation = method != reqwest::Method::GET;
                if mutation {
                    assert_eq!(method, reqwest::Method::PATCH);
                    assert_eq!(path, node_path);
                    assert_eq!(
                        count.fetch_add(1, Ordering::SeqCst),
                        0,
                        "controller resent an original API mutation"
                    );
                }
                let mut upstream = outbound.send().await.unwrap();
                let code = upstream.status();
                let mut bytes = Vec::new();
                while let Some(chunk) = upstream.chunk().await.unwrap() {
                    assert!(bytes.len() + chunk.len() <= 4 << 20);
                    bytes.extend_from_slice(&chunk);
                }
                if mutation {
                    assert_eq!(
                        code,
                        reqwest::StatusCode::OK,
                        "actual API did not apply original cordon"
                    );
                    status.store(code.as_u16() as usize, Ordering::SeqCst);
                    // The actual API has replied successfully after its effect.
                    // Hold the response beyond the unchanged five-second client
                    // timeout; this response can never authorize another send.
                    tokio::time::sleep(Duration::from_secs(8)).await;
                }
                Response::builder()
                    .status(code)
                    .header("content-type", "application/json")
                    .body(Body::from(bytes))
                    .unwrap()
            }
        });
        let pki = support::pki();
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(pki.server.as_bytes()))
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(pki.server_key.as_bytes()))
            .unwrap()
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let router = router.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    let service = hyper_util::service::TowerToHyperService::new(router);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        let mut contract = original;
        contract.api_origin = format!("https://{address}/");
        contract.ca_sha256 = hex::encode(Sha256::digest(pki.ca.as_bytes()));
        contract.validate().unwrap();
        Self {
            contract,
            ca: pki.ca.into_bytes(),
            mutations,
            backend_status,
            task,
        }
    }
}

async fn stop_root_now(r: &Ready, operation: u64) {
    let at = now();
    let command = kedgeflow::family::Command::sign(
        kedgeflow::family::CommandPayload {
            family_digest: r.r.digest().unwrap(),
            operation_key: format!("{operation:064x}"),
            expected_head: r._family.status().await.unwrap().head,
            issued_at: at,
            expires_at: (at + 30000).min(r.r.expires_at),
            action: kedgeflow::family::Action::Stop {
                branch_id: "root".into(),
            },
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    r._family.apply(command).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_process_api_effect_lost_reply_restart_never_resends_or_releases_sql() {
    let api = LostApiReply::new().await;
    let mut r = Box::pin(setup_physical_api(Some((
        api.contract.clone(),
        api.ca.clone(),
    ))))
    .await;
    let process = ProcessFixture::with_pause(&r, Pause::PassThrough).await;
    let mut child = process.start().await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let (record, candidate, accepted) = accept_original(&mut r, &process).await;
    seal_acceptance(&r, &record, &candidate, &accepted).await;
    let until = std::time::Instant::now() + Duration::from_secs(9);
    let original = loop {
        // A concurrent native result write can defeat a read's epoch compare.
        // Retry only the observation; this path never authorizes API work.
        let state = match r.controller.state().await {
            Ok(Some(state)) => Some(state),
            Err(kedgeflow::error::Error::Unavailable(_)) => None,
            other => panic!("original state read: {other:?}"),
        };
        if state.as_ref().is_some_and(|state| {
            state
                .body
                .steps
                .last()
                .and_then(|s| s.response.as_ref())
                .is_some_and(|r| r.http_status == 0)
        }) {
            break state.unwrap();
        }
        assert!(
            std::time::Instant::now() < until,
            "original transport ambiguity was not retained"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(api.backend_status.load(Ordering::SeqCst), 200);
    assert_eq!(api.mutations.load(Ordering::SeqCst), 1);
    assert_eq!(process.gate.successful.load(Ordering::SeqCst), 1);
    let pending_attempts = process.gate.requests.load(Ordering::SeqCst);
    let inventory = r.api.inventory(&r.contract).await.unwrap();
    assert!(inventory.target(&r.contract).unwrap().unschedulable);
    assert_eq!(
        inventory.target(&r.contract).unwrap().operation.as_deref(),
        Some(original.body.accepted.operation().unwrap().as_str())
    );
    assert_eq!(
        original
            .body
            .physical_status(&r.contract, &inventory)
            .unwrap(),
        "unknown"
    );
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    stop_root_now(&r, 301).await;
    let mut restarted = process.start().await;
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(api.mutations.load(Ordering::SeqCst), 1);
    assert_eq!(
        process.gate.requests.load(Ordering::SeqCst),
        pending_attempts
    );
    assert_eq!(
        r.controller
            .state()
            .await
            .unwrap()
            .unwrap()
            .digest()
            .unwrap(),
        original.digest().unwrap()
    );
    assert!(r.controller.close_unstarted().await.is_err());
    let aggregate = r
        .saga
        .export(&super::super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(report.status, "unresolved");
    assert_eq!(report.nodes["child-1"].forward, saga::ForwardState::Unknown);
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    retain(&r, "kube-drain-process-lost-api", &aggregate);
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        std::fs::write(PathBuf::from(out).join("kube-drain-process-lost-api/process.json"), canonical(&json!({
            "actual_api_mutation_requests":1,"actual_api_status_before_reply_discard":200,
            "pending_cas_attempts_before_restart":pending_attempts,"pending_cas_successes":1,
            "native_controller_status":"committed acceptance","physical_status":"unknown",
            "cordon_observed":true,"additional_mutations_after_restart":0,
            "original_controller_state_digest":original.digest().unwrap(),
            "scope":"shipping controller processes; selected TLS fault transport over actual Kubernetes API; actual SA permissions; root stopped before restart; host native/SQL orchestration"
        })).unwrap()).unwrap();
    }
    restarted.kill().await.unwrap();
    restarted.wait().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_process_sigkill_after_pending_restarts_query_only_after_root_stop() {
    use std::os::unix::process::ExitStatusExt;
    let mut r = Box::pin(setup_physical()).await;
    let process = ProcessFixture::new(&r).await;
    let checked = process.command("check").output().await.unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let mut child = process.start().await;
    process.verify_roles().await;
    let first_pid = child.id().unwrap();
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let (record, candidate, accepted) = accept_original(&mut r, &process).await;
    tokio::time::timeout(Duration::from_secs(4), process.gate.pending.notified())
        .await
        .unwrap();
    let pending = r.controller.state().await.unwrap().unwrap();
    assert_eq!(pending.body.steps.len(), 1);
    assert!(pending.body.steps[0].response.is_none());
    child.kill().await.unwrap();
    let exit = child.wait().await.unwrap();
    assert_eq!(exit.signal(), Some(9));
    process.gate.release.notify_one();
    seal_acceptance(&r, &record, &candidate, &accepted).await;
    let at = now();
    let command = kedgeflow::family::Command::sign(
        kedgeflow::family::CommandPayload {
            family_digest: r.r.digest().unwrap(),
            operation_key: format!("{:064x}", 300),
            expected_head: r._family.status().await.unwrap().head,
            issued_at: at,
            expires_at: (at + 30000).min(r.r.expires_at),
            action: kedgeflow::family::Action::Stop {
                branch_id: "root".into(),
            },
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    r._family.apply(command).await.unwrap();
    let mut restarted = process.start().await;
    assert_ne!(restarted.id(), Some(first_pid));
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let query = process
        .query
        .post(format!("{}/query", process.endpoint))
        .bearer_auth(QUERY_TOKEN)
        .json(&json!({"attempt_id":candidate.attempt_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(query.status(), reqwest::StatusCode::OK);
    let observed: kedgeflow::ledger::AuthoritativeObservation = query.json().await.unwrap();
    assert_eq!(observed.status, "committed"); // original acceptance only
    let retained = r.controller.state().await.unwrap().unwrap();
    assert_eq!(retained.digest().unwrap(), pending.digest().unwrap());
    assert_eq!(process.gate.requests.load(Ordering::SeqCst), 1);
    assert_eq!(process.gate.successful.load(Ordering::SeqCst), 1);
    let inventory = r.api.inventory(&r.contract).await.unwrap();
    assert!(!inventory.target(&r.contract).unwrap().unschedulable);
    assert!(r.controller.close_unstarted().await.is_err());
    let aggregate = r
        .saga
        .export(&super::super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(report.status, "unresolved");
    assert_eq!(report.nodes["child-1"].forward, saga::ForwardState::Unknown);
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    retain(&r, "kube-drain-process-pending", &aggregate);
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let out = PathBuf::from(out).join("kube-drain-process-pending");
        std::fs::write(out.join("process.json"), canonical(&json!({
            "first_process":first_pid,"first_termination_signal":exit.signal(),
            "restarted_process":restarted.id(),"pending_cas_count":1,
            "original_controller_state_digest":pending.digest().unwrap(),
            "retained_controller_state_digest":retained.digest().unwrap(),
            "actual_node_unschedulable":false,"native_query":"committed controller acceptance",
            "physical_status":"unknown","api_wire_count":"not instrumented in this case; pause is after durable Pending and before its RPC success reply",
            "scope":"shipping controller processes; real etcd behind selected mTLS relay; actual owned Kubernetes API; host native authority and SQL orchestration; no test clock override"
        })).unwrap()).unwrap();
    }
    restarted.kill().await.unwrap();
    restarted.wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_process_quiesce_defeats_paused_pending_cas_and_cli_closes_no_effect() {
    let mut r = Box::pin(setup_physical()).await;
    let process = ProcessFixture::with_pause(&r, Pause::BeforeCas).await;
    let mut child = process.start().await;
    process.verify_roles().await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let (record, candidate, accepted) = accept_original(&mut r, &process).await;
    tokio::time::timeout(Duration::from_secs(4), process.gate.pending.notified())
        .await
        .unwrap();
    assert!(
        r.controller
            .state()
            .await
            .unwrap()
            .unwrap()
            .body
            .steps
            .is_empty()
    );
    // No other native mutation is made while this exact final Pending CAS is
    // paused. The owner quiesce changes its compared native epoch/phase.
    Box::pin(owner_now(&r.saga, IntentAction::Quiesce, 3)).await;
    process.gate.release.notify_one();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(process.gate.requests.load(Ordering::SeqCst), 1);
    assert_eq!(process.gate.successful.load(Ordering::SeqCst), 0);
    assert!(
        r.controller
            .state()
            .await
            .unwrap()
            .unwrap()
            .body
            .steps
            .is_empty()
    );
    seal_acceptance(&r, &record, &candidate, &accepted).await;
    let closed = process.command("close-unstarted").output().await.unwrap();
    assert!(
        closed.status.success(),
        "{}",
        String::from_utf8_lossy(&closed.stderr)
    );
    let closed: Signed<State> = serde_json::from_slice(&closed.stdout).unwrap();
    assert!(closed.body.closed.is_some() && closed.body.steps.is_empty());
    let inventory = r.api.inventory(&r.contract).await.unwrap();
    assert!(!inventory.target(&r.contract).unwrap().unschedulable);
    let aggregate = r
        .saga
        .export(&super::super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        report.nodes["child-1"].forward,
        saga::ForwardState::NoEffect
    );
    assert_eq!(
        report.nodes["child-1"].physical_status.as_deref(),
        Some("no_physical_effect")
    );
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    retain(&r, "kube-drain-process-cas", &aggregate);
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        std::fs::write(PathBuf::from(out).join("kube-drain-process-cas/process.json"), canonical(&json!({
            "process":child.id(),"pending_cas_attempts":1,"pending_cas_successes":0,
            "closed_before_pending":true,"actual_node_unschedulable":false,
            "scope":"shipping controller; final CAS paused before real etcd; permanent owner quiesce wins; no test clock override"
        })).unwrap()).unwrap();
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
