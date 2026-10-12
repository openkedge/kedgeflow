//! Forced process termination of shipping binaries, with test-owned transport
//! barriers and an atomic software target. No production fault-injection hooks.
#![cfg(unix)]
#[path = "support/domain.rs"]
mod domain;
mod support;
use axum::{Extension, Form, Json, Router, extract::State, http::HeaderMap, routing::post};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    auth::{DualAuthenticator, WorkloadIdentity},
    contracts::{Grant, GrantVerifier, canonical, sign_grant},
    gateway::Request,
    ledger::{AuthorityLedger, EtcdLedger},
    recovery::{Candidate, verify_outcomes},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::Notify,
};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Point {
    BeforeClaim,
    AfterClaim,
    BeforeDispatch,
    AfterDispatch,
    TargetCommit,
    BeforeTerminal,
    AfterTerminal,
    BeforeReceipt,
    AfterReceipt,
}
impl Point {
    fn worker(self) -> bool {
        matches!(self, Self::BeforeReceipt | Self::AfterReceipt)
    }
    fn phase(self) -> &'static str {
        match self {
            Self::BeforeClaim | Self::AfterClaim => "claim",
            Self::BeforeDispatch | Self::AfterDispatch => "dispatch",
            Self::BeforeTerminal | Self::AfterTerminal => "terminal",
            Self::BeforeReceipt | Self::AfterReceipt => "receipt",
            Self::TargetCommit => "target",
        }
    }
    fn after(self) -> bool {
        matches!(
            self,
            Self::AfterClaim | Self::AfterDispatch | Self::AfterTerminal | Self::AfterReceipt
        )
    }
}
struct Barrier {
    point: Point,
    armed: AtomicBool,
    entered: Notify,
}
impl Barrier {
    async fn stop(&self) {
        self.entered.notify_one();
        // Before-submit requests are never forwarded later. The bounded test
        // kills its child and aborts the test server's pending connection task.
        std::future::pending::<()>().await;
    }
    fn take(&self, phase: &str) -> bool {
        self.point.phase() == phase && self.armed.swap(false, Ordering::SeqCst)
    }
}
struct TargetState {
    version: u64,
    fence: u64,
    attempts: BTreeMap<String, String>,
}
struct World {
    endpoint: String,
    ledger: EtcdLedger,
    grant: Grant,
    digest: String,
    token: String,
    barrier: Barrier,
    claims: AtomicUsize,
    exchanges: AtomicUsize,
    dispatches: AtomicUsize,
    queries: AtomicUsize,
    target: Mutex<TargetState>,
}
fn phase(body: &Value) -> Option<&'static str> {
    let puts: Vec<_> = body["success"]
        .as_array()?
        .iter()
        .filter_map(|v| v.get("request_put"))
        .collect();
    for p in &puts {
        let key = String::from_utf8(STANDARD.decode(p["key"].as_str()?).ok()?).ok()?;
        if key.ends_with("/receipt-head") {
            return Some("receipt");
        }
    }
    for p in puts {
        let key = String::from_utf8(STANDARD.decode(p["key"].as_str()?).ok()?).ok()?;
        let value = STANDARD.decode(p["value"].as_str()?).ok()?;
        if key.contains("/outbox/") {
            return match value.as_slice() {
                b"claimed_not_dispatched" => Some("claim"),
                b"dispatch_authorized" => Some("dispatch"),
                b"committed" => Some("terminal"),
                _ => None,
            };
        }
    }
    None
}
async fn proxy(
    State(w): State<Arc<World>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let role = workload.as_str();
    assert!(matches!(
        role,
        "spiffe://test/gateway" | "spiffe://test/outcome"
    ));
    assert_eq!(
        headers["authorization"],
        if role.ends_with("gateway") {
            "gateway-etcd-role"
        } else {
            "outcome-etcd-role"
        }
    );
    let phase = phase(&body);
    let expected_role = if w.barrier.point.worker() {
        "spiffe://test/outcome"
    } else {
        "spiffe://test/gateway"
    };
    let stop = role == expected_role && phase.is_some_and(|p| w.barrier.take(p));
    if stop && !w.barrier.point.after() {
        w.barrier.stop().await;
    }
    let response = reqwest::Client::new()
        .post(format!("{}/v3/kv/txn", w.endpoint))
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    if phase == Some("claim") && response["succeeded"] == true {
        w.claims.fetch_add(1, Ordering::SeqCst);
    }
    if stop {
        assert_eq!(
            response["succeeded"], true,
            "barrier must follow a successful transaction"
        );
        w.barrier.stop().await;
    }
    Json(response)
}
async fn exchange(
    State(w): State<Arc<World>>,
    Extension(workload): Extension<WorkloadIdentity>,
    Form(body): Form<BTreeMap<String, String>>,
) -> Json<Value> {
    assert_eq!(workload.as_str(), "spiffe://test/gateway");
    assert_eq!(body["subject_token"], w.token);
    assert_eq!(body["actor_token"], "software-agent-assertion");
    assert_eq!(body["audience"], "urn:kf:crash-target");
    assert_eq!(body["scope"], "mutate");
    assert_eq!(body["kedgeflow_grant_digest"], w.digest);
    let raw = URL_SAFE_NO_PAD.decode(&body["kedgeflow_grant"]).unwrap();
    let verified = verifier(&w.grant).verify(&raw, now()).unwrap();
    assert_eq!(verified.grant, w.grant);
    let status = w
        .ledger
        .execution_status(&w.grant, &w.digest)
        .await
        .unwrap();
    assert_eq!(status.state, "claimed");
    assert_eq!(
        status.attempt_id.as_deref(),
        Some(body["kedgeflow_attempt_id"].as_str())
    );
    w.exchanges.fetch_add(1, Ordering::SeqCst);
    Json(
        json!({"access_token":"software-target-only","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":2,"scope":"mutate"}),
    )
}
async fn dispatch(
    State(w): State<Arc<World>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(workload.as_str(), "spiffe://test/gateway");
    assert_eq!(headers["authorization"], "Bearer software-target-only");
    assert!(!headers.contains_key(kedgeflow::grant_reference::INLINE_HEADER));
    let args = &body["params"]["arguments"];
    let id = args["kf_attempt_id"].as_str().unwrap();
    assert_eq!(args["kf_grant_digest"], w.digest);
    assert_eq!(args["node"], w.grant.resources[0].id);
    assert_eq!(
        args["kf_resource_incarnation"],
        w.grant.resources[0].incarnation
    );
    assert_eq!(args["fence"], w.grant.fence);
    assert_eq!(
        w.ledger
            .execution_status(&w.grant, &w.digest)
            .await
            .unwrap()
            .state,
        "dispatch_authorized"
    );
    w.dispatches.fetch_add(1, Ordering::SeqCst);
    {
        let mut target = w.target.lock().unwrap();
        assert_eq!(args["expected_version"], target.version);
        assert!(w.grant.fence > target.fence);
        assert!(!target.attempts.contains_key(id));
        target.version += 1;
        target.fence = w.grant.fence;
        target.attempts.insert(id.into(), w.digest.clone());
    }
    if w.barrier.take("target") {
        w.barrier.stop().await;
    }
    Json(
        json!({"jsonrpc":"2.0","id":body["id"],"result":{"resultType":"complete","structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":id,"grant_digest":w.digest,"resource":w.grant.resources[0],"fence":w.grant.fence,"status":"committed","post_version":2}}}}),
    )
}
async fn query(
    State(w): State<Arc<World>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(workload.as_str(), "spiffe://test/outcome");
    assert_eq!(headers["authorization"], "Bearer software-query-only");
    assert_eq!(body["profile"], kedgeflow::recovery::PROFILE);
    assert_eq!(body["operation"], "query");
    let id = body["attempt_id"].as_str().unwrap();
    w.queries.fetch_add(1, Ordering::SeqCst);
    let committed = w
        .target
        .lock()
        .unwrap()
        .attempts
        .get(id)
        .is_some_and(|d| d == &w.digest);
    Json(
        json!({"AttemptID":id,"RootID":w.grant.root_id,"GrantDigest":w.digest,"Status":if committed {"committed"} else {"not_found"},"TargetReference":"software:fenced-target:241"}),
    )
}
fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn verifier(g: &Grant) -> GrantVerifier {
    GrantVerifier {
        keys: BTreeMap::from([(
            "test-key".into(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
        )]),
        audience: g.audience.clone(),
    }
}
fn jwt(header: Value, payload: Value, seed: u8) -> String {
    let body = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
    );
    format!(
        "{body}.{}",
        URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[seed; 32])
                .sign(body.as_bytes())
                .to_bytes()
        )
    )
}
/// One software CA; dual-use gateway leaf because the shipping config uses one
/// enrolled certificate for both its server and outgoing client connections.
fn pki() -> (support::Pki, support::Pki, support::Pki) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
    };
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate().unwrap();
    let cert = ca.self_signed(&key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca, &key);
    let leaf = |workload: &str| {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        p.subject_alt_names
            .push(SanType::URI(workload.try_into().unwrap()));
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let leaf = p.signed_by(&key, &issuer).unwrap();
        support::Pki {
            ca: cert.pem(),
            server: leaf.pem(),
            server_key: key.serialize_pem(),
            client: leaf.pem(),
            client_key: key.serialize_pem(),
        }
    };
    (
        leaf("spiffe://test/gateway"),
        leaf("spiffe://test/agent"),
        leaf("spiffe://test/outcome"),
    )
}
struct ScopedServer {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ScopedServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn serve(pki: &support::Pki, router: Router) -> ScopedServer {
    let tls = kedgeflow::tls::server_config_pem(
        pki.server.as_bytes(),
        pki.server_key.as_bytes(),
        pki.ca.as_bytes(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, tls, router)
            .await
            .unwrap();
    });
    ScopedServer { url, task }
}
struct Harness {
    w: Arc<World>,
    _dir: tempfile::TempDir,
    _server: ScopedServer,
    gateway_config: PathBuf,
    worker_config: PathBuf,
    reservation: Option<tokio::net::TcpListener>,
    url: String,
    client: reqwest::Client,
    request: Request,
    signed: String,
    jwk: Value,
    jti: AtomicUsize,
}
impl Harness {
    async fn new(point: Point) -> Option<Self> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(e) => e,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP crash matrix: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = reservation.local_addr().unwrap();
        let url = format!("https://{listen}/mcp");
        let (gateway, agent, outcome) = pki();
        let (mut call, _) = domain::call();
        let time = now();
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes())});
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()));
        let token = jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":call.grant.subject.iss,"sub":call.grant.subject.sub,"aud":url,"exp":time/1000+120,"iat":time/1000,"scope":"mutate kf.status","cnf":{"jkt":jkt}}),
            7,
        );
        let headers = proof(&url, &token, &jwk, 0);
        let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(agent.client.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        let identity = DualAuthenticator::new(
            &call.grant.subject.iss,
            &url,
            &url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
        .authenticate_at(
            &headers,
            &WorkloadIdentity::from_verified_cert_der(cert.as_ref()).unwrap(),
            time / 1000,
        )
        .unwrap();
        call.grant.audience = url.clone();
        call.grant.issued_at = time;
        call.grant.valid_from = time;
        call.grant.expires_at = time + 12000;
        call.grant.subject = identity.subject;
        call.grant.workload_id = identity.workload_id;
        call.grant.dpop_jkt = identity.dpop_jkt;
        call.grant.delegation_digest = identity.delegation_digest;
        let raw = sign_grant(&call.grant, "test-key", &SigningKey::from_bytes(&[6; 32])).unwrap();
        let gd = verifier(&call.grant).verify(&raw, time).unwrap().digest;
        let ledger = EtcdLedger::new(
            reqwest::Client::new(),
            &endpoint,
            format!("/kf-crash/{}/{}", std::process::id(), rand::random::<u64>()),
        )
        .unwrap();
        ledger.publish_policy(&call.grant).await.unwrap();
        ledger.issue(&call.grant, &gd).await.unwrap();
        let w = Arc::new(World {
            endpoint,
            ledger,
            grant: call.grant,
            digest: gd,
            token,
            barrier: Barrier {
                point,
                armed: AtomicBool::new(true),
                entered: Notify::new(),
            },
            claims: AtomicUsize::new(0),
            exchanges: AtomicUsize::new(0),
            dispatches: AtomicUsize::new(0),
            queries: AtomicUsize::new(0),
            target: Mutex::new(TargetState {
                version: 1,
                fence: 0,
                attempts: BTreeMap::new(),
            }),
        });
        let server = serve(
            &gateway,
            Router::new()
                .route("/v3/kv/txn", post(proxy))
                .route("/exchange", post(exchange))
                .route("/target", post(dispatch))
                .route("/query", post(query))
                .with_state(w.clone()),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for (name, body) in [
            ("ca", gateway.ca.as_str()),
            ("gateway-cert", gateway.client.as_str()),
            ("gateway-key", gateway.client_key.as_str()),
            ("outcome-cert", outcome.client.as_str()),
            ("outcome-key", outcome.client_key.as_str()),
            ("actor", "software-agent-assertion"),
            ("gateway-token", "gateway-etcd-role"),
            ("outcome-token", "outcome-etcd-role"),
            ("query-token", "software-query-only"),
        ] {
            std::fs::write(d.join(name), body).unwrap();
        }
        std::fs::write(d.join("receipt-key"), STANDARD.encode([14; 32])).unwrap();
        let cfg = json!({"listen":listen,"external_url":url,"certificate":d.join("gateway-cert"),"private_key":d.join("gateway-key"),"workload_ca":d.join("ca"),"grant_key_id":"test-key","grant_public_key_base64":STANDARD.encode(SigningKey::from_bytes(&[6;32]).verifying_key().as_bytes()),"oidc_issuer":w.grant.subject.iss,"oidc_public_key_base64":STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),"etcd_endpoints":[server.url],"etcd_prefix":w.ledger.namespace(),"etcd_ca":d.join("ca"),"etcd_token_file":d.join("gateway-token"),"broker_endpoint":format!("{}/exchange",server.url),"broker_ca":d.join("ca"),"target_audience":"urn:kf:crash-target","target_scope":"mutate","actor_workload":"spiffe://test/agent","actor_token_file":d.join("actor"),"target_url":format!("{}/target",server.url),"target_ca":d.join("ca"),"tools":[call.descriptor],"require_control":false});
        let gateway_config = d.join("gateway.json");
        std::fs::write(&gateway_config, serde_json::to_vec(&cfg).unwrap()).unwrap();
        let cfg = json!({"etcd_endpoint":server.url,"etcd_prefix":w.ledger.namespace(),"etcd_ca":d.join("ca"),"etcd_certificate":d.join("outcome-cert"),"etcd_private_key":d.join("outcome-key"),"etcd_token_file":d.join("outcome-token"),"gateway_audience":url,"grant_keys":{"test-key":STANDARD.encode(SigningKey::from_bytes(&[6;32]).verifying_key().as_bytes())},"query_url":format!("{}/query",server.url),"query_ca":d.join("ca"),"query_certificate":d.join("outcome-cert"),"query_private_key":d.join("outcome-key"),"query_token_file":d.join("query-token"),"receipt_key_id":"outcome-14","receipt_signing_key_file":d.join("receipt-key"),"source_id":"spiffe://test/outcome","page_size":8,"poll_interval_ms":100});
        let worker_config = d.join("worker.json");
        std::fs::write(&worker_config, serde_json::to_vec(&cfg).unwrap()).unwrap();
        let client = kedgeflow::tls::pinned_http_client_pem(
            agent.ca.as_bytes(),
            agent.client.as_bytes(),
            agent.client_key.as_bytes(),
            Duration::from_secs(8),
        )
        .unwrap();
        Some(Self {
            w,
            _dir: dir,
            _server: server,
            gateway_config,
            worker_config,
            reservation: Some(reservation),
            url,
            client,
            request: call.request,
            signed: String::from_utf8(raw).unwrap(),
            jwk,
            jti: AtomicUsize::new(1),
        })
    }
    async fn gateway(&mut self) -> Child {
        self.reservation.take();
        let mut child = Command::new(env!("CARGO_BIN_EXE_kf-proxy"))
            .args(["--config", self.gateway_config.to_str().unwrap()])
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let line = stderr
                    .next_line()
                    .await
                    .unwrap()
                    .expect("gateway exited before listening");
                if line.contains("reference gateway listening") {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        child
    }
    fn headers(&self) -> HeaderMap {
        proof(
            &self.url,
            &self.w.token,
            &self.jwk,
            self.jti.fetch_add(1, Ordering::SeqCst),
        )
    }
    fn call(&self) -> tokio::task::JoinHandle<reqwest::Result<Value>> {
        let client = self.client.clone();
        let url = self.url.clone();
        let mut request = self.request.clone();
        request.id = json!(self.jti.load(Ordering::SeqCst));
        let mut headers = self.headers();
        headers.insert(
            kedgeflow::grant_reference::INLINE_HEADER,
            URL_SAFE_NO_PAD
                .encode(self.signed.as_bytes())
                .parse()
                .unwrap(),
        );
        tokio::spawn(async move {
            client
                .post(url)
                .headers(headers)
                .json(&request)
                .send()
                .await?
                .json()
                .await
        })
    }
    async fn status(&self) -> Value {
        let mut req = self.request.clone();
        req.id = json!(self.jti.load(Ordering::SeqCst));
        req.method = kedgeflow::execution_status::METHOD.into();
        req.params.arguments =
            json!({"profile":kedgeflow::execution_status::PROFILE,"grant":self.signed});
        req.params
            .meta
            .get_mut("io.modelcontextprotocol/clientCapabilities")
            .unwrap()["extensions"][kedgeflow::execution_status::EXTENSION] =
            json!({"profile":kedgeflow::execution_status::PROFILE});
        self.client
            .post(&self.url)
            .headers(self.headers())
            .json(&req)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    fn worker(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kf-recover"));
        cmd.args(["--config", self.worker_config.to_str().unwrap(), "--once"])
            .kill_on_drop(true);
        cmd
    }
    async fn sweep(&self) -> Value {
        let output = tokio::time::timeout(Duration::from_secs(10), self.worker().output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.w.claims.load(Ordering::SeqCst),
            self.w.exchanges.load(Ordering::SeqCst),
            self.w.dispatches.load(Ordering::SeqCst),
            self.w.target.lock().unwrap().attempts.len(),
        )
    }
    async fn reached(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.w.barrier.entered.notified())
            .await
            .expect("crash barrier not reached");
    }
    async fn receipt(&self, c: &Candidate) -> Option<Vec<u8>> {
        self.w
            .ledger
            .read_key(&format!(
                "{}/domains/{}/roots/{}/attempts/{}/receipt-head",
                self.w.ledger.namespace(),
                URL_SAFE_NO_PAD.encode(c.grant.conflict_domain.as_bytes()),
                URL_SAFE_NO_PAD.encode(c.grant.root_id.as_bytes()),
                URL_SAFE_NO_PAD.encode(c.attempt_id.as_bytes())
            ))
            .await
            .unwrap()
    }
}
fn proof(url: &str, token: &str, jwk: &Value, jti: usize) -> HeaderMap {
    let proof = jwt(
        json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":jwk}),
        json!({"jti":format!("crash-{jti}"),"htm":"POST","htu":url,"iat":now()/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}),
        8,
    );
    let mut h = HeaderMap::new();
    h.insert("authorization", format!("DPoP {token}").parse().unwrap());
    h.insert("dpop", proof.parse().unwrap());
    h
}
async fn kill(child: &mut Child) {
    use std::os::unix::process::ExitStatusExt;
    assert!(
        child.try_wait().unwrap().is_none(),
        "process must still be blocked"
    );
    child.kill().await.unwrap();
    let exit = child.wait().await.unwrap();
    assert_eq!(exit.signal(), Some(9), "forced termination must be SIGKILL");
}
async fn run(point: Point) {
    let Some(mut h) = Harness::new(point).await else {
        return;
    };
    let mut gateway = h.gateway().await;
    let mut request = h.call();
    if point.worker() {
        let reply = request.await.unwrap().unwrap();
        assert!(
            reply.get("result").is_some(),
            "gateway call failed: {reply}"
        );
        kill(&mut gateway).await;
    } else {
        tokio::select! {
            _ = h.reached() => (),
            result = &mut request => panic!("gateway finished before crash barrier: {result:?}"),
        }
        kill(&mut gateway).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
    let before =
        h.w.ledger
            .execution_status(&h.w.grant, &h.w.digest)
            .await
            .unwrap();
    let expected = match point {
        Point::BeforeClaim => "unclaimed",
        Point::AfterClaim | Point::BeforeDispatch => "claimed",
        Point::AfterTerminal | Point::BeforeReceipt | Point::AfterReceipt => "committed",
        _ => "dispatch_authorized",
    };
    assert_eq!(before.state, expected);
    let expected_counts = match point {
        Point::BeforeClaim => (0, 0, 0, 0),
        Point::AfterClaim => (1, 0, 0, 0),
        Point::BeforeDispatch | Point::AfterDispatch => (1, 1, 0, 0),
        _ => (1, 1, 1, 1),
    };
    assert_eq!(h.counts(), expected_counts);
    let c = before.attempt_id.clone().map(|id| Candidate {
        grant: h.w.grant.clone(),
        attempt_id: id,
    });
    let mut gateway = h.gateway().await;
    // A new RPC ID/PoP proof against a consumed grant resolves the original
    // attempt even before expiry. It cannot exchange another target credential.
    if c.is_some() {
        assert!(
            now() < h.w.grant.expires_at,
            "fixture budget expired before retry qualification"
        );
        let reply = h.call().await.unwrap().unwrap();
        assert_eq!(reply["error"]["message"], "NONCE_CONSUMED");
        assert_eq!(
            reply["error"]["data"]["attempt_id"],
            before.attempt_id.clone().unwrap()
        );
    }
    if point.worker() {
        let c = c.as_ref().unwrap();
        assert!(h.receipt(c).await.is_none());
        let stdout = h._dir.path().join("blocked-worker.stdout");
        let stderr = h._dir.path().join("blocked-worker.stderr");
        let mut worker = h
            .worker()
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let diagnostics = || {
            format!(
                "stdout: {}; stderr: {}",
                std::fs::read_to_string(&stdout).unwrap_or_default(),
                std::fs::read_to_string(&stderr).unwrap_or_default()
            )
        };
        tokio::select! {
            reached = tokio::time::timeout(Duration::from_secs(5), h.w.barrier.entered.notified()) => {
                assert!(reached.is_ok(), "crash barrier not reached: {}", diagnostics());
            },
            status = worker.wait() => panic!("worker exited before crash barrier ({status:?}): {}", diagnostics()),
        }
        kill(&mut worker).await;
        assert_eq!(h.receipt(c).await.is_some(), point == Point::AfterReceipt);
    }
    let retained_head = match &c {
        Some(c) => h.receipt(c).await,
        None => None,
    };
    let wait = h.w.grant.expires_at.saturating_sub(now()) + 1;
    if wait > 0 {
        tokio::time::sleep(Duration::from_millis(wait as u64)).await;
    }
    let first = h.sweep().await;
    assert_eq!(first["examined"], if c.is_some() { 1 } else { 0 });
    assert_eq!(first["unavailable"], 0);
    let recovered = match point {
        Point::BeforeClaim => "unclaimed",
        Point::AfterClaim | Point::BeforeDispatch => "not_dispatched",
        Point::AfterDispatch => "unknown",
        _ => "committed",
    };
    for _ in 0..3 {
        let reply = h.status().await;
        assert_eq!(
            reply["result"]["state"], recovered,
            "status failed: {reply}"
        );
        assert_eq!(reply["result"]["attempt_id"], json!(before.attempt_id));
    }
    let head = match &c {
        Some(c) => h.receipt(c).await,
        None => None,
    };
    if point == Point::AfterReceipt {
        assert_eq!(head, retained_head);
    }
    let second = h.sweep().await;
    assert_eq!(second["unavailable"], 0);
    if let Some(c) = &c {
        assert_eq!(h.receipt(c).await, head);
        let original =
            h.w.ledger
                .execution_status(&h.w.grant, &h.w.digest)
                .await
                .unwrap();
        assert_eq!(original.attempt_id.as_ref(), Some(&c.attempt_id));
        assert!(matches!(
            h.w.ledger
                .claim(&h.w.grant, &h.w.digest, "replacement-attempt")
                .await,
            Err(kedgeflow::error::Error::NonceConsumed)
        ));
        let mut next = h.w.grant.clone();
        next.root_generation += 1;
        next.fence += 1;
        next.gid.push_str("-replacement");
        assert!(
            h.w.ledger
                .replace(&h.w.grant, &next, &h.w.digest)
                .await
                .is_err()
        );
        let bundle = h.w.ledger.export_outcomes(c).await.unwrap();
        assert_eq!(bundle.receipts.len(), 1);
        let report = verify_outcomes(
            &bundle,
            &verifier(&h.w.grant),
            &BTreeMap::from([(
                "outcome-14".into(),
                SigningKey::from_bytes(&[14; 32]).verifying_key(),
            )]),
            "spiffe://test/outcome",
        )
        .unwrap();
        assert_eq!(report.reported_status, recovered);
    }
    assert_eq!(h.counts(), expected_counts);
    let queries = h.w.queries.load(Ordering::SeqCst);
    assert_eq!(
        queries,
        match point {
            Point::AfterDispatch => 2,
            Point::TargetCommit | Point::BeforeTerminal => 1,
            _ => 0,
        }
    );
    kill(&mut gateway).await;
    println!(
        "crash matrix: {}",
        json!({"point":format!("{point:?}"),"termination":"SIGKILL; waited before restart","before":expected,"after":recovered,"claims":expected_counts.0,"exchanges":expected_counts.1,"dispatches":expected_counts.2,"target_commits":expected_counts.3,"queries":queries,"receipts":if c.is_some() {1} else {0},"additional_claims_exchanges_dispatches":0})
    );
}
#[tokio::test]
async fn killed_gateway_before_claim() {
    run(Point::BeforeClaim).await;
}
#[tokio::test]
async fn killed_gateway_after_claim_before_response() {
    run(Point::AfterClaim).await;
}
#[tokio::test]
async fn killed_gateway_before_dispatch_authorization() {
    run(Point::BeforeDispatch).await;
}
#[tokio::test]
async fn killed_gateway_after_dispatch_before_response() {
    run(Point::AfterDispatch).await;
}
#[tokio::test]
async fn killed_gateway_after_target_commit_before_reply() {
    run(Point::TargetCommit).await;
}
#[tokio::test]
async fn killed_gateway_after_target_reply_before_terminal_cas() {
    run(Point::BeforeTerminal).await;
}
#[tokio::test]
async fn killed_gateway_after_terminal_cas_before_response() {
    run(Point::AfterTerminal).await;
}
#[tokio::test]
async fn killed_worker_before_receipt_cas() {
    run(Point::BeforeReceipt).await;
}
#[tokio::test]
async fn killed_worker_after_receipt_cas_before_response() {
    run(Point::AfterReceipt).await;
}
