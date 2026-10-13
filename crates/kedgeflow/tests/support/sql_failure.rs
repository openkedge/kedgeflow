//! RFC 0026: fresh signed SQL path, shipping process kills and witnessed recovery.
use super::exchange;
use super::*;
use axum::{
    Extension, Json, Router,
    extract::{Request as HttpRequest, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    auth::WorkloadIdentity,
    clock::{Clock, SystemClock},
    control::{ControlPermissions, ControlService},
    error::Error,
    ledger::OutcomeQuerier,
    outcome_report_service::{OutcomeReportService, ReporterTrust},
    postgres_store::{PostgresStore, ReservationStore, UnixDatabase},
    recovery::Candidate,
    recovery_config::HttpOutcomeQuerier,
    restore::RestoreGate,
    tls,
};
use live_agent::{Provider, Running, Target};
use std::{
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicBool, AtomicUsize},
};
use support::witness::WitnessProcess;
use tokio::{
    process::Child,
    sync::{Mutex, Notify},
};
const QUERY_TOKEN: &str = "generated-sql-failure-query-only-00000000000000000000";
const REPORT_AUD: &str = "urn:kedgeflow:sql-failure-reports";
const RECOVERY: &str = "spiffe://test/recovery";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    Claim,
    Mint,
    Authorized,
    Commit,
    TargetLock,
    TargetCommit,
    BrokerMint,
    PendingWitness,
    Restore,
    Incident,
    RecoveryReceipt,
}
impl Point {
    fn sql_committed(self) -> bool {
        matches!(
            self,
            Self::Commit
                | Self::TargetCommit
                | Self::Restore
                | Self::Incident
                | Self::RecoveryReceipt
        )
    }
    fn broker_count(self) -> usize {
        usize::from(!matches!(self, Self::Claim | Self::PendingWitness))
    }
    fn dispatch_count(self) -> usize {
        usize::from(matches!(
            self,
            Self::Authorized
                | Self::Commit
                | Self::TargetLock
                | Self::TargetCommit
                | Self::Restore
                | Self::Incident
                | Self::RecoveryReceipt
        ))
    }
}
struct Boundary {
    point: Point,
    entered: Notify,
    release: Notify,
    armed: AtomicBool,
    claims: AtomicUsize,
    permits: AtomicUsize,
    authorizations: AtomicUsize,
    broker_calls: AtomicUsize,
    broker_replies: AtomicUsize,
    broker_forwards: AtomicUsize,
    target_calls: AtomicUsize,
    target_forwards: AtomicUsize,
    queries: AtomicUsize,
    unavailable_query: AtomicBool,
    pending_claim: AtomicBool,
    receipt_seen: AtomicBool,
    receipt_entered: Notify,
    receipt_armed: AtomicBool,
}
impl Boundary {
    fn new(point: Point) -> Self {
        Self {
            point,
            entered: Notify::new(),
            release: Notify::new(),
            armed: AtomicBool::new(true),
            claims: AtomicUsize::new(0),
            permits: AtomicUsize::new(0),
            authorizations: AtomicUsize::new(0),
            broker_calls: AtomicUsize::new(0),
            broker_replies: AtomicUsize::new(0),
            broker_forwards: AtomicUsize::new(0),
            target_calls: AtomicUsize::new(0),
            target_forwards: AtomicUsize::new(0),
            queries: AtomicUsize::new(0),
            unavailable_query: AtomicBool::new(point == Point::Incident),
            pending_claim: AtomicBool::new(false),
            receipt_seen: AtomicBool::new(false),
            receipt_entered: Notify::new(),
            receipt_armed: AtomicBool::new(true),
        }
    }
    fn take(&self, point: Point) -> bool {
        self.point == point && self.armed.swap(false, Ordering::SeqCst)
    }
    async fn stop(&self) {
        self.entered.notify_one();
        std::future::pending::<()>().await;
    }
    async fn reached(&self) {
        tokio::time::timeout(Duration::from_secs(12), self.entered.notified())
            .await
            .expect("SQL failure barrier not reached");
    }
}
fn writes(v: &Value) -> std::vec::IntoIter<(String, Vec<u8>)> {
    let mut result = Vec::new();
    for op in v["success"].as_array().into_iter().flatten() {
        if let Some(nested) = op.get("request_txn") {
            result.extend(writes(nested));
        }
        if let Some(put) = op.get("request_put") {
            let key =
                String::from_utf8(STANDARD.decode(put["key"].as_str().unwrap()).unwrap()).unwrap();
            result.push((
                key,
                STANDARD.decode(put["value"].as_str().unwrap()).unwrap(),
            ));
        }
    }
    result.into_iter()
}
fn succeeded(v: &Value) -> bool {
    v["succeeded"] == true
        && v["responses"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|op| op.get("response_txn"))
            .all(succeeded)
}
struct EtcdRelay {
    origin: String,
    witness: bool,
    boundary: Arc<Boundary>,
}
async fn etcd_relay(
    State(p): State<Arc<EtcdRelay>>,
    Extension(w): Extension<WorkloadIdentity>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Json<Value> {
    let role = match w.as_str() {
        "spiffe://test/gateway" => "gateway-etcd-role",
        "spiffe://test/broker" => "broker-etcd-role",
        RECOVERY => "recovery-etcd-role",
        _ => panic!("unenrolled ledger peer"),
    };
    assert_eq!(
        h["authorization"],
        if p.witness { "witness-role" } else { role }
    );
    let claim = writes(&v)
        .any(|(key, value)| key.contains("/outbox/") && value == b"claimed_not_dispatched");
    let permit = writes(&v).any(|(key, _)| key.ends_with("/credential-permit"));
    let authorized =
        writes(&v).any(|(key, value)| key.contains("/outbox/") && value == b"dispatch_authorized");
    let ready = writes(&v).any(|(_, value)| {
        serde_json::from_slice::<Value>(&value).is_ok_and(|v| v["state"] == "ready")
    });
    if p.witness
        && ready
        && p.boundary.pending_claim.load(Ordering::SeqCst)
        && p.boundary.take(Point::PendingWitness)
    {
        p.boundary.stop().await;
    }
    let answer = reqwest::Client::new()
        .post(format!("{}/v3/kv/txn", p.origin))
        .json(&v)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    if p.witness
        && ready
        && p.boundary.receipt_seen.load(Ordering::SeqCst)
        && p.boundary.point == Point::RecoveryReceipt
        && p.boundary.receipt_armed.swap(false, Ordering::SeqCst)
    {
        p.boundary.receipt_entered.notify_one();
        std::future::pending::<()>().await;
    }
    if !p.witness && succeeded(&answer) {
        if writes(&v).any(|(key, _)| key.ends_with("/receipt-head")) {
            p.boundary.receipt_seen.store(true, Ordering::SeqCst);
        }
        if claim {
            p.boundary.claims.fetch_add(1, Ordering::SeqCst);
            p.boundary.pending_claim.store(true, Ordering::SeqCst);
        }
        if permit {
            p.boundary.permits.fetch_add(1, Ordering::SeqCst);
        }
        if authorized {
            p.boundary.authorizations.fetch_add(1, Ordering::SeqCst);
        }
    }
    Json(answer)
}
struct ServiceRelay {
    upstream: String,
    public: String,
    client: reqwest::Client,
    boundary: Arc<Boundary>,
    broker: bool,
}
async fn service_relay(
    State(p): State<Arc<ServiceRelay>>,
    Extension(w): Extension<WorkloadIdentity>,
    h: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if p.broker
        || serde_json::from_slice::<Value>(&body).is_ok_and(|v| v["operation"] == "dispatch")
    {
        assert_eq!(w.as_str(), "spiffe://test/gateway");
        if p.broker {
            p.boundary.broker_calls.fetch_add(1, Ordering::SeqCst);
            if p.boundary.take(Point::Claim) {
                p.boundary.stop().await;
            }
        } else {
            p.boundary.target_calls.fetch_add(1, Ordering::SeqCst);
            if p.boundary.take(Point::Authorized) {
                p.boundary.stop().await;
            }
            p.boundary.target_forwards.fetch_add(1, Ordering::SeqCst);
            if p.boundary.point == Point::TargetLock {
                p.boundary.entered.notify_one();
            }
        }
    } else {
        assert_eq!(w.as_str(), RECOVERY);
        assert_eq!(h["authorization"], format!("Bearer {QUERY_TOKEN}"));
        p.boundary.queries.fetch_add(1, Ordering::SeqCst);
        if p.boundary.unavailable_query.load(Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    let operation = serde_json::from_slice::<Value>(&body).ok();
    let path = if p.broker {
        "/exchange"
    } else if operation
        .as_ref()
        .is_some_and(|v| v["operation"] == "dispatch")
    {
        "/dispatch"
    } else {
        "/query"
    };
    let url = reqwest::Url::parse(&p.public).unwrap();
    if p.broker {
        p.boundary.broker_forwards.fetch_add(1, Ordering::SeqCst);
    }
    let mut request = p.client.post(format!("{}{path}", p.upstream)).header(
        "host",
        format!("{}:{}", url.host_str().unwrap(), url.port().unwrap()),
    );
    for name in ["content-type", "authorization"] {
        if let Some(value) = h.get(name) {
            request = request.header(name, value);
        }
    }
    let response = match request.body(body).send().await {
        Ok(r) => r,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let status = response.status();
    let raw = response.bytes().await.unwrap();
    if status.is_success() {
        if p.broker {
            p.boundary.broker_replies.fetch_add(1, Ordering::SeqCst);
            if p.boundary.take(Point::Mint) {
                p.boundary.stop().await;
            }
            if p.boundary.take(Point::BrokerMint) {
                p.boundary.entered.notify_one();
                p.boundary.release.notified().await;
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        } else if serde_json::from_slice::<Value>(&raw).is_ok_and(|v| v["status"] == "committed") {
            if [
                Point::Commit,
                Point::Restore,
                Point::Incident,
                Point::RecoveryReceipt,
            ]
            .iter()
            .any(|point| p.boundary.take(*point))
            {
                p.boundary.stop().await;
            }
            if p.boundary.take(Point::TargetCommit) {
                p.boundary.entered.notify_one();
                p.boundary.release.notified().await;
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
    }
    (status, [("content-type", "application/json")], raw).into_response()
}
struct Native {
    child: Child,
    binary: &'static str,
    config: PathBuf,
    address: std::net::SocketAddr,
    stderr: PathBuf,
}
impl Native {
    async fn start(binary: &'static str, config: PathBuf, address: std::net::SocketAddr) -> Self {
        let stderr = config.with_extension("stderr.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stderr)
            .unwrap();
        let child = tokio::process::Command::new(binary)
            .args(["--config", config.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(file)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut result = Self {
            child,
            binary,
            config,
            address,
            stderr,
        };
        for _ in 0..200 {
            assert!(
                result.child.try_wait().unwrap().is_none(),
                "native process exited: {}",
                std::fs::read_to_string(&result.stderr).unwrap_or_default()
            );
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("native service failed to listen");
    }
    async fn kill(&mut self) {
        self.child.start_kill().unwrap();
        let status = self.child.wait().await.unwrap();
        assert_eq!(status.signal(), Some(9));
    }
    async fn restart(&mut self) {
        let next = Self::start(self.binary, self.config.clone(), self.address).await;
        *self = next;
    }
}
async fn address() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    (listener, url)
}
fn client(p: &support::Pki) -> reqwest::Client {
    tls::pinned_http_client_pem(
        p.ca.as_bytes(),
        p.client.as_bytes(),
        p.client_key.as_bytes(),
        Duration::from_secs(10),
    )
    .unwrap()
}
fn server(p: &support::Pki) -> Arc<rustls::ServerConfig> {
    tls::server_config_pem(
        p.server.as_bytes(),
        p.server_key.as_bytes(),
        p.ca.as_bytes(),
    )
    .unwrap()
}
async fn serve(listener: tokio::net::TcpListener, p: &support::Pki, router: Router) -> Running {
    let config = server(p);
    Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, config, router)
            .await
            .unwrap();
    }))
}
fn write(directory: &Path, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}
fn json_file(directory: &Path, name: &str, value: &Value) -> PathBuf {
    write(directory, name, serde_json::to_vec(value).unwrap())
}
async fn prefix_snapshot(origin: &str, prefix: &str) -> Value {
    reqwest::Client::new().post(format!("{origin}/v3/kv/range")).json(&json!({"key":STANDARD.encode(format!("{prefix}/")),"range_end":STANDARD.encode(format!("{prefix}0"))})).send().await.unwrap().error_for_status().unwrap().json().await.unwrap()
}
async fn restore_prefix(origin: &str, prefix: &str, snapshot: &Value) {
    let mut ops = vec![
        json!({"request_delete_range":{"key":STANDARD.encode(format!("{prefix}/")),"range_end":STANDARD.encode(format!("{prefix}0"))}}),
    ];
    for kv in snapshot["kvs"].as_array().unwrap() {
        ops.push(json!({"request_put":{"key":kv["key"],"value":kv["value"]}}));
    }
    // A stopped logical restore is deliberately staged below etcd's operation
    // bound; no live writer or gate check is allowed between these batches.
    for batch in std::iter::once(&ops[..1]).chain(ops[1..].chunks(64)) {
        let response: Value = reqwest::Client::new()
            .post(format!("{origin}/v3/kv/txn"))
            .json(&json!({"success":batch}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["succeeded"], true);
    }
}
struct IssuanceSnapshot {
    origin: String,
    prefix: String,
    captured: Mutex<Option<Value>>,
}
async fn capture_issue(
    State(p): State<Arc<IssuanceSnapshot>>,
    request: HttpRequest,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let raw = axum::body::to_bytes(body, 2 << 20).await.unwrap();
    let issue = serde_json::from_slice::<Value>(&raw).is_ok_and(|v| v["operation"] == "issue");
    let response = next
        .run(HttpRequest::from_parts(parts, axum::body::Body::from(raw)))
        .await;
    if issue && response.status().is_success() {
        *p.captured.lock().await = Some(prefix_snapshot(&p.origin, &p.prefix).await);
    }
    response
}
async fn run(point: Point) {
    let socket = match std::env::var("KF_POSTGRES_TEST_SOCKET") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_POSTGRES").as_deref(), Ok("1"));
            eprintln!("SKIP SQL failure: PostgreSQL absent");
            return;
        }
    };
    let etcd = match std::env::var("ETCD_ENDPOINT") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
            eprintln!("SKIP SQL failure: etcd absent");
            return;
        }
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !root
        .join("tests/sdk/node_modules/@modelcontextprotocol/client/package.json")
        .is_file()
    {
        assert_ne!(std::env::var("KF_REQUIRE_SDK").as_deref(), Ok("1"));
        eprintln!("SKIP SQL failure: SDK absent");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path();
    let boundary = Arc::new(Boundary::new(point));
    let mut pkis = support::dual_pki_for_workloads(&[
        "spiffe://test/operator",
        "spiffe://test/gateway",
        "spiffe://test/agent",
        "spiffe://test/broker",
        RECOVERY,
        "spiffe://test/sql-target",
        "spiffe://test/collector",
    ]);
    let native = pkis.split_off(3);
    let broker_pki = &native[0];
    let recovery_pki = &native[1];
    let target_pki = &native[2];
    let collector_pki = &native[3];
    let witness = WitnessProcess::start().await;
    let (witness_listener, witness_url) = address().await;
    let witness_prefix = format!("/kf-sql-witness/{:x}", rand::random::<u64>());
    let witness_router = Router::new()
        .route("/v3/kv/txn", post(etcd_relay))
        .with_state(Arc::new(EtcdRelay {
            origin: witness.endpoint.clone(),
            witness: true,
            boundary: boundary.clone(),
        }));
    let _witness_relay = serve(witness_listener, &pkis[1], witness_router).await;
    let gate = RestoreGate::new(
        EtcdLedger::new(client(&pkis[1]), &witness_url, &witness_prefix)
            .unwrap()
            .with_auth_token("witness-role")
            .unwrap(),
    )
    .unwrap();
    let (gateway_reservation, gateway_origin) = address().await;
    let gateway_address = gateway_reservation.local_addr().unwrap();
    let gateway_url = format!("{gateway_origin}/mcp");
    let now = SystemClock.now_ms();
    let Some(h) = Harness::with_environment(
        Some(&gateway_url),
        now,
        |f| {
            f.sql();
            let resource = format!("sql-failure-{:x}", rand::random::<u64>());
            f.proposal["resources"][0]["id"] = json!(resource);
            f.proposal["parameters"]["resource_id"] = json!(resource);
            f.proposal["baseline_state"][0]["resource"]["id"] = json!(resource);
            f.evidence["state_scope"][0]["id"] = json!(resource);
            f.descriptor["adapter_contract"]["guard_scope"] = json!([resource]);
            f.descriptor["concurrency"]["predicate_descriptor"]["clauses"][0]["resource"]["id"] =
                json!(resource);
            f.repin_descriptor();
        },
        Some(gate.clone()),
        Some(pkis),
    )
    .await
    else {
        return;
    };
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    h.clock.0.store(0, Ordering::SeqCst); // Shipping processes and providers use real UTC.
    let database = UnixDatabase {
        socket_directory: socket.into(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    };
    let db = sql_leaf::owner(&database).await;
    let resource = &h.registration.scope.resource;
    db.execute("INSERT INTO kf_reservation.resource(tenant,conflict_domain,resource_id,incarnation,version,last_fence,reservation,active) VALUES($1,$2,$3,$4,241,0,'unreserved',true)",&[&h.f.trust.tenant,&h.registration.scope.conflict_domain,&resource.id,&resource.incarnation]).await.unwrap();
    let store = PostgresStore::new(database.clone()).unwrap();
    let (ledger_listener, ledger_url) = address().await;
    let _ledger_relay = serve(
        ledger_listener,
        &h.gateway_pki,
        Router::new()
            .route("/v3/kv/txn", post(etcd_relay))
            .with_state(Arc::new(EtcdRelay {
                origin: etcd.clone(),
                witness: false,
                boundary: boundary.clone(),
            })),
    )
    .await;
    let (leaf_listener, leaf_origin) = address().await;
    let admit = format!("{leaf_origin}/admit");
    let issue = format!("{leaf_origin}/issue");
    let status = format!("{leaf_origin}/status");
    let (evidence_listener, evidence_origin) = address().await;
    let evidence_url = format!("{evidence_origin}/evidence");
    let (broker_relay_listener, broker_origin) = address().await;
    let broker_url = format!("{broker_origin}/exchange");
    let (broker_reservation, broker_physical) = address().await;
    let broker_address = broker_reservation.local_addr().unwrap();
    let (target_relay_listener, target_origin) = address().await;
    let target_url = format!("{target_origin}/dispatch");
    let query_url = format!("{target_origin}/query");
    let (target_reservation, target_physical) = address().await;
    let target_address = target_reservation.local_addr().unwrap();
    let auth = |url: &str| {
        DualAuthenticator::new(
            &h.f.identity.subject.iss,
            AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    };
    let grants = GrantVerifier {
        keys: keys(5),
        audience: gateway_url.clone(),
    };
    let leaf = Arc::new(
        ControlService::new(
            Arc::new(h.f.trust.clone()),
            AdmissionController::new(
                CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
                "key-6".into(),
                SigningKey::from_bytes(&[6; 32]),
            )
            .unwrap(),
            GrantAuthority::new(
                IssuanceVerifier {
                    tenant: h.f.trust.tenant.clone(),
                    admission_keys: keys(6),
                    grants: grants.clone(),
                },
                "key-5".into(),
                SigningKey::from_bytes(&[5; 32]),
            )
            .unwrap(),
            h.ledger.clone(),
            h.clock.clone(),
            auth(&admit),
            auth(&issue),
            ControlPermissions {
                subjects: vec![h.f.identity.subject.clone()],
                admission_scope: "kf.admit".into(),
                issuance_scope: "kf.issue".into(),
            },
        )
        .unwrap()
        .with_status(auth(&status), "kf.status".into())
        .unwrap(),
    );
    let issuance = Arc::new(IssuanceSnapshot {
        origin: etcd.clone(),
        prefix: h.ledger.namespace().into(),
        captured: Mutex::new(None),
    });
    let leaf_router = leaf.router().layer(middleware::from_fn_with_state(
        issuance.clone(),
        capture_issue,
    ));
    let leaf_task = serve(leaf_listener, &h.agent_pki, leaf_router).await;
    let mut tool = h.tool();
    tool.name = "postgres_reserve".into();
    tool.admission_endpoint = admit.clone();
    let registration = json!({"tenant":h.f.trust.tenant,"conflict_domain":tool.conflict_domain,"action":tool.action,"resource":resource,"adapter_contract":tool.adapter_contract,"predicate_id":tool.predicate_id,"predicate_version":tool.predicate_version,"gateway_workload":"spiffe://test/gateway","query_workload":RECOVERY,"target_audience":target_url,"target_scope":"reservation:write"});
    let mut identity = exchange::Fixture::new();
    identity.snapshot.issuer = h.f.identity.subject.iss.clone();
    identity.snapshot.subject_audience = AUD.into();
    identity.snapshot.actor_audience = broker_url.clone();
    identity.snapshot.not_before = now;
    identity.snapshot.expires_at = now + 120000;
    identity.snapshot.subject_keys[0].kid = "key-7".into();
    identity.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    identity.snapshot.subject_keys[0].not_before = now;
    identity.snapshot.subject_keys[0].expires_at = now + 120000;
    identity.snapshot.actor_keys[0].not_before = now;
    identity.snapshot.actor_keys[0].expires_at = now + 120000;
    identity.snapshot.registrations[0].subject = h.f.identity.subject.clone();
    let scopes = "capacity.reserve kf.admit kf.issue kf.status kf.evidence";
    identity.snapshot.registrations[0].allowed_scopes =
        scopes.split_whitespace().map(String::from).collect();
    let actor = identity.actor_token(
        json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),
        json!({"sub":"spiffe://test/agent","aud":broker_url,"exp":now/1000+120,"iat":now/1000}),
    );
    let ca = write(dir, "ca.pem", &h.gateway_pki.ca);
    let material = |name: &str, p: &support::Pki| {
        (
            write(dir, &format!("{name}.pem"), &p.client),
            write(dir, &format!("{name}.key"), &p.client_key),
        )
    };
    let (gateway_cert, gateway_key) = material("gateway", &h.gateway_pki);
    let (broker_cert, broker_key) = material("broker", broker_pki);
    let (recovery_cert, recovery_key) = material("recovery", recovery_pki);
    let (target_cert, target_key) = material("target", target_pki);
    let target_seed = write(dir, "target.seed", STANDARD.encode([29; 32]));
    let query_token = write(dir, "query.token", QUERY_TOKEN);
    let witness_token = write(dir, "witness.token", "witness-role");
    let restore = |certificate: &PathBuf, private_key: &PathBuf| json!({"endpoint":witness_url,"prefix":witness_prefix,"ca":ca,"certificate":certificate,"private_key":private_key,"token_file":witness_token});
    let public = |n| json!({format!("key-{n}"):STANDARD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let broker_config = json_file(
        dir,
        "broker.json",
        &json!({"listen":broker_address,"external_url":broker_url,"certificate":broker_cert,"private_key":broker_key,"workload_ca":ca,"etcd_endpoint":ledger_url,"etcd_prefix":h.ledger.namespace(),"etcd_ca":ca,"etcd_certificate":broker_cert,"etcd_private_key":broker_key,"etcd_token_file":write(dir,"broker.token","broker-etcd-role"),"gateway_audience":gateway_url,"delegation_audience":AUD,"grant_keys":public(5),"registration":{"gateway_workload":"spiffe://test/gateway","target_audience":target_url,"target_scope":"reservation:write","max_lifetime_ms":4000,"tool":tool},"identity_snapshot_file":write(dir,"identity.json",serde_json::to_vec(&identity.snapshot).unwrap()),"identity_epoch_floor_file":write(dir,"identity.floor","1"),"target_key_id":"key-29","target_signing_key_file":target_seed,"target_verification_keys":public(29),"allow_unmanaged_fixture":false,"installed_trust_digest":h.registration.trust_digest,"restore_gate":restore(&broker_cert,&broker_key)}),
    );
    let target_config = json_file(
        dir,
        "target.json",
        &json!({"listen":target_address,"dispatch_url":target_url,"query_url":query_url,"certificate":target_cert,"private_key":target_key,"workload_ca":ca,"database":database,"gateway_audience":gateway_url,"grant_keys":public(5),"token_issuer":broker_url,"target_keys":public(29),"query_token_file":query_token,"registration":registration}),
    );
    let gateway_config = json_file(
        dir,
        "gateway.json",
        &json!({"listen":gateway_address,"external_url":gateway_url,"delegation_audience":AUD,"certificate":gateway_cert,"private_key":gateway_key,"workload_ca":ca,"grant_key_id":"key-5","grant_public_key_base64":public(5)["key-5"],"oidc_issuer":h.f.identity.subject.iss,"oidc_public_key_base64":public(7)["key-7"],"etcd_endpoints":[ledger_url],"etcd_prefix":h.ledger.namespace(),"etcd_ca":ca,"etcd_token_file":write(dir,"gateway.token","gateway-etcd-role"),"require_control":true,"restore_gate":restore(&gateway_cert,&gateway_key),"broker_endpoint":broker_url,"broker_ca":ca,"target_audience":target_url,"target_scope":"reservation:write","actor_workload":"spiffe://test/agent","actor_token_file":write(dir,"actor.jwt",actor),"target_url":target_url,"target_ca":ca,"tools":[tool],"postgres_adapter":{"profile":kedgeflow::leaf_action::PROFILE,"registration":registration,"token_issuer":broker_url,"target_keys":public(29)}}),
    );
    let recovery_config = json!({"etcd_endpoint":ledger_url,"etcd_prefix":h.ledger.namespace(),"etcd_ca":ca,"etcd_certificate":recovery_cert,"etcd_private_key":recovery_key,"etcd_token_file":write(dir,"recovery.token","recovery-etcd-role"),"restore_gate":restore(&recovery_cert,&recovery_key),"gateway_audience":gateway_url,"grant_keys":public(5),"query_url":query_url,"query_ca":ca,"query_certificate":recovery_cert,"query_private_key":recovery_key,"query_token_file":query_token,"receipt_key_id":"key-30","receipt_signing_key_file":write(dir,"outcome.seed",STANDARD.encode([30;32])),"source_id":RECOVERY,"page_size":1,"poll_interval_ms":100});
    let recovery_file = json_file(dir, "recovery.json", &recovery_config);
    let broker_relay = Arc::new(ServiceRelay {
        upstream: broker_physical,
        public: broker_origin,
        client: client(&h.gateway_pki),
        boundary: boundary.clone(),
        broker: true,
    });
    let _broker_relay = serve(
        broker_relay_listener,
        &h.gateway_pki,
        Router::new()
            .route("/exchange", post(service_relay))
            .with_state(broker_relay),
    )
    .await;
    let target_relay = Arc::new(ServiceRelay {
        upstream: target_physical,
        public: target_origin,
        client: client(recovery_pki),
        boundary: boundary.clone(),
        broker: false,
    });
    // Dispatch forwarding uses the enrolled gateway certificate; query forwarding
    // uses the distinct recovery certificate. No workload headers substitute TLS.
    let dispatch_relay = Arc::new(ServiceRelay {
        upstream: target_relay.upstream.clone(),
        public: target_relay.public.clone(),
        client: client(&h.gateway_pki),
        boundary: boundary.clone(),
        broker: false,
    });
    let target_router = Router::new()
        .route("/dispatch", post(service_relay).with_state(dispatch_relay))
        .route("/query", post(service_relay).with_state(target_relay));
    let _target_relay = serve(target_relay_listener, &h.gateway_pki, target_router).await;
    let provider = Arc::new(Provider {
        auth: auth(&evidence_url),
        clock: h.clock.clone(),
        evidence: h.f.evidence.clone(),
        policy: h.f.trust.policy.clone(),
        descriptor_digest: h.f.trust.descriptor_digest.clone(),
        calls: AtomicUsize::new(0),
        baseline_calls: AtomicUsize::new(0),
        target: Arc::new(Target {
            calls: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            state: Mutex::new((241, 0, 3)),
        }),
        resource: resource.clone(),
    });
    let _provider = serve(
        evidence_listener,
        &h.agent_pki,
        Router::new()
            .route("/evidence", post(live_agent::evidence))
            .with_state(provider.clone()),
    )
    .await;
    drop(broker_reservation);
    let mut broker = Native::start(
        env!("CARGO_BIN_EXE_kf-broker"),
        broker_config,
        broker_address,
    )
    .await;
    drop(target_reservation);
    let mut target = Native::start(
        env!("CARGO_BIN_EXE_kf-postgres-target"),
        target_config,
        target_address,
    )
    .await;
    drop(gateway_reservation);
    let mut gateway = Native::start(
        env!("CARGO_BIN_EXE_kf-proxy"),
        gateway_config,
        gateway_address,
    )
    .await;
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
    let token = |scope: &str| {
        let time = SystemClock.now_ms();
        jwt(
            json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
            json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":time/1000+120,"iat":time/1000,"scope":scope,"cnf":{"jkt":jkt}}),
            7,
        )
    };
    let url_public = |n| json!({format!("key-{n}"):URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let mut agent = json!({"mode":"normal","realtime":true,"executeOnly":true,"token":token(scopes),"storeDirectory":dir.join("operations"),"evidenceUrl":evidence_url,"tls":{"ca":h.agent_pki.ca,"cert":h.agent_pki.client,"key":h.agent_pki.client_key},"proposalTemplate":h.f.proposal,"config":{"gatewayUrl":gateway_url,"admissionUrl":admit,"issuanceUrl":issue,"statusUrl":status,"delegationAudience":AUD,"workloadId":"spiffe://test/agent","subject":h.f.identity.subject,"tenant":h.f.trust.tenant,"toolName":tool.name,"descriptor":String::from_utf8(fixture::signed("ctd",h.f.descriptor.clone(),2)).unwrap(),"descriptorDigest":h.f.trust.descriptor_digest,"registryKeys":url_public(2),"proposalKeys":url_public(1),"manifestKeys":url_public(3),"evidenceKeys":url_public(4),"admissionKeys":url_public(6),"issuerKeys":url_public(5),"proposalKeyId":"key-1","authorizationKey":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes())}});
    let agent_file = json_file(dir, "agent.json", &agent);
    let mut locker = sql_leaf::owner(&database).await;
    let lock = if point == Point::TargetLock {
        let transaction = locker.transaction().await.unwrap();
        transaction.query_one("SELECT version FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2 FOR UPDATE",&[&h.f.trust.tenant,&resource.id]).await.unwrap();
        Some(transaction)
    } else {
        None
    };
    let node = tokio::process::Command::new("node")
        .arg(root.join("tests/sdk/live-agent.mjs"))
        .arg(&agent_file)
        .kill_on_drop(true)
        .output();
    tokio::pin!(node);
    tokio::select! {_=boundary.reached()=>(),result=&mut node=>panic!("Node ended before barrier: {:?}",result.map(|o|String::from_utf8_lossy(&o.stderr).into_owned()))}
    match point {
        Point::TargetLock => {
            for step in 0..200 {
                let count:i64=db.query_one("SELECT count(*) FROM pg_stat_activity WHERE usename='kf_executor' AND wait_event_type='Lock'",&[]).await.unwrap().get(0);
                if count == 1 {
                    break;
                }
                assert!(
                    step < 199,
                    "native SQL transaction did not reach real row lock"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            target.kill().await;
            // A backend blocked on a row lock detects the dead Unix-socket
            // client after waking. The explicit transaction then rolls back.
            lock.unwrap().rollback().await.unwrap();
            for step in 0..200 {
                let count: i64 = db
                    .query_one(
                        "SELECT count(*) FROM pg_stat_activity WHERE usename='kf_executor'",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if count == 0 {
                    break;
                }
                assert!(step < 199);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            target.restart().await;
        }
        Point::TargetCommit => {
            target.kill().await;
            boundary.release.notify_one();
            target.restart().await;
        }
        Point::BrokerMint => {
            broker.kill().await;
            boundary.release.notify_one();
            broker.restart().await;
        }
        _ => {
            gateway.kill().await;
        }
    }
    let output = tokio::time::timeout(Duration::from_secs(20), &mut node)
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let first: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(first["status"], "PASS");
    let retained: Value = serde_json::from_slice(
        &std::fs::read(dir.join("operations").join(format!(
            "{}.json",
            hex::encode(Sha256::digest(b"sdk:live-operation"))
        )))
        .unwrap(),
    )
    .unwrap();
    let original = grants
        .verify_retained(retained["grant"].as_str().unwrap().as_bytes())
        .unwrap();
    let candidate = if point == Point::PendingWitness {
        let snapshot = prefix_snapshot(&etcd, h.ledger.namespace()).await;
        let id = snapshot["kvs"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|kv| {
                let key = String::from_utf8(STANDARD.decode(kv["key"].as_str().unwrap()).unwrap())
                    .unwrap();
                if key.contains("/attempts/") {
                    serde_json::from_slice::<Value>(
                        &STANDARD.decode(kv["value"].as_str().unwrap()).unwrap(),
                    )
                    .ok()
                    .and_then(|v| v["id"].as_str().map(String::from))
                } else {
                    None
                }
            })
            .unwrap();
        Candidate {
            grant: original.grant.clone(),
            attempt_id: id,
        }
    } else {
        let status = h
            .ledger
            .execution_status(&original.grant, &original.digest)
            .await
            .unwrap();
        Candidate {
            grant: original.grant.clone(),
            attempt_id: status.attempt_id.unwrap(),
        }
    };
    qualify_tail(
        point,
        &h,
        &candidate,
        &original.digest,
        &store,
        &db,
        &gate,
        &etcd,
        &issuance,
        &boundary,
        &recovery_file,
        &recovery_config,
        &mut gateway,
        &mut broker,
        &mut target,
        &agent_file,
        &mut agent,
        dir,
        recovery_pki,
        collector_pki,
        leaf_task,
    )
    .await;
}
async fn once(binary: &str, file: &Path) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(binary)
            .args(["--config", file.to_str().unwrap(), "--once"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}
fn sweep(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["unavailable"], 0);
    result
}
#[allow(clippy::too_many_arguments)]
async fn qualify_tail(
    point: Point,
    h: &Harness,
    c: &Candidate,
    gd: &str,
    store: &PostgresStore,
    db: &tokio_postgres::Client,
    gate: &RestoreGate,
    etcd: &str,
    issuance: &IssuanceSnapshot,
    b: &Boundary,
    recovery_file: &Path,
    recovery_config: &Value,
    gateway: &mut Native,
    broker: &mut Native,
    target: &mut Native,
    agent_file: &Path,
    agent: &mut Value,
    dir: &Path,
    recovery_pki: &support::Pki,
    collector_pki: &support::Pki,
    leaf_task: Running,
) {
    let before = store
        .lookup(&h.f.trust.tenant, &c.attempt_id)
        .await
        .unwrap();
    assert_eq!(before.is_some(), point.sql_committed());
    if let Some(outcome) = &before {
        assert_eq!(outcome.request.grant_digest, gd);
        assert_eq!(outcome.request.root_id, c.grant.root_id);
        assert_eq!(outcome.request.fence, c.grant.fence);
        assert_eq!(outcome.post_version, Some(242));
    }
    let row=db.query_one("SELECT version,last_fence,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.f.trust.tenant,&c.grant.resources[0].id]).await.unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        if point.sql_committed() { 242 } else { 241 }
    );
    assert_eq!(
        row.get::<_, i64>(1),
        if point.sql_committed() {
            c.grant.fence as i64
        } else {
            0
        }
    );
    assert_eq!(
        row.get::<_, String>(2),
        if point.sql_committed() {
            "booking:pilot"
        } else {
            "unreserved"
        }
    );
    assert_eq!(b.claims.load(Ordering::SeqCst), 1);
    assert_eq!(
        b.broker_calls.load(Ordering::SeqCst),
        usize::from(point != Point::PendingWitness)
    );
    assert_eq!(b.permits.load(Ordering::SeqCst), point.broker_count());
    assert_eq!(
        b.broker_forwards.load(Ordering::SeqCst),
        point.broker_count()
    );
    assert_eq!(
        b.broker_replies.load(Ordering::SeqCst),
        point.broker_count()
    );
    assert_eq!(
        b.authorizations.load(Ordering::SeqCst),
        point.dispatch_count()
    );
    assert_eq!(
        b.target_calls.load(Ordering::SeqCst),
        point.dispatch_count()
    );
    assert_eq!(
        b.target_forwards.load(Ordering::SeqCst),
        usize::from(matches!(
            point,
            Point::Commit
                | Point::TargetLock
                | Point::TargetCommit
                | Point::Restore
                | Point::Incident
                | Point::RecoveryReceipt
        ))
    );
    let expected = if point.sql_committed() {
        "committed"
    } else if matches!(point, Point::Claim | Point::Mint | Point::BrokerMint) {
        "not_dispatched"
    } else {
        "unknown"
    };
    if point == Point::PendingWitness {
        assert!(gate.check(&h.ledger).await.is_err());
        let output = once(env!("CARGO_BIN_EXE_kf-recover"), recovery_file).await;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("quarantine"));
        assert!(
            h.ledger
                .claim(&c.grant, gd, "forbidden-replacement")
                .await
                .is_err()
        );
        let unguarded =
            EtcdLedger::new(reqwest::Client::new(), etcd, h.ledger.namespace()).unwrap();
        assert!(matches!(
            unguarded.claim(&c.grant, gd, "gate-removed").await,
            Err(Error::Refused(_))
        ));
        assert!(
            store
                .lookup(&h.f.trust.tenant, &c.attempt_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(b.queries.load(Ordering::SeqCst), 0);
        println!(
            "SQL failure PASS: PendingWitness; local claim retained, witness pending, recovery/removal bypass refused, no mint or SQL effect"
        );
    } else if point == Point::Incident {
        incident_case(
            h,
            c,
            gd,
            b,
            recovery_config,
            dir,
            recovery_pki,
            collector_pki,
        )
        .await;
    } else {
        let wait = c.grant.expires_at - SystemClock.now_ms() + 5;
        if wait > 0 {
            tokio::time::sleep(Duration::from_millis(wait as u64)).await;
        }
        if point == Point::RecoveryReceipt {
            let mut worker = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-recover"))
                .args(["--config", recovery_file.to_str().unwrap(), "--once"])
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(dir.join("worker.stderr")).unwrap())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            tokio::select! {
                result=tokio::time::timeout(Duration::from_secs(12),b.receipt_entered.notified())=>result.expect("witnessed SQL receipt barrier"),
                status=worker.wait()=>panic!("worker ended before receipt: {status:?}: {}",std::fs::read_to_string(dir.join("worker.stderr")).unwrap()),
            }
            worker.start_kill().unwrap();
            assert_eq!(worker.wait().await.unwrap().signal(), Some(9));
            gate.check(&h.ledger).await.unwrap();
            assert_eq!(h.ledger.export_outcomes(c).await.unwrap().receipts.len(), 1);
            println!(
                "SQL recovery PASS: native worker killed after witnessed receipt retention before reply; restart retains original receipt"
            );
        }
        let first = sweep(once(env!("CARGO_BIN_EXE_kf-recover"), recovery_file).await);
        assert_eq!(first["reported"], 1);
        let head = h.ledger.export_outcomes(c).await.unwrap();
        assert_eq!(head.receipts.len(), 1);
        assert_eq!(
            h.ledger.execution_status(&c.grant, gd).await.unwrap().state,
            expected
        );
        sweep(once(env!("CARGO_BIN_EXE_kf-recover"), recovery_file).await);
        assert_eq!(
            h.ledger.export_outcomes(c).await.unwrap().receipts,
            head.receipts
        );
        assert!(matches!(
            h.ledger.claim(&c.grant, gd, "forbidden-replacement").await,
            Err(Error::NonceConsumed)
        ));
        if point == Point::Restore {
            restore_case(
                h,
                c,
                gd,
                gate,
                etcd,
                issuance,
                b,
                recovery_file,
                gateway,
                broker,
                &head,
                leaf_task,
            )
            .await;
        }
        println!(
            "SQL failure PASS: {point:?}; original attempt={}, outcome={expected}, claim=1, permits={}, dispatches={}, SQL effects={}",
            c.attempt_id,
            point.broker_count(),
            b.target_forwards.load(Ordering::SeqCst),
            usize::from(point.sql_committed())
        );
    }
    if !matches!(
        point,
        Point::TargetLock
            | Point::TargetCommit
            | Point::BrokerMint
            | Point::PendingWitness
            | Point::Restore
    ) {
        gateway.restart().await;
    }
    if point != Point::PendingWitness {
        agent["executeOnly"] = json!(false);
        agent["mode"] = json!("resume");
        agent["expectedState"] = json!(expected);
        let time = SystemClock.now_ms();
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
        agent["token"] = json!(jwt(
            json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
            json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":time/1000+120,"iat":time/1000,"scope":"kf.status","cnf":{"jkt":jkt}}),
            7
        ));
        std::fs::write(agent_file, serde_json::to_vec(agent).unwrap()).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = tokio::time::timeout(
            Duration::from_secs(20),
            tokio::process::Command::new("node")
                .arg(root.join("tests/sdk/live-agent.mjs"))
                .arg(agent_file)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let status: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(status["attempt_id"], c.attempt_id);
        assert_eq!(status["grant_digest"], gd);
        assert_eq!(b.claims.load(Ordering::SeqCst), 1);
        assert_eq!(b.permits.load(Ordering::SeqCst), point.broker_count());
        assert_eq!(
            b.target_calls.load(Ordering::SeqCst),
            point.dispatch_count()
        );
        gate.check(&h.ledger).await.unwrap();
        gateway.kill().await;
    }
    assert_eq!(
        store
            .lookup(&h.f.trust.tenant, &c.attempt_id)
            .await
            .unwrap(),
        before
    );
    let final_row=db.query_one("SELECT version,last_fence,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.f.trust.tenant,&c.grant.resources[0].id]).await.unwrap();
    assert_eq!(final_row.get::<_, i64>(0), row.get::<_, i64>(0));
    assert_eq!(final_row.get::<_, i64>(1), row.get::<_, i64>(1));
    assert_eq!(final_row.get::<_, String>(2), row.get::<_, String>(2));
    broker.kill().await;
    target.kill().await;
}
#[allow(clippy::too_many_arguments)]
async fn restore_case(
    h: &Harness,
    c: &Candidate,
    gd: &str,
    gate: &RestoreGate,
    etcd: &str,
    issuance: &IssuanceSnapshot,
    b: &Boundary,
    recovery_file: &Path,
    gateway: &mut Native,
    broker: &mut Native,
    head: &kedgeflow::recovery::OutcomeBundle,
    mut leaf_task: Running,
) {
    let latest = prefix_snapshot(etcd, h.ledger.namespace()).await;
    let old = issuance
        .captured
        .lock()
        .await
        .clone()
        .expect("preclaim issuance snapshot");
    assert_ne!(old["kvs"], latest["kvs"]);
    broker.kill().await;
    leaf_task.0.abort();
    let _ = (&mut leaf_task.0).await;
    // All fixture writers are stopped. Only this privileged test-owned logical
    // prefix copy is rolled back; SQL and the independent witness are retained.
    restore_prefix(etcd, h.ledger.namespace(), &old).await;
    assert!(gate.check(&h.ledger).await.is_err());
    let refused = once(env!("CARGO_BIN_EXE_kf-recover"), recovery_file).await;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("quarantine"));
    assert!(
        h.ledger
            .claim(&c.grant, gd, "stale-replacement")
            .await
            .is_err()
    );
    let config: Value = serde_json::from_slice(&std::fs::read(recovery_file).unwrap()).unwrap();
    let transport = tls::pinned_http_client_pem(
        &std::fs::read(config["query_ca"].as_str().unwrap()).unwrap(),
        &std::fs::read(config["query_certificate"].as_str().unwrap()).unwrap(),
        &std::fs::read(config["query_private_key"].as_str().unwrap()).unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
    let query = HttpOutcomeQuerier::new(
        transport,
        config["query_url"].as_str().unwrap(),
        QUERY_TOKEN.into(),
    )
    .unwrap();
    let retained = query.query(&c.attempt_id).await.unwrap();
    assert_eq!(retained.status, "committed");
    assert_eq!(retained.grant_digest, gd);
    assert_eq!(retained.root_id, c.grant.root_id);
    assert_eq!(b.target_calls.load(Ordering::SeqCst), 1);
    restore_prefix(etcd, h.ledger.namespace(), &latest).await;
    gate.check(&h.ledger).await.unwrap();
    sweep(once(env!("CARGO_BIN_EXE_kf-recover"), recovery_file).await);
    assert_eq!(
        h.ledger.export_outcomes(c).await.unwrap().receipts,
        head.receipts
    );
    assert_eq!(
        h.ledger.execution_status(&c.grant, gd).await.unwrap().state,
        "committed"
    );
    assert!(matches!(
        h.ledger.claim(&c.grant, gd, "restored-replacement").await,
        Err(Error::NonceConsumed)
    ));
    broker.restart().await;
    gateway.restart().await;
    println!(
        "SQL restore PASS: stopped preclaim logical prefix refused; independent target retained original commit; exact latest copy recovered original receipt and consumed nonce"
    );
}
struct CollectorBoundary {
    reports: AtomicUsize,
    lookups: AtomicUsize,
    block: AtomicBool,
    entered: Notify,
}
async fn collector_boundary(
    State(b): State<Arc<CollectorBoundary>>,
    request: HttpRequest,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let raw = axum::body::to_bytes(body, 2 << 20).await.unwrap();
    let value: Value = serde_json::from_slice(&raw).unwrap();
    let report = value["operation"] == "report";
    if report {
        b.reports.fetch_add(1, Ordering::SeqCst);
    } else {
        b.lookups.fetch_add(1, Ordering::SeqCst);
    }
    let response = next
        .run(HttpRequest::from_parts(parts, axum::body::Body::from(raw)))
        .await;
    if report && response.status().is_success() && b.block.swap(false, Ordering::SeqCst) {
        b.entered.notify_one();
        std::future::pending::<()>().await;
    }
    response
}
async fn progress(h: &Harness) -> Vec<kedgeflow::supervision::DeliveryProgress> {
    let snapshot = prefix_snapshot(
        &std::env::var("ETCD_ENDPOINT").unwrap(),
        h.ledger.namespace(),
    )
    .await;
    snapshot["kvs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|kv| {
            let key = String::from_utf8(STANDARD.decode(kv["key"].as_str()?).ok()?).ok()?;
            if !key.contains("/delivery-progress/") {
                return None;
            }
            Some(serde_json::from_slice(&STANDARD.decode(kv["value"].as_str()?).unwrap()).unwrap())
        })
        .collect()
}
#[allow(clippy::too_many_arguments)]
async fn incident_case(
    h: &Harness,
    c: &Candidate,
    gd: &str,
    b: &Boundary,
    recovery_config: &Value,
    dir: &Path,
    recovery_pki: &support::Pki,
    collector_pki: &support::Pki,
) {
    let (listener, origin) = address().await;
    let url = format!("{origin}/outcomes");
    let subject = kedgeflow::contracts::Subject {
        iss: "https://report-identity.test".into(),
        sub: "sql-supervisor".into(),
    };
    let trust = ReporterTrust {
        tenant: h.f.trust.tenant.clone(),
        conflict_domain: c.grant.conflict_domain.clone(),
        source_id: RECOVERY.into(),
        subject: subject.clone(),
        required_scope: "kf.outcome-report".into(),
        grants: GrantVerifier {
            keys: keys(5),
            audience: c.grant.audience.clone(),
        },
        outcome_keys: keys(30),
    };
    // The draft native collector looks up retained source receipts in the
    // shared fixture ledger. Its keys/subject/peer stay separate; this does not
    // qualify an independent enterprise collector store or access deployment.
    let collector = h.ledger.clone();
    let service = Arc::new(
        OutcomeReportService::new(
            trust,
            collector,
            DualAuthenticator::new(
                &subject.iss,
                REPORT_AUD,
                &url,
                SigningKey::from_bytes(&[37; 32]).verifying_key().to_bytes(),
            )
            .unwrap(),
            "sql-fixture-collector".into(),
            "key-31".into(),
            SigningKey::from_bytes(&[31; 32]),
            Arc::new(SystemClock),
        )
        .unwrap(),
    );
    let network = Arc::new(CollectorBoundary {
        reports: AtomicUsize::new(0),
        lookups: AtomicUsize::new(0),
        block: AtomicBool::new(true),
        entered: Notify::new(),
    });
    let _collector = serve(
        listener,
        collector_pki,
        service.router().layer(middleware::from_fn_with_state(
            network.clone(),
            collector_boundary,
        )),
    )
    .await;
    let proof = SigningKey::from_bytes(&[36; 32]);
    let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(proof.verifying_key().as_bytes())});
    let time = SystemClock.now_ms();
    let token = jwt(
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-37"}),
        json!({"iss":subject.iss,"sub":subject.sub,"aud":REPORT_AUD,"exp":time/1000+120,"iat":time/1000,"scope":"kf.outcome-report","cnf":{"jkt":URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()))}}),
        37,
    );
    let config = json_file(
        dir,
        "supervision.json",
        &json!({"recovery":recovery_config,"delivery":{"collector_id":"sql-fixture-collector","collector_url":url,"collector_ca":write(dir,"report-ca.pem",&recovery_pki.ca),"certificate":write(dir,"report-cert.pem",&recovery_pki.client),"private_key":write(dir,"report-key.pem",&recovery_pki.client_key),"token_file":write(dir,"report.jwt",token),"dpop_signing_key_file":write(dir,"report.seed",STANDARD.encode([36;32])),"tenant":h.f.trust.tenant,"conflict_domain":c.grant.conflict_domain,"reporter_subject":subject,"report_scope":"kf.outcome-report","outcome_keys":{"key-30":STANDARD.encode(SigningKey::from_bytes(&[30;32]).verifying_key().as_bytes())},"acknowledgement_keys":{"key-31":STANDARD.encode(SigningKey::from_bytes(&[31;32]).verifying_key().as_bytes())}},"incident_policy":{"owner_id":"team:fixture-sql-sre","unknown_after_ms":1000},"receipt_budget":2}),
    );
    let wait = c.grant.expires_at - SystemClock.now_ms() + 5;
    if wait > 0 {
        tokio::time::sleep(Duration::from_millis(wait as u64)).await;
    }
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-supervise"))
        .args(["--config", config.to_str().unwrap(), "--once"])
        .stdout(std::fs::File::create(dir.join("supervisor.stdout")).unwrap())
        .stderr(std::fs::File::create(dir.join("supervisor.stderr")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(12),network.entered.notified())=>result.expect("collector acceptance barrier"),
        result=child.wait()=>panic!("supervisor ended before collector acceptance: {result:?}: {}; stdout={}; reports={} lookups={} incident={:?} bundle={:?}",std::fs::read_to_string(dir.join("supervisor.stderr")).unwrap(),std::fs::read_to_string(dir.join("supervisor.stdout")).unwrap(),network.reports.load(Ordering::SeqCst),network.lookups.load(Ordering::SeqCst),h.ledger.supervision_incident(c).await,h.ledger.export_outcomes(c).await.map(|v|v.receipts.len())),
    }
    let opened = h.ledger.supervision_incident(c).await.unwrap().unwrap();
    assert_eq!(opened.state, "open");
    assert_eq!(opened.owner_id, "team:fixture-sql-sre");
    assert_eq!(opened.grant_digest, gd);
    assert_eq!(opened.attempt_id, c.attempt_id);
    let unknown = h.ledger.export_outcomes(c).await.unwrap();
    assert_eq!(unknown.receipts.len(), 1);
    assert!(progress(h).await.is_empty());
    child.start_kill().unwrap();
    assert_eq!(child.wait().await.unwrap().signal(), Some(9));
    let wait = opened.deadline - SystemClock.now_ms() + 5;
    if wait > 0 {
        tokio::time::sleep(Duration::from_millis(wait as u64)).await;
    }
    let restarted = sweep(once(env!("CARGO_BIN_EXE_kf-supervise"), &config).await);
    assert_eq!(restarted["incidents_escalated"], 1);
    assert_eq!(restarted["delivered"], 1);
    let escalated = h.ledger.supervision_incident(c).await.unwrap().unwrap();
    assert_eq!(escalated.state, "escalated");
    assert_eq!(escalated.incident_id, opened.incident_id);
    assert_eq!(escalated.deadline, opened.deadline);
    assert_eq!(
        h.ledger.export_outcomes(c).await.unwrap().receipts,
        unknown.receipts
    );
    assert_eq!(network.reports.load(Ordering::SeqCst), 1);
    let first = progress(h).await;
    assert_eq!(first.len(), 1);
    b.unavailable_query.store(false, Ordering::SeqCst);
    let resolved = sweep(once(env!("CARGO_BIN_EXE_kf-supervise"), &config).await);
    assert_eq!(resolved["incidents_resolved"], 1);
    assert_eq!(resolved["delivered"], 1);
    let incident = h.ledger.supervision_incident(c).await.unwrap().unwrap();
    assert_eq!(incident.state, "resolved");
    assert_eq!(incident.incident_id, opened.incident_id);
    let bundle = h.ledger.export_outcomes(c).await.unwrap();
    assert_eq!(bundle.receipts.len(), 2);
    assert_eq!(bundle.receipts[0], unknown.receipts[0]);
    let delivered = progress(h).await;
    assert_eq!(delivered.len(), 2);
    assert!(
        delivered
            .iter()
            .any(|p| p.acknowledgement == first[0].acknowledgement)
    );
    for (index, raw) in bundle.receipts.iter().enumerate() {
        let envelope: kedgeflow::contracts::Envelope = serde_json::from_str(raw).unwrap();
        let receipt_digest = kedgeflow::contracts::record_digest(&envelope).unwrap();
        let retained = delivered
            .iter()
            .find(|p| p.receipt_digest == receipt_digest)
            .unwrap();
        let expected=kedgeflow::outcome_report::Acknowledgement {
            report_id:kedgeflow::contracts::digest("outcome-delivery",&json!({"collector_id":"sql-fixture-collector","collector_url":url,"tenant":h.f.trust.tenant,"grant_digest":gd,"attempt_id":c.attempt_id,"receipt_digest":receipt_digest})).unwrap(),
            tenant:h.f.trust.tenant.clone(),grant_digest:gd.into(),attempt_id:c.attempt_id.clone(),receipt_digest,evidence_digest:envelope.payload["resolution_evidence"][0]["digest"].as_str().unwrap().into(),source_id:RECOVERY.into(),collector_id:"sql-fixture-collector".into(),collector_url:url.clone(),previous_receipt_digest:if index==0 {None}else{Some(first[0].receipt_digest.clone())},accepted_at:0,
        };
        kedgeflow::outcome_report::verify_ack(&retained.acknowledgement, &keys(31), &expected)
            .unwrap();
    }
    let stable = sweep(once(env!("CARGO_BIN_EXE_kf-supervise"), &config).await);
    assert_eq!(stable["delivered"], 0);
    assert_eq!(network.reports.load(Ordering::SeqCst), 2);
    assert!(network.lookups.load(Ordering::SeqCst) >= 3);
    assert!(matches!(
        h.ledger.claim(&c.grant, gd, "incident-replacement").await,
        Err(Error::NonceConsumed)
    ));
    assert_eq!(b.claims.load(Ordering::SeqCst), 1);
    assert_eq!(b.broker_replies.load(Ordering::SeqCst), 1);
    assert_eq!(b.target_calls.load(Ordering::SeqCst), 1);
    println!(
        "SQL incident PASS: native supervisor killed after collector acceptance; query outage escalated same owned incident; lookup retained signed ACK, later SQL commit resolved with ordered linked ACK and no remint/resend"
    );
}
#[tokio::test]
async fn shipping_gateway_killed_after_witnessed_claim_resolves_without_exchange() {
    run(Point::Claim).await;
}
#[tokio::test]
async fn shipping_gateway_killed_after_native_mint_seals_without_sql_resend() {
    run(Point::Mint).await;
}
#[tokio::test]
async fn shipping_gateway_killed_after_authorization_keeps_absent_sql_unknown() {
    run(Point::Authorized).await;
}
#[tokio::test]
async fn shipping_gateway_killed_after_sql_commit_recovers_original_outcome() {
    run(Point::Commit).await;
}
#[tokio::test]
async fn shipping_target_killed_during_real_sql_lock_keeps_rollback_unknown() {
    run(Point::TargetLock).await;
}
#[tokio::test]
async fn shipping_target_killed_after_commit_preserves_outcome_before_delivery() {
    run(Point::TargetCommit).await;
}
#[tokio::test]
async fn shipping_broker_killed_after_mint_preserves_original_permit() {
    run(Point::BrokerMint).await;
}
#[tokio::test]
async fn interrupted_witness_finalization_quarantines_consumed_sql_claim() {
    run(Point::PendingWitness).await;
}
#[tokio::test]
async fn fresh_sql_stale_logical_restore_cannot_reopen_consumed_authority() {
    run(Point::Restore).await;
}
#[tokio::test]
async fn shipping_supervisor_kill_preserves_sql_incident_and_collector_acknowledgement() {
    run(Point::Incident).await;
}

#[tokio::test]
async fn shipping_recovery_killed_after_witnessed_sql_receipt_preserves_original_chain() {
    run(Point::RecoveryReceipt).await;
}
