//! Native collector/ledger + shipping supervisor fault qualification. All keys,
//! identities and query observations are software fixtures; no external paging.
#[path = "support/domain.rs"]
mod domain;
mod support;
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    auth::{DualAuthenticator, WorkloadIdentity},
    clock::Clock,
    contracts::{GrantVerifier, Subject, canonical, sign_grant},
    error::Result,
    ledger::{AuthoritativeObservation, AuthorityLedger, EtcdLedger, OutcomeQuerier},
    outcome_report_client::{CollectorTrust, OutcomeReportClient},
    outcome_report_service::{OutcomeReportService, ReporterTrust},
    recovery::{Candidate, ExecutionRecord, RecoveryWorker, verify_outcomes},
    supervision::{DeliveryProgress, IncidentPolicy, OutcomeSupervisor},
    tls,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
const SOURCE: &str = "spiffe://test/outcome";
const AUD: &str = "urn:kedgeflow:supervision-test";
struct Time(AtomicI64);
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn keys(id: &str, seed: u8) -> BTreeMap<String, ed25519_dalek::VerifyingKey> {
    BTreeMap::from([(
        id.into(),
        SigningKey::from_bytes(&[seed; 32]).verifying_key(),
    )])
}
fn jwt(header: Value, claims: Value, seed: u8) -> String {
    let m = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(canonical(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(canonical(&claims).unwrap())
    );
    format!(
        "{m}.{}",
        URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[seed; 32])
                .sign(m.as_bytes())
                .to_bytes()
        )
    )
}
struct Query {
    c: Candidate,
    gd: String,
    mode: AtomicUsize,
    calls: AtomicUsize,
}
#[async_trait]
impl OutcomeQuerier for Query {
    async fn query(&self, id: &str) -> Result<AuthoritativeObservation> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        Ok(AuthoritativeObservation {
            attempt_id: id.into(),
            root_id: self.c.grant.root_id.clone(),
            grant_digest: self.gd.clone(),
            status: if mode != 1 { "pending" } else { "committed" }.into(),
            target_reference: if mode == 2 {
                format!("software:supervised:observation-{call}")
            } else {
                "software:supervised:original".into()
            },
        })
    }
}
async fn query_route(
    State(q): State<Arc<Query>>,
    Extension(w): Extension<WorkloadIdentity>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Json<AuthoritativeObservation> {
    assert_eq!(w.as_str(), SOURCE);
    assert_eq!(h["authorization"], "Bearer query-role");
    Json(q.query(v["attempt_id"].as_str().unwrap()).await.unwrap())
}
struct Network {
    reports: AtomicUsize,
    lookups: AtomicUsize,
    drop_reply: AtomicBool,
    invalid_reply: AtomicBool,
    block: AtomicBool,
    entered: Notify,
}
async fn collector_fault(State(n): State<Arc<Network>>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let raw = axum::body::to_bytes(body, 2 << 20).await.unwrap();
    let v: Value = serde_json::from_slice(&raw).unwrap();
    let report = v["operation"] == "report";
    if report {
        n.reports.fetch_add(1, Ordering::SeqCst);
    } else {
        n.lookups.fetch_add(1, Ordering::SeqCst);
    }
    let response = next
        .run(Request::from_parts(parts, axum::body::Body::from(raw)))
        .await;
    if report && response.status().is_success() {
        if n.block.swap(false, Ordering::SeqCst) {
            n.entered.notify_one();
            std::future::pending::<()>().await;
        }
        if n.drop_reply.swap(false, Ordering::SeqCst) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "test-owned lost accepted reply",
            )
                .into_response();
        }
        if n.invalid_reply.swap(false, Ordering::SeqCst) {
            let (parts, body) = response.into_parts();
            let raw = axum::body::to_bytes(body, 1 << 20).await.unwrap();
            let mut v: Value = serde_json::from_slice(&raw).unwrap();
            v["acknowledgement"] = json!("invalid-test-signature");
            return Response::from_parts(
                parts,
                axum::body::Body::from(serde_json::to_vec(&v).unwrap()),
            );
        }
    }
    response
}
struct LedgerProxy {
    endpoint: String,
    drop_progress: AtomicBool,
    pause_incident: AtomicBool,
    incident_entered: Notify,
    incident_release: Notify,
}
fn contains_progress(v: &Value) -> bool {
    v["success"].as_array().is_some_and(|ops| {
        ops.iter().any(|op| {
            op.get("request_txn").map_or_else(
                || {
                    op["request_put"]["key"]
                        .as_str()
                        .and_then(|s| STANDARD.decode(s).ok())
                        .is_some_and(|k| {
                            String::from_utf8_lossy(&k).contains("/delivery-progress/")
                        })
                },
                contains_progress,
            )
        })
    })
}
async fn ledger_proxy(
    State(p): State<Arc<LedgerProxy>>,
    Extension(w): Extension<WorkloadIdentity>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(w.as_str(), SOURCE);
    assert_eq!(h["authorization"], "supervisor-etcd");
    if contains_progress(&v) && p.drop_progress.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"test-owned before-progress failure"})),
        );
    }
    let incident_write = v["success"].as_array().is_some_and(|ops| {
        ops.iter().any(|op| {
            op["request_put"]["key"]
                .as_str()
                .and_then(|k| STANDARD.decode(k).ok())
                .is_some_and(|k| String::from_utf8_lossy(&k).ends_with("/incident"))
        })
    });
    if incident_write && p.pause_incident.swap(false, Ordering::SeqCst) {
        p.incident_entered.notify_one();
        p.incident_release.notified().await;
    }
    let reply = reqwest::Client::new()
        .post(format!("{}/v3/kv/txn", p.endpoint))
        .json(&v)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    (StatusCode::OK, Json(reply))
}
struct Harness {
    ledger: EtcdLedger,
    c: Candidate,
    gd: String,
    verifier: GrantVerifier,
    clock: Arc<Time>,
    query: Arc<Query>,
    trust: ReporterTrust,
    pki: support::Pki,
    url: String,
    network: Arc<Network>,
    task: Option<tokio::task::JoinHandle<()>>,
    proxy: Arc<LedgerProxy>,
    _servers: Vec<support::HttpsServer>,
    dir: tempfile::TempDir,
    config: Value,
    endpoint: String,
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}
impl Harness {
    async fn new() -> Option<Self> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(v) => v,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP supervision: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let (mut call, _) = domain::call();
        let now = chrono::Utc::now().timestamp_millis();
        call.grant.issued_at = now - 120000;
        call.grant.valid_from = now - 120000;
        call.grant.expires_at = now - 60000;
        call.signed_grant =
            sign_grant(&call.grant, "test-key", &SigningKey::from_bytes(&[6; 32])).unwrap();
        let verifier = GrantVerifier {
            keys: keys("test-key", 6),
            audience: call.grant.audience.clone(),
        };
        let gd = verifier.verify_retained(&call.signed_grant).unwrap().digest;
        let clock = Arc::new(Time(AtomicI64::new(now)));
        let prefix = format!(
            "/kf-supervision/{}/{}",
            std::process::id(),
            rand::random::<u64>()
        );
        let ledger = EtcdLedger::new(reqwest::Client::new(), &endpoint, &prefix)
            .unwrap()
            .with_clock(clock.clone());
        ledger.publish_policy(&call.grant).await.unwrap();
        ledger.issue(&call.grant, &gd).await.unwrap();
        let c = Candidate {
            grant: call.grant.clone(),
            attempt_id: "supervised-original".into(),
        };
        ledger
            .claim_recorded(
                &c.grant,
                &gd,
                &c.attempt_id,
                &ExecutionRecord {
                    signed_grant: String::from_utf8(call.signed_grant).unwrap(),
                    tool: call.descriptor.name,
                    parameters: call.request.params.arguments,
                },
            )
            .await
            .unwrap();
        ledger
            .authorize_dispatch(&c.grant, &gd, &c.attempt_id)
            .await
            .unwrap();
        let query = Arc::new(Query {
            c: c.clone(),
            gd: gd.clone(),
            mode: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        });
        let trust = ReporterTrust {
            tenant: "tenant-42".into(),
            conflict_domain: c.grant.conflict_domain.clone(),
            source_id: SOURCE.into(),
            subject: Subject {
                iss: c.grant.subject.iss.clone(),
                sub: "recovery-service".into(),
            },
            required_scope: "kf.outcome-report".into(),
            grants: verifier.clone(),
            outcome_keys: keys("outcome-14", 14),
        };
        let pki = support::pki_with_workload(SOURCE);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/outcomes", listener.local_addr().unwrap());
        let network = Arc::new(Network {
            reports: AtomicUsize::new(0),
            lookups: AtomicUsize::new(0),
            drop_reply: AtomicBool::new(false),
            invalid_reply: AtomicBool::new(false),
            block: AtomicBool::new(false),
            entered: Notify::new(),
        });
        let proxy = Arc::new(LedgerProxy {
            endpoint: endpoint.clone(),
            drop_progress: AtomicBool::new(false),
            pause_incident: AtomicBool::new(false),
            incident_entered: Notify::new(),
            incident_release: Notify::new(),
        });
        let proxy_server = support::serve_tls(
            &pki,
            Router::new()
                .route("/v3/kv/txn", post(ledger_proxy))
                .with_state(proxy.clone()),
        )
        .await;
        let query_server = support::serve_tls(
            &pki,
            Router::new()
                .route("/query", post(query_route))
                .with_state(query.clone()),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let path = |s: &str| dir.path().join(s);
        for (n, v) in [
            ("ca", pki.ca.clone()),
            ("cert", pki.client.clone()),
            ("private", pki.client_key.clone()),
            ("etcd-token", "supervisor-etcd".into()),
            ("query-token", "query-role".into()),
            ("outcome-key", STANDARD.encode([14; 32])),
            ("proof-key", STANDARD.encode([8; 32])),
        ] {
            std::fs::write(path(n), v).unwrap();
        }
        let config = json!({"recovery":{"etcd_endpoint":proxy_server.url,"etcd_prefix":prefix,"etcd_ca":path("ca"),"etcd_certificate":path("cert"),"etcd_private_key":path("private"),"etcd_token_file":path("etcd-token"),"gateway_audience":c.grant.audience,"grant_keys":{"test-key":STANDARD.encode(SigningKey::from_bytes(&[6;32]).verifying_key().as_bytes())},"query_url":format!("{}/query",query_server.url),"query_ca":path("ca"),"query_certificate":path("cert"),"query_private_key":path("private"),"query_token_file":path("query-token"),"receipt_key_id":"outcome-14","receipt_signing_key_file":path("outcome-key"),"source_id":SOURCE,"page_size":1,"poll_interval_ms":100},
  "delivery":{"collector_id":"collector-supervised","collector_url":url,"collector_ca":path("ca"),"certificate":path("cert"),"private_key":path("private"),"token_file":path("report-token"),"dpop_signing_key_file":path("proof-key"),"tenant":"tenant-42","conflict_domain":c.grant.conflict_domain,"reporter_subject":trust.subject,"report_scope":"kf.outcome-report","outcome_keys":{"outcome-14":STANDARD.encode(SigningKey::from_bytes(&[14;32]).verifying_key().as_bytes())},"acknowledgement_keys":{"collector-15":STANDARD.encode(SigningKey::from_bytes(&[15;32]).verifying_key().as_bytes())}},"incident_policy":{"owner_id":"team:sre-outcomes","unknown_after_ms":1000},"receipt_budget":1});
        let mut h = Self {
            ledger,
            c,
            gd,
            verifier,
            clock,
            query,
            trust,
            pki,
            url,
            network,
            task: None,
            proxy,
            _servers: vec![proxy_server, query_server],
            dir,
            config,
            endpoint,
        };
        h.start(listener);
        h.write_config();
        Some(h)
    }
    fn start(&mut self, listener: tokio::net::TcpListener) {
        let service = Arc::new(
            OutcomeReportService::new(
                self.trust.clone(),
                self.ledger.clone(),
                DualAuthenticator::new(
                    &self.trust.subject.iss,
                    AUD,
                    &self.url,
                    SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
                )
                .unwrap(),
                "collector-supervised".into(),
                "collector-15".into(),
                SigningKey::from_bytes(&[15; 32]),
                self.clock.clone(),
            )
            .unwrap(),
        );
        let router = service.router().layer(middleware::from_fn_with_state(
            self.network.clone(),
            collector_fault,
        ));
        let tls = tls::server_config_pem(
            self.pki.server.as_bytes(),
            self.pki.server_key.as_bytes(),
            self.pki.ca.as_bytes(),
        )
        .unwrap();
        self.task = Some(tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, tls, router)
                .await
                .unwrap();
        }));
    }
    async fn stop(&mut self) {
        let t = self.task.take().unwrap();
        t.abort();
        let _ = t.await;
    }
    async fn restart(&mut self) {
        if self.task.is_some() {
            self.stop().await;
        }
        let address = reqwest::Url::parse(&self.url)
            .unwrap()
            .socket_addrs(|| None)
            .unwrap()[0];
        self.start(tokio::net::TcpListener::bind(address).await.unwrap());
    }
    fn token(&self) -> String {
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes())});
        jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":self.trust.subject.iss,"sub":"recovery-service","aud":AUD,"iat":self.clock.now_ms()/1000,"exp":self.clock.now_ms()/1000+3600,"scope":"kf.outcome-report","cnf":{"jkt":URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()))}}),
            7,
        )
    }
    fn write_config(&self) {
        std::fs::write(self.dir.path().join("report-token"), self.token()).unwrap();
        std::fs::write(
            self.dir.path().join("supervise.json"),
            serde_json::to_vec(&self.config).unwrap(),
        )
        .unwrap();
    }
    fn client(&self) -> OutcomeReportClient {
        OutcomeReportClient::new(
            tls::pinned_client_pem(
                self.pki.ca.as_bytes(),
                self.pki.client.as_bytes(),
                self.pki.client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap(),
            CollectorTrust {
                reporter: self.trust.clone(),
                collector_id: "collector-supervised".into(),
                collector_url: self.url.clone(),
                acknowledgement_keys: keys("collector-15", 15),
            },
            self.token(),
            SigningKey::from_bytes(&[8; 32]),
            self.clock.clone(),
        )
        .unwrap()
    }
    fn worker(&self, proxied: bool) -> RecoveryWorker {
        let ledger = if proxied {
            let client = tls::pinned_http_client_pem(
                self.pki.ca.as_bytes(),
                self.pki.client.as_bytes(),
                self.pki.client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap();
            EtcdLedger::new(
                client,
                self._servers[0].url.clone(),
                self.ledger.namespace(),
            )
            .unwrap()
            .with_auth_token("supervisor-etcd")
            .unwrap()
        } else {
            self.ledger.clone()
        };
        RecoveryWorker::new(
            ledger,
            self.verifier.clone(),
            self.query.clone(),
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]),
            SOURCE.into(),
            self.clock.clone(),
        )
        .unwrap()
    }
    fn supervisor(
        &self,
        budget: usize,
        policy: IncidentPolicy,
        proxied: bool,
    ) -> OutcomeSupervisor {
        OutcomeSupervisor::new(
            self.worker(proxied),
            self.client(),
            policy,
            budget,
            self.clock.clone(),
        )
        .unwrap()
    }
    fn standard(&self) -> OutcomeSupervisor {
        self.supervisor(1, self.policy(), false)
    }
    fn policy(&self) -> IncidentPolicy {
        IncidentPolicy {
            owner_id: "team:sre-outcomes".into(),
            unknown_after_ms: 1000,
        }
    }
    fn advance(&self, ms: i64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }
    async fn incident(&self) -> kedgeflow::supervision::Incident {
        self.ledger
            .supervision_incident(&self.c)
            .await
            .unwrap()
            .unwrap()
    }
    async fn progress(&self) -> Vec<(String, DeliveryProgress)> {
        let prefix = format!("{}/delivery-progress/", self.base());
        let body = json!({"success":[{"request_range":{"key":STANDARD.encode(&prefix),"range_end":STANDARD.encode(format!("{prefix}\u{10ffff}"))}}]});
        let v = self.raw(body).await;
        v["responses"][0]["response_range"]["kvs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|kv| {
                (
                    String::from_utf8(STANDARD.decode(kv["key"].as_str().unwrap()).unwrap())
                        .unwrap(),
                    serde_json::from_slice(
                        &STANDARD.decode(kv["value"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect()
    }
    fn base(&self) -> String {
        format!(
            "{}/domains/{}/roots/{}/attempts/{}",
            self.ledger.namespace(),
            URL_SAFE_NO_PAD.encode(&self.c.grant.conflict_domain),
            URL_SAFE_NO_PAD.encode(&self.c.grant.root_id),
            URL_SAFE_NO_PAD.encode(&self.c.attempt_id)
        )
    }
    async fn raw(&self, v: Value) -> Value {
        reqwest::Client::new()
            .post(format!("{}/v3/kv/txn", self.endpoint))
            .json(&v)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn held(&self) {
        assert!(
            self.ledger
                .claim(&self.c.grant, &self.gd, "another-attempt")
                .await
                .is_err()
        );
        let mut next = self.c.grant.clone();
        next.root_generation += 1;
        next.fence += 1;
        next.gid.push_str("-replace");
        next.nonce.push_str("-replace");
        assert!(
            self.ledger
                .replace(&self.c.grant, &next, &self.gd)
                .await
                .is_err()
        );
        let b = self.ledger.export_outcomes(&self.c).await.unwrap();
        verify_outcomes(&b, &self.verifier, &keys("outcome-14", 14), SOURCE).unwrap();
    }
    async fn cli(&self, flag: &str) -> std::process::Output {
        tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-supervise"))
                .args([
                    "--config",
                    self.dir.path().join("supervise.json").to_str().unwrap(),
                    flag,
                ])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap()
    }
}
#[tokio::test]
async fn unknown_deadline_owner_and_resolution_survive_recreated_supervisors() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let s = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!((s.incidents_opened, s.delivered, s.unavailable), (1, 1, 0));
    let first = h.incident().await;
    assert_eq!(first.state, "open");
    assert_eq!(first.deadline, first.unknown_since + 1000);
    h.advance(999);
    assert_eq!(
        h.standard()
            .sweep(None, 1)
            .await
            .unwrap()
            .incidents_escalated,
        0
    );
    h.advance(1);
    assert_eq!(
        h.standard()
            .sweep(None, 1)
            .await
            .unwrap()
            .incidents_escalated,
        1
    );
    let escalated = h.incident().await;
    assert_eq!(escalated.state, "escalated");
    assert_eq!(escalated.deadline, first.deadline);
    assert_eq!(escalated.owner_id, first.owner_id);
    h.query.mode.store(1, Ordering::SeqCst);
    let s = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!(
        (s.incidents_resolved, s.delivered, s.unavailable),
        (1, 1, 0)
    );
    let resolved = h.incident().await;
    assert_eq!(
        (resolved.revision, resolved.state.as_str()),
        (3, "resolved")
    );
    assert_eq!(resolved.deadline, first.deadline);
    assert_eq!(h.progress().await.len(), 2);
    h.held().await;
}
#[tokio::test]
async fn late_discovery_uses_original_unknown_journal_not_restart_time() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.worker(false).recover(&h.c).await.unwrap();
    let since = h.clock.now_ms();
    h.advance(2000);
    let s = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!((s.incidents_opened, s.incidents_escalated), (1, 1));
    assert_eq!(h.incident().await.unknown_since, since);
    assert_eq!(h.incident().await.deadline, since + 1000);
    h.held().await;
}
#[tokio::test]
async fn changed_owner_deadline_and_regressed_clock_refuse_existing_incident() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.standard().sweep(None, 1).await.unwrap();
    let old = h.incident().await;
    let network =
        h.network.lookups.load(Ordering::SeqCst) + h.network.reports.load(Ordering::SeqCst);
    for policy in [
        IncidentPolicy {
            owner_id: "other-owner".into(),
            unknown_after_ms: 1000,
        },
        IncidentPolicy {
            owner_id: old.owner_id.clone(),
            unknown_after_ms: 2000,
        },
    ] {
        assert_eq!(
            h.supervisor(1, policy, false)
                .sweep(None, 1)
                .await
                .unwrap()
                .unavailable,
            1
        );
        assert_eq!(h.incident().await, old);
    }
    h.advance(-1);
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().unavailable, 1);
    assert_eq!(h.incident().await, old);
    assert_eq!(
        h.network.lookups.load(Ordering::SeqCst) + h.network.reports.load(Ordering::SeqCst),
        network
    );
}
#[tokio::test]
async fn receipt_budget_orders_unknown_then_commit_and_restart_skips_acks() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.worker(false).recover(&h.c).await.unwrap();
    h.query.mode.store(1, Ordering::SeqCst);
    h.worker(false).recover(&h.c).await.unwrap();
    let first = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!(
        (first.delivered, first.delivery_deferred, first.unavailable),
        (1, 1, 0)
    );
    let old = h.progress().await[0].1.acknowledgement.clone();
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().delivered, 1);
    let network =
        h.network.lookups.load(Ordering::SeqCst) + h.network.reports.load(Ordering::SeqCst);
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().delivered, 0);
    assert_eq!(
        h.network.lookups.load(Ordering::SeqCst) + h.network.reports.load(Ordering::SeqCst),
        network
    );
    assert!(
        h.progress()
            .await
            .iter()
            .any(|(_, p)| p.acknowledgement == old)
    );
    assert_eq!(h.incident().await.state, "resolved");
    h.held().await;
}
#[tokio::test]
async fn lost_collector_ack_reply_is_resolved_by_lookup_after_restart() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    h.network.drop_reply.store(true, Ordering::SeqCst);
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().unavailable, 1);
    assert!(h.progress().await.is_empty());
    let old = h.incident().await;
    h.restart().await;
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().delivered, 1);
    assert_eq!(h.network.reports.load(Ordering::SeqCst), 1);
    assert_eq!(h.incident().await, old);
    h.held().await;
}
#[tokio::test]
async fn failed_local_progress_write_reuses_accepted_report() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.proxy.drop_progress.store(true, Ordering::SeqCst);
    assert_eq!(
        h.supervisor(1, h.policy(), true)
            .sweep(None, 1)
            .await
            .unwrap()
            .unavailable,
        1
    );
    assert!(h.progress().await.is_empty());
    assert_eq!(
        h.supervisor(1, h.policy(), true)
            .sweep(None, 1)
            .await
            .unwrap()
            .delivered,
        1
    );
    assert_eq!(h.network.reports.load(Ordering::SeqCst), 1);
    assert_eq!(h.progress().await.len(), 1);
    h.held().await;
}
#[tokio::test]
async fn concurrent_workers_reuse_incident_events_and_signed_ack() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.worker(false).recover(&h.c).await.unwrap();
    h.advance(1000);
    let a = h.standard();
    let b = h.standard();
    let (a, b) = tokio::join!(a.sweep(None, 1), b.sweep(None, 1));
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.incidents_opened + b.incidents_opened, 1);
    assert_eq!(a.incidents_escalated + b.incidents_escalated, 1);
    assert_eq!(h.incident().await.revision, 2);
    assert_eq!(h.progress().await.len(), 1);
    h.held().await;
}
#[tokio::test]
async fn collector_outage_preserves_owned_escalation_and_resumes_delivery() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    h.worker(false).recover(&h.c).await.unwrap();
    h.stop().await;
    h.advance(1000);
    let s = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!(
        (s.incidents_opened, s.incidents_escalated, s.unavailable),
        (1, 1, 1)
    );
    let old = h.incident().await;
    h.restart().await;
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().delivered, 1);
    assert_eq!(h.incident().await, old);
    h.held().await;
}
#[tokio::test]
async fn invalid_ack_and_corrupt_progress_never_skip_verification() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.network.invalid_reply.store(true, Ordering::SeqCst);
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().unavailable, 1);
    assert!(h.progress().await.is_empty());
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().delivered, 1);
    let (key, mut progress) = h.progress().await.remove(0);
    progress.acknowledgement = "invalid-test-signature".into();
    h.raw(json!({"success":[{"request_put":{"key":STANDARD.encode(key),"value":STANDARD.encode(canonical(&serde_json::to_value(progress).unwrap()).unwrap())}}]})).await;
    let network =
        h.network.lookups.load(Ordering::SeqCst) + h.network.reports.load(Ordering::SeqCst);
    assert_eq!(h.standard().sweep(None, 1).await.unwrap().unavailable, 1);
    assert_eq!(
        h.network.lookups.load(Ordering::SeqCst) + h.network.reports.load(Ordering::SeqCst),
        network
    );
}
#[tokio::test]
async fn restore_required_state_refuses_supervision_before_network() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.raw(json!({"success":[{"request_put":{"key":STANDARD.encode(format!("{}/restore-gate",h.ledger.namespace())),"value":STANDARD.encode("test-required-witness")}}]})).await;
    assert!(h.standard().sweep(None, 1).await.is_err());
    assert_eq!(
        h.network.reports.load(Ordering::SeqCst) + h.network.lookups.load(Ordering::SeqCst),
        0
    );
    assert_eq!(h.query.calls.load(Ordering::SeqCst), 0);
}
#[cfg(unix)]
#[tokio::test]
async fn shipping_supervisor_kill_after_acceptance_resumes_exact_ack_and_owner() {
    use std::os::unix::process::ExitStatusExt;
    let Some(mut h) = Harness::new().await else {
        return;
    };
    assert!(h.cli("--check").await.status.success());
    assert_eq!(h.query.calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.network.reports.load(Ordering::SeqCst), 0);
    h.network.block.store(true, Ordering::SeqCst);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-supervise"))
        .args([
            "--config",
            h.dir.path().join("supervise.json").to_str().unwrap(),
            "--once",
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), h.network.entered.notified())
        .await
        .unwrap();
    assert!(child.try_wait().unwrap().is_none());
    child.kill().await.unwrap();
    let exit = child.wait().await.unwrap();
    assert_eq!(exit.signal(), Some(9));
    let original = h.incident().await;
    assert!(h.progress().await.is_empty());
    h.restart().await;
    h.clock
        .0
        .store(chrono::Utc::now().timestamp_millis(), Ordering::SeqCst);
    h.write_config();
    let output = h.cli("--once").await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sweep: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(sweep["delivered"], 1);
    assert_eq!(h.network.reports.load(Ordering::SeqCst), 1);
    let progress = h.progress().await[0].1.acknowledgement.clone();
    let incident = h.incident().await;
    assert_eq!(incident.owner_id, original.owner_id);
    assert_eq!(incident.deadline, original.deadline);
    let output = h.cli("--once").await;
    assert!(output.status.success());
    assert_eq!(h.progress().await[0].1.acknowledgement, progress);
    assert_eq!(h.network.reports.load(Ordering::SeqCst), 1);
    h.query.mode.store(1, Ordering::SeqCst);
    h.clock
        .0
        .store(chrono::Utc::now().timestamp_millis(), Ordering::SeqCst);
    h.write_config();
    assert!(h.cli("--once").await.status.success());
    assert_eq!(h.incident().await.state, "resolved");
    assert_eq!(h.incident().await.deadline, original.deadline);
    assert_eq!(h.progress().await.len(), 2);
    h.held().await;
    println!(
        "supervision matrix: SIGKILL reaped after collector acceptance; restart reused exact signed ack and incident owner/deadline; later commit resolved while consumption stayed held"
    );
}

#[tokio::test]
async fn actual_signer_and_registered_domain_are_checked_before_work() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let wrong = RecoveryWorker::new(
        h.ledger.clone(),
        h.verifier.clone(),
        h.query.clone(),
        "outcome-14".into(),
        SigningKey::from_bytes(&[16; 32]),
        SOURCE.into(),
        h.clock.clone(),
    )
    .unwrap();
    assert!(OutcomeSupervisor::new(wrong, h.client(), h.policy(), 1, h.clock.clone()).is_err());
    let file = h.dir.path().join("wrong-outcome-key");
    std::fs::write(&file, STANDARD.encode([16; 32])).unwrap();
    h.config["recovery"]["receipt_signing_key_file"] = json!(file);
    h.write_config();
    let check = h.cli("--check").await;
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("registrations do not match"));
    h.trust.conflict_domain = "another-domain".into();
    let s = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!((s.recovered, s.unavailable), (0, 1));
    assert_eq!(h.query.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.network.reports.load(Ordering::SeqCst) + h.network.lookups.load(Ordering::SeqCst),
        0
    );
    assert!(h.ledger.supervision_incident(&h.c).await.unwrap().is_none());
    assert!(h.progress().await.is_empty());
    assert_eq!(
        h.ledger
            .status(&h.c.grant, &h.c.attempt_id)
            .await
            .unwrap()
            .status,
        "claimed"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn shipping_continuous_polling_delivers_later_commit_and_retains_progress() {
    use tokio::io::AsyncBufReadExt;
    let Some(h) = Harness::new().await else {
        return;
    };
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-supervise"))
        .args([
            "--config",
            h.dir.path().join("supervise.json").to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let first = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let first: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first["delivered"], 1);
    assert_eq!(first["incidents_opened"], 1);
    let original = h.incident().await;
    h.query.mode.store(1, Ordering::SeqCst);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let line = tokio::time::timeout_at(deadline, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let s: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(s["unavailable"], 0);
        if s["incidents_resolved"] == 1 {
            assert_eq!(s["delivered"], 1);
            break;
        }
    }
    assert!(child.try_wait().unwrap().is_none());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let incident = h.incident().await;
    assert_eq!(incident.state, "resolved");
    assert_eq!(incident.deadline, original.deadline);
    assert_eq!(incident.owner_id, original.owner_id);
    let mut before: Vec<_> = h
        .progress()
        .await
        .into_iter()
        .map(|(_, p)| p.acknowledgement)
        .collect();
    before.sort();
    assert_eq!(before.len(), 2);
    let output = h.cli("--once").await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let s: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(s["delivered"], 0);
    let mut after: Vec<_> = h
        .progress()
        .await
        .into_iter()
        .map(|(_, p)| p.acknowledgement)
        .collect();
    after.sort();
    assert_eq!(after, before);
    assert_eq!(h.network.reports.load(Ordering::SeqCst), 2);
    h.held().await;
    println!(
        "supervision matrix: continuous shipping worker automatically delivered unknown then later commit; restart verified both local acknowledgements without reporting again"
    );
}

#[tokio::test]
async fn stale_escalation_cas_cannot_overwrite_retained_commit() {
    let Some(h) = Harness::new().await else {
        return;
    };
    h.standard().sweep(None, 1).await.unwrap();
    let original = h.incident().await;
    h.advance(1000);
    h.proxy.pause_incident.store(true, Ordering::SeqCst);
    let supervisor = h.supervisor(1, h.policy(), true);
    let task = tokio::spawn(async move { supervisor.sweep(None, 1).await });
    tokio::time::timeout(Duration::from_secs(5), h.proxy.incident_entered.notified())
        .await
        .unwrap();
    h.query.mode.store(1, Ordering::SeqCst);
    h.worker(false).recover(&h.c).await.unwrap();
    h.proxy.incident_release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.unavailable, 1);
    assert_eq!(result.incidents_escalated, 0);
    assert_eq!(
        h.incident().await,
        original,
        "stale escalation must not update incident head or events"
    );
    let result = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!(result.incidents_resolved, 1);
    let resolved = h.incident().await;
    assert_eq!(
        (resolved.revision, resolved.state.as_str()),
        (2, "resolved")
    );
    assert_eq!(resolved.deadline, original.deadline);
    assert_eq!(resolved.owner_id, original.owner_id);
    h.held().await;
}

#[tokio::test]
async fn export_capacity_refusal_cannot_suppress_owned_deadline() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let first = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!(
        (first.incidents_opened, first.delivered, first.unavailable),
        (1, 1, 0)
    );
    let original = h.incident().await;
    h.query.mode.store(2, Ordering::SeqCst);
    for _ in 0..64 {
        h.worker(false).recover(&h.c).await.unwrap();
    }
    assert!(h.ledger.export_outcomes(&h.c).await.is_err());
    let reports = h.network.reports.load(Ordering::SeqCst);
    let lookups = h.network.lookups.load(Ordering::SeqCst);
    h.advance(1000);
    let s = h.standard().sweep(None, 1).await.unwrap();
    assert_eq!(
        (s.incidents_escalated, s.delivered, s.unavailable),
        (1, 0, 1)
    );
    let escalated = h.incident().await;
    assert_eq!(escalated.state, "escalated");
    assert_eq!(escalated.deadline, original.deadline);
    assert_eq!(escalated.unknown_since, original.unknown_since);
    assert_eq!(escalated.owner_id, original.owner_id);
    assert_eq!(h.network.reports.load(Ordering::SeqCst), reports);
    assert_eq!(h.network.lookups.load(Ordering::SeqCst), lookups);
    assert_eq!(h.progress().await.len(), 1);
}
