//! Native mTLS/DPoP and actual-etcd delivery; software role/query fixtures.
#[path = "support/domain.rs"]
mod domain;
mod support;
use async_trait::async_trait;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    auth::DualAuthenticator,
    clock::Clock,
    contracts::{Envelope, Subject, canonical, record_digest, signature_input},
    error::Result,
    ledger::{AuthoritativeObservation, AuthorityLedger, EtcdLedger, OutcomeQuerier},
    outcome_report::{Acknowledgement, PROFILE, verify_ack},
    outcome_report_client::{CollectorTrust, DeliveryReceipt, OutcomeReportClient},
    outcome_report_service::{OutcomeReportService, ReporterTrust},
    recovery::{Candidate, ExecutionRecord, RecoveryWorker},
    tls,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
const SOURCE: &str = "spiffe://test/outcome";
const AUD: &str = "urn:kedgeflow:outcome-report-test";
struct Time(AtomicI64);
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Query {
    c: Candidate,
    gd: String,
    mode: AtomicUsize,
}
#[async_trait]
impl OutcomeQuerier for Query {
    async fn query(&self, id: &str) -> Result<AuthoritativeObservation> {
        Ok(AuthoritativeObservation {
            attempt_id: id.into(),
            root_id: self.c.grant.root_id.clone(),
            grant_digest: self.gd.clone(),
            status: if self.mode.load(Ordering::SeqCst) == 0 {
                "pending"
            } else {
                "committed"
            }
            .into(),
            target_reference: "software:retained:241".into(),
        })
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
struct Harness {
    shared_auth: bool,
    ledger: EtcdLedger,
    c: Candidate,
    receipts: Vec<DeliveryReceipt>,
    trust: ReporterTrust,
    clock: Arc<Time>,
    url: String,
    pki: support::Pki,
    agent_pki: support::Pki,
    dropped: Arc<AtomicUsize>,
    task: Option<tokio::task::JoinHandle<()>>,
    jti: AtomicU64,
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
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
                eprintln!("SKIP outcome report: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let (call, verifier) = domain::call();
        let ledger = EtcdLedger::new(
            reqwest::Client::new(),
            endpoint,
            format!(
                "/kf-report/{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ),
        )
        .unwrap();
        ledger.publish_policy(&call.grant).await.unwrap();
        ledger.issue(&call.grant, &call.grant_digest).await.unwrap();
        let c = Candidate {
            grant: call.grant.clone(),
            attempt_id: "original-report-attempt".into(),
        };
        let clock = Arc::new(Time(AtomicI64::new(domain::NOW + 120000)));
        let query = Arc::new(Query {
            c: c.clone(),
            gd: call.grant_digest.clone(),
            mode: AtomicUsize::new(0),
        });
        ledger
            .claim_recorded(
                &c.grant,
                &call.grant_digest,
                &c.attempt_id,
                &ExecutionRecord {
                    signed_grant: String::from_utf8(call.signed_grant.clone()).unwrap(),
                    tool: call.descriptor.name,
                    parameters: call.request.params.arguments,
                },
            )
            .await
            .unwrap();
        ledger
            .authorize_dispatch(&c.grant, &call.grant_digest, &c.attempt_id)
            .await
            .unwrap();
        let worker = RecoveryWorker::new(
            ledger.clone(),
            verifier.clone(),
            query.clone(),
            "outcome-14".into(),
            SigningKey::from_bytes(&[14; 32]),
            SOURCE.into(),
            clock.clone(),
        )
        .unwrap();
        worker.recover(&c).await.unwrap();
        query.mode.store(1, Ordering::SeqCst);
        worker.recover(&c).await.unwrap();
        let bundle = ledger.export_outcomes(&c).await.unwrap();
        let receipts = bundle
            .receipts
            .iter()
            .map(|raw| {
                let e: Envelope = serde_json::from_str(raw).unwrap();
                let ed = e.payload["resolution_evidence"][0]["digest"]
                    .as_str()
                    .unwrap();
                DeliveryReceipt {
                    signed_grant: bundle.execution.signed_grant.clone(),
                    signed_receipt: raw.clone(),
                    evidence: bundle.evidence[ed].clone(),
                }
            })
            .collect();
        let subject = Subject {
            iss: c.grant.subject.iss.clone(),
            sub: "recovery-service".into(),
        };
        let trust = ReporterTrust {
            tenant: "tenant-42".into(),
            conflict_domain: c.grant.conflict_domain.clone(),
            source_id: SOURCE.into(),
            subject,
            required_scope: "kf.outcome-report".into(),
            grants: verifier,
            outcome_keys: keys("outcome-14", 14),
        };
        let mut pkis = support::pki_for_workloads(&[SOURCE, "spiffe://test/agent"]);
        let agent_pki = pkis.pop().unwrap();
        let pki = pkis.pop().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/outcomes", listener.local_addr().unwrap());
        let mut h = Self {
            shared_auth: false,
            ledger,
            c,
            receipts,
            trust,
            clock,
            url,
            pki,
            agent_pki,
            dropped: Arc::new(AtomicUsize::new(0)),
            task: None,
            jti: AtomicU64::new(0),
        };
        h.start(listener);
        Some(h)
    }
    fn start(&mut self, listener: tokio::net::TcpListener) {
        use axum::{
            extract::Request,
            http::StatusCode,
            middleware::{self, Next},
            response::{IntoResponse, Response},
        };
        let auth = DualAuthenticator::new(
            &self.trust.subject.iss,
            AUD,
            &self.url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let auth = if self.shared_auth {
            auth.with_shared_replay(
                self.ledger.clone(),
                kedgeflow::shared_auth::SharedAuthConfig {
                    capacity: 16,
                    registrations: vec![kedgeflow::shared_auth::SubjectWorkload {
                        subject: self.trust.subject.clone(),
                        workload_id: self.trust.source_id.clone(),
                        allowed_scopes: std::collections::BTreeSet::from([self
                            .trust
                            .required_scope
                            .clone()]),
                    }],
                },
            )
            .unwrap()
        } else {
            auth
        };
        let service = Arc::new(
            OutcomeReportService::new(
                self.trust.clone(),
                self.ledger.clone(),
                auth,
                "collector-test".into(),
                "collector-15".into(),
                SigningKey::from_bytes(&[15; 32]),
                self.clock.clone(),
            )
            .unwrap(),
        );
        let dropped = self.dropped.clone();
        let router =
            service
                .router()
                .layer(middleware::from_fn(move |request: Request, next: Next| {
                    let dropped = dropped.clone();
                    async move {
                        let response: Response = next.run(request).await;
                        if response.status().is_success() && dropped.swap(0, Ordering::SeqCst) == 1
                        {
                            (
                                StatusCode::SERVICE_UNAVAILABLE,
                                "software discarded committed acknowledgement reply",
                            )
                                .into_response()
                        } else {
                            response
                        }
                    }
                }));
        let config = tls::server_config_pem(
            self.pki.server.as_bytes(),
            self.pki.server_key.as_bytes(),
            self.pki.ca.as_bytes(),
        )
        .unwrap();
        self.task = Some(tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, config, router)
                .await
                .unwrap();
        }));
    }
    async fn restart(&mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        let _ = task.await;
        let address = reqwest::Url::parse(&self.url)
            .unwrap()
            .socket_addrs(|| None)
            .unwrap()[0];
        self.start(tokio::net::TcpListener::bind(address).await.unwrap());
    }
    fn transport(&self, agent: bool) -> tls::PinnedClient {
        let p = if agent { &self.agent_pki } else { &self.pki };
        tls::pinned_client_pem(
            p.ca.as_bytes(),
            p.client.as_bytes(),
            p.client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    }
    fn token(&self, scope: &str, sub: &str) -> String {
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes())});
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()));
        let now = self.clock.now_ms() / 1000;
        jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":self.trust.subject.iss,"sub":sub,"aud":AUD,"iat":now,"exp":now+60,"scope":scope,"cnf":{"jkt":jkt}}),
            7,
        )
    }
    fn headers(&self, scope: &str, sub: &str, htu: &str) -> http::HeaderMap {
        let token = self.token(scope, sub);
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes())});
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":jwk}),
            json!({"jti":format!("report-{}",self.jti.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":htu,"iat":self.clock.now_ms()/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}),
            8,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("DPoP {token}").parse().unwrap());
        headers.insert("dpop", proof.parse().unwrap());
        headers
    }
    fn client(&self) -> OutcomeReportClient {
        OutcomeReportClient::new(
            self.transport(false),
            CollectorTrust {
                reporter: self.trust.clone(),
                collector_id: "collector-test".into(),
                collector_url: self.url.clone(),
                acknowledgement_keys: keys("collector-15", 15),
            },
            self.token("kf.outcome-report", "recovery-service"),
            SigningKey::from_bytes(&[8; 32]),
            self.clock.clone(),
        )
        .unwrap()
    }
    fn command(&self, i: usize) -> Value {
        let r = &self.receipts[i];
        json!({"profile":PROFILE,"operation":"report","request_id":"wire-report","signed_grant":r.signed_grant,"signed_receipt":r.signed_receipt,"evidence":r.evidence})
    }
    async fn send(&self, body: Value, headers: http::HeaderMap, agent: bool) -> (u16, Value) {
        let r = self
            .transport(agent)
            .client()
            .post(&self.url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        assert_eq!(r.headers()["cache-control"], "no-store");
        (status, r.json().await.unwrap())
    }
    async fn unchanged(&self, before: &kedgeflow::ledger::Attempt) {
        assert_eq!(
            &self
                .ledger
                .status(&self.c.grant, &self.c.attempt_id)
                .await
                .unwrap(),
            before
        );
        let gd: Envelope = serde_json::from_str(&self.receipts[0].signed_grant).unwrap();
        let gd = record_digest(&gd).unwrap();
        assert!(
            self.ledger
                .claim(&self.c.grant, &gd, "new-attempt")
                .await
                .is_err()
        );
        let mut next = self.c.grant.clone();
        next.gid.push_str("-replacement");
        next.root_generation += 1;
        next.fence += 1;
        assert!(
            self.ledger
                .replace(&self.c.grant, &next, &gd)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn native_delivery_recovers_lost_ack_reply_and_reuses_it_after_restart() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let before = h.ledger.status(&h.c.grant, &h.c.attempt_id).await.unwrap();
    let client = h.client();
    assert!(
        client
            .lookup("before", &h.receipts[0])
            .await
            .unwrap()
            .is_none()
    );
    h.dropped.store(1, Ordering::SeqCst);
    assert!(client.deliver("lost", &h.receipts[0]).await.is_err());
    let ack = client
        .lookup("resolve-lost", &h.receipts[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client.deliver("duplicate", &h.receipts[0]).await.unwrap(),
        ack
    );
    h.clock.0.fetch_add(1000, Ordering::SeqCst);
    h.restart().await;
    assert_eq!(
        h.client()
            .lookup("restart-query", &h.receipts[0])
            .await
            .unwrap()
            .unwrap(),
        ack
    );
    assert_eq!(
        h.client()
            .deliver("restart-report", &h.receipts[0])
            .await
            .unwrap(),
        ack
    );
    h.unchanged(&before).await;
    println!(
        "native delivery: discarded first ack reply; lookup/retry/recreated collector reused exact signed acknowledgement"
    );
}
#[tokio::test]
async fn native_delivery_orders_predecessors_and_concurrent_duplicates_preserve_authority() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let before = h.ledger.status(&h.c.grant, &h.c.attempt_id).await.unwrap();
    let (status, r) = h
        .send(
            h.command(1),
            h.headers("kf.outcome-report", "recovery-service", &h.url),
            false,
        )
        .await;
    assert_eq!(status, 409);
    assert_eq!(r["code"], "predecessor_required");
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..16 {
        let c = h.client();
        let receipt = h.receipts[0].clone();
        tasks.spawn(async move { c.deliver(&format!("parallel-{i}"), &receipt).await });
    }
    let mut acknowledgements = std::collections::BTreeSet::new();
    while let Some(r) = tasks.join_next().await {
        acknowledgements.insert(r.unwrap().unwrap());
    }
    assert_eq!(acknowledgements.len(), 1);
    let last = h
        .client()
        .deliver("terminal", &h.receipts[1])
        .await
        .unwrap();
    let payload: Value = serde_json::from_str(&last).unwrap();
    assert_eq!(
        payload["payload"]["previous_receipt_digest"],
        record_digest(&serde_json::from_str::<Envelope>(&h.receipts[0].signed_receipt).unwrap())
            .unwrap()
    );
    assert_eq!(
        h.client()
            .deliver("late-unknown", &h.receipts[0])
            .await
            .unwrap(),
        acknowledgements.into_iter().next().unwrap()
    );
    assert_eq!(
        h.client()
            .lookup("terminal-query", &h.receipts[1])
            .await
            .unwrap()
            .unwrap(),
        last
    );
    h.unchanged(&before).await;
    println!(
        "native delivery: 16 duplicates -> one acknowledgement; terminal receipt requires acknowledged unknown predecessor"
    );
}
#[tokio::test]
async fn native_delivery_refuses_identity_scope_proof_and_record_substitution() {
    let Some(h) = Harness::new().await else {
        return;
    };
    for (scope, sub, url, agent, expected) in [
        ("mutate", "recovery-service", h.url.as_str(), false, 403),
        (
            "kf.outcome-report",
            "other-subject",
            h.url.as_str(),
            false,
            403,
        ),
        (
            "kf.outcome-report",
            "recovery-service",
            "https://other.test/outcomes",
            false,
            401,
        ),
        (
            "kf.outcome-report",
            "recovery-service",
            h.url.as_str(),
            true,
            403,
        ),
    ] {
        assert_eq!(
            h.send(h.command(0), h.headers(scope, sub, url), agent)
                .await
                .0,
            expected
        );
    }
    let mut changed = h.command(0);
    changed["evidence"]["observation"]["Status"] = json!("committed");
    let (status, r) = h
        .send(
            changed,
            h.headers("kf.outcome-report", "recovery-service", &h.url),
            false,
        )
        .await;
    assert_eq!(status, 409);
    assert_eq!(r["code"], "not_retained");
    let mut changed = h.command(0);
    let mut receipt: Value =
        serde_json::from_str(changed["signed_receipt"].as_str().unwrap()).unwrap();
    receipt["payload"]["source_id"] = json!("spiffe://test/other");
    changed["signed_receipt"] = json!(receipt.to_string());
    assert_eq!(
        h.send(
            changed,
            h.headers("kf.outcome-report", "recovery-service", &h.url),
            false
        )
        .await
        .0,
        400
    );
    let mut changed = h.command(0);
    changed["extra"] = json!(1);
    assert_eq!(
        h.send(
            changed,
            h.headers("kf.outcome-report", "recovery-service", &h.url),
            false
        )
        .await
        .0,
        400
    );
    let headers = h.headers("kf.outcome-report", "recovery-service", &h.url);
    assert_eq!(h.send(h.command(0), headers.clone(), false).await.0, 200);
    assert_eq!(h.send(h.command(0), headers, false).await.0, 401);
}
#[tokio::test]
async fn signed_but_unretained_receipts_and_forged_acknowledgements_refuse() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let mut command = h.command(0);
    let mut e: Envelope =
        serde_json::from_str(command["signed_receipt"].as_str().unwrap()).unwrap();
    e.payload["event_time"] = json!(domain::NOW + 130000);
    e.signature = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[14; 32])
            .sign(&signature_input(&e).unwrap())
            .to_bytes(),
    );
    command["signed_receipt"] =
        json!(String::from_utf8(canonical(&serde_json::to_value(e).unwrap()).unwrap()).unwrap());
    let (status, r) = h
        .send(
            command,
            h.headers("kf.outcome-report", "recovery-service", &h.url),
            false,
        )
        .await;
    assert_eq!(status, 409);
    assert_eq!(r["code"], "not_retained");
    let raw = h.client().deliver("valid", &h.receipts[0]).await.unwrap();
    let mut ack: Value = serde_json::from_str(&raw).unwrap();
    let expected: Acknowledgement = serde_json::from_value(ack["payload"].clone()).unwrap();
    assert!(verify_ack(&raw, &keys("collector-15", 16), &expected).is_err());
    ack["payload"]["receipt_digest"] = json!("a".repeat(64));
    let mut message = b"KedgeFlow:KF-OUTCOME-REPORT-0.1-draft\0".to_vec();
    message.extend(canonical(&json!({"profile":ack["profile"],"kind":ack["kind"],"key_id":ack["key_id"],"payload":ack["payload"]})).unwrap());
    ack["signature"] =
        json!(URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[15; 32]).sign(&message).to_bytes()));
    assert!(verify_ack(&ack.to_string(), &keys("collector-15", 15), &expected).is_err());
    let mut wrong = expected.clone();
    wrong.collector_url = "https://other.test/outcomes".into();
    assert!(verify_ack(&raw, &keys("collector-15", 15), &wrong).is_err());
}
#[tokio::test]
async fn collector_configuration_check_is_local_closed_and_role_separated() {
    let pki = support::pki_with_workload(SOURCE);
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    for (name, text) in [
        ("server", &pki.server),
        ("server-key", &pki.server_key),
        ("ca", &pki.ca),
        ("client", &pki.client),
        ("client-key", &pki.client_key),
    ] {
        std::fs::write(p.join(name), text).unwrap();
    }
    std::fs::write(p.join("etcd-token"), "software-role").unwrap();
    std::fs::write(p.join("ack-key"), STANDARD.encode([15; 32])).unwrap();
    let config = json!({"listen":"127.0.0.1:0","external_url":"https://127.0.0.1:1/outcomes","certificate":p.join("server"),"private_key":p.join("server-key"),"workload_ca":p.join("ca"),"oidc_issuer":"https://issuer.test","delegation_audience":AUD,"oidc_public_key_base64":STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),"etcd_endpoint":"https://127.0.0.1:1/","etcd_prefix":"/tenant-42","etcd_ca":p.join("ca"),"etcd_certificate":p.join("client"),"etcd_private_key":p.join("client-key"),"etcd_token_file":p.join("etcd-token"),"tenant":"tenant-42","conflict_domain":"domain","source_id":SOURCE,"reporter_subject":{"iss":"https://issuer.test","sub":"recovery-service"},"report_scope":"kf.outcome-report","gateway_audience":"https://gateway.test/mcp","grant_keys":{"grant":STANDARD.encode(SigningKey::from_bytes(&[6;32]).verifying_key().as_bytes())},"outcome_keys":{"outcome":STANDARD.encode(SigningKey::from_bytes(&[14;32]).verifying_key().as_bytes())},"collector_id":"collector-test","acknowledgement_key_id":"collector-15","acknowledgement_signing_key_file":p.join("ack-key")});
    let file = p.join("config.json");
    std::fs::write(&file, config.to_string()).unwrap();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-outcomes"))
        .args(["--config", file.to_str().unwrap(), "--check"])
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut bad = config.clone();
    bad["unknown"] = json!(true);
    assert!(
        kedgeflow::outcome_report_config::OutcomeReportConfig::decode(bad.to_string().as_bytes())
            .is_err()
    );
    let mut bad = config;
    bad["outcome_keys"] = bad["grant_keys"].clone();
    let bad =
        kedgeflow::outcome_report_config::OutcomeReportConfig::decode(bad.to_string().as_bytes())
            .unwrap();
    assert!(bad.service().await.is_err());
}

#[tokio::test]
async fn native_collector_shared_replay_survives_service_restart() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    h.shared_auth = true;
    h.restart().await;
    let headers = h.headers("kf.outcome-report", "recovery-service", &h.url);
    let (status, first) = h.send(h.command(0), headers.clone(), false).await;
    assert_eq!(status, 200, "{first}");
    h.restart().await;
    let (status, denied) = h.send(h.command(0), headers, false).await;
    assert_eq!(status, 401, "{denied}");
    let fresh = h.headers("kf.outcome-report", "recovery-service", &h.url);
    let (status, second) = h.send(h.command(0), fresh, false).await;
    assert_eq!(status, 200, "{second}");
    assert!(first["acknowledgement"].is_string());
    assert_eq!(first["acknowledgement"], second["acknowledgement"]);
}
