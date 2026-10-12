//! Authorization prerequisite only: real etcd, software provider identities,
//! no production token mint, AS integration or target credential assertion.
#[path = "support/domain.rs"]
mod domain;
mod support;
use async_trait::async_trait;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use kedgeflow::{
    auth::{Identity, WorkloadIdentity},
    broker_authorization::{
        BrokerAuthorizer, BrokerRegistration, ExchangeIdentityProvider, ExchangeRequest,
        VerifiedExchangeIdentity,
    },
    clock::Clock,
    contracts::GrantVerifier,
    error::{Error, Result},
    gateway::VerifiedCall,
    ledger::{AuthorityLedger, EtcdLedger},
    recovery::ExecutionRecord,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
const NOW: i64 = domain::NOW;
const GATEWAY: &str = "spiffe://test/gateway";
struct Time(AtomicI64);
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Provider {
    identity: Mutex<Identity>,
    subject_expiry: AtomicI64,
    actor_expiry: AtomicI64,
    calls: AtomicUsize,
    fail: AtomicBool,
    advance: AtomicI64,
    clock: Arc<Time>,
}
#[async_trait]
impl ExchangeIdentityProvider for Provider {
    async fn verify(
        &self,
        subject: &str,
        actor: &str,
        _now: i64,
    ) -> Result<VerifiedExchangeIdentity> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst)
            || subject != "caller-token-never-forward"
            || actor != "software-actor"
        {
            return Err(Error::Refused(
                "software provider verification refused".into(),
            ));
        }
        self.clock
            .0
            .fetch_add(self.advance.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(VerifiedExchangeIdentity {
            identity: self.identity.lock().unwrap().clone(),
            subject_valid_until: self.subject_expiry.load(Ordering::SeqCst),
            actor_valid_until: self.actor_expiry.load(Ordering::SeqCst),
        })
    }
}
struct Harness {
    ledger: EtcdLedger,
    call: VerifiedCall,
    grants: GrantVerifier,
    provider: Arc<Provider>,
    clock: Arc<Time>,
    gateway: WorkloadIdentity,
}
impl Harness {
    async fn new(recorded: bool) -> Option<Self> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(v) => v,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP broker: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let (call, grants) = domain::call();
        let clock = Arc::new(Time(AtomicI64::new(NOW)));
        let ledger = EtcdLedger::new(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            &endpoint,
            format!(
                "/kf-broker/{}/{:x}",
                std::process::id(),
                rand::random::<u64>()
            ),
        )
        .unwrap()
        .with_clock(clock.clone());
        ledger.publish_policy(&call.grant).await.unwrap();
        ledger.issue(&call.grant, &call.grant_digest).await.unwrap();
        if recorded {
            ledger
                .claim_recorded(
                    &call.grant,
                    &call.grant_digest,
                    &call.attempt_id,
                    &ExecutionRecord {
                        signed_grant: String::from_utf8(call.signed_grant.clone()).unwrap(),
                        tool: call.descriptor.name.clone(),
                        parameters: call.request.params.arguments.clone(),
                    },
                )
                .await
                .unwrap();
        }
        let provider = Arc::new(Provider {
            identity: Mutex::new(call.identity.clone()),
            subject_expiry: AtomicI64::new(NOW + 45000),
            actor_expiry: AtomicI64::new(NOW + 30000),
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            advance: AtomicI64::new(0),
            clock: clock.clone(),
        });
        let p = support::pki_with_workload(GATEWAY);
        let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(p.client.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        let gateway = WorkloadIdentity::from_verified_cert_der(cert.as_ref()).unwrap();
        Some(Self {
            ledger,
            call,
            grants,
            provider,
            clock,
            gateway,
        })
    }
    fn registration(&self) -> BrokerRegistration {
        BrokerRegistration {
            gateway_workload: GATEWAY.into(),
            target_audience: "urn:test:conditional-target".into(),
            target_scope: "target:update".into(),
            max_lifetime_ms: 20000,
            tool: self.call.descriptor.clone(),
        }
    }
    fn authorizer(&self, ledger: EtcdLedger) -> BrokerAuthorizer {
        BrokerAuthorizer::new(
            self.registration(),
            self.grants.clone(),
            ledger,
            self.provider.clone(),
            self.clock.clone(),
        )
        .unwrap()
    }
    fn request(&self) -> ExchangeRequest {
        ExchangeRequest {
            subject_token: self.call.identity.access_token.clone(),
            actor_token: "software-actor".into(),
            signed_grant: String::from_utf8(self.call.signed_grant.clone()).unwrap(),
            grant_digest: self.call.grant_digest.clone(),
            attempt_id: self.call.attempt_id.clone(),
            audience: self.registration().target_audience,
            scope: self.registration().target_scope,
        }
    }
    fn domain(&self) -> String {
        format!(
            "{}/domains/{}",
            self.ledger.namespace(),
            URL_SAFE_NO_PAD.encode(&self.call.grant.conflict_domain)
        )
    }
    fn root(&self) -> String {
        format!(
            "{}/roots/{}",
            self.domain(),
            URL_SAFE_NO_PAD.encode(&self.call.grant.root_id)
        )
    }
    fn permit_key(&self) -> String {
        format!(
            "{}/attempts/{}/credential-permit",
            self.root(),
            URL_SAFE_NO_PAD.encode(&self.call.attempt_id)
        )
    }
    async fn read(&self, key: &str) -> Option<Vec<u8>> {
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        let r: Value = reqwest::Client::new()
            .post(format!("{endpoint}/v3/kv/range"))
            .json(&json!({"key":STANDARD.encode(key)}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        r["kvs"]
            .as_array()
            .and_then(|v| v.first())
            .map(|v| STANDARD.decode(v["value"].as_str().unwrap()).unwrap())
    }
    async fn put(&self, key: &str, value: &str) {
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        assert!(
            reqwest::Client::new()
                .post(format!("{endpoint}/v3/kv/put"))
                .json(&json!({"key":STANDARD.encode(key),"value":STANDARD.encode(value)}))
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
    }
    async fn held(&self) {
        assert!(matches!(
            self.ledger
                .claim(
                    &self.call.grant,
                    &self.call.grant_digest,
                    "replacement-attempt"
                )
                .await,
            Err(Error::NonceConsumed)
        ));
        assert_eq!(
            self.ledger
                .status(&self.call.grant, &self.call.attempt_id)
                .await
                .unwrap()
                .status,
            "claimed"
        );
    }
}
#[tokio::test]
async fn concurrent_brokers_return_one_permit_and_recreated_broker_refuses() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let request = h.request();
    let a = h.authorizer(h.ledger.clone());
    let b = h.authorizer(h.ledger.clone());
    let (x, y) = tokio::join!(
        a.authorize(&request, &h.gateway),
        b.authorize(&request, &h.gateway)
    );
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    let permit = x.or(y).unwrap();
    assert_eq!(permit.authorized_at, NOW);
    assert_eq!(permit.expires_at, NOW + 20000);
    assert_eq!(permit.attempt_id, h.call.attempt_id);
    assert_eq!(permit.target_scope, "target:update");
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&request, &h.gateway)
            .await
            .is_err()
    );
    let retained = h.read(&h.permit_key()).await.unwrap();
    let v: Value = serde_json::from_slice(&retained).unwrap();
    assert_eq!(v["permit_id"], permit.permit_id);
    let raw = String::from_utf8(retained).unwrap();
    assert!(!raw.contains("caller-token-never-forward") && !raw.contains("software-actor"));
    h.held().await;
}
#[tokio::test]
async fn unclaimed_or_unrecorded_attempt_cannot_authorize_exchange() {
    let Some(h) = Harness::new(false).await else {
        return;
    };
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    h.ledger
        .claim(&h.call.grant, &h.call.grant_digest, &h.call.attempt_id)
        .await
        .unwrap();
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    assert!(h.read(&h.permit_key()).await.is_none());
    h.held().await;
}
#[tokio::test]
async fn gateway_target_and_signed_request_substitutions_refuse() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let p = support::pki_with_workload("spiffe://test/agent");
    let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(p.client.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    let agent = WorkloadIdentity::from_verified_cert_der(cert.as_ref()).unwrap();
    let a = h.authorizer(h.ledger.clone());
    assert!(a.authorize(&h.request(), &agent).await.is_err());
    for mode in 0..7 {
        let mut r = h.request();
        match mode {
            0 => r.audience = "urn:another-target".into(),
            1 => r.scope = "target:update target:admin".into(),
            2 => r.attempt_id = "foreign-attempt".into(),
            3 => r.grant_digest = hex::encode([0u8; 32]),
            4 => r.signed_grant.push('x'),
            5 => r.actor_token = "unverified-actor".into(),
            _ => r.subject_token = "unverified-subject".into(),
        }
        assert!(a.authorize(&r, &h.gateway).await.is_err(), "mode {mode}");
        assert!(h.read(&h.permit_key()).await.is_none());
    }
    h.held().await;
}
#[tokio::test]
async fn verified_identity_substitution_and_expiry_cannot_widen_grant() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let original = h.call.identity.clone();
    for mode in 0..6 {
        let mut id = original.clone();
        match mode {
            0 => id.subject.sub = "other".into(),
            1 => id.workload_id = "spiffe://test/other".into(),
            2 => id.dpop_jkt = "other-key".into(),
            3 => id.delegation_digest = hex::encode([0u8; 32]),
            4 => id.access_token = "another-token".into(),
            _ => {
                id.scopes.clear();
            }
        }
        *h.provider.identity.lock().unwrap() = id;
        assert!(
            h.authorizer(h.ledger.clone())
                .authorize(&h.request(), &h.gateway)
                .await
                .is_err(),
            "mode {mode}"
        );
        assert!(h.read(&h.permit_key()).await.is_none());
    }
    *h.provider.identity.lock().unwrap() = original;
    h.provider.actor_expiry.store(NOW + 999, Ordering::SeqCst);
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    h.provider.actor_expiry.store(i64::MIN, Ordering::SeqCst);
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    h.provider.actor_expiry.store(NOW + 30000, Ordering::SeqCst);
    h.provider.subject_expiry.store(NOW, Ordering::SeqCst);
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    assert!(h.read(&h.permit_key()).await.is_none());
    h.held().await;
}
#[tokio::test]
async fn provider_delay_failure_and_shorter_lifetime_are_enforced() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    h.provider.fail.store(true, Ordering::SeqCst);
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    h.provider.fail.store(false, Ordering::SeqCst);
    h.provider.advance.store(60000, Ordering::SeqCst);
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    assert!(h.read(&h.permit_key()).await.is_none());
    let Some(h) = Harness::new(true).await else {
        return;
    };
    h.provider.actor_expiry.store(NOW + 1234, Ordering::SeqCst);
    let p = h
        .authorizer(h.ledger.clone())
        .authorize(&h.request(), &h.gateway)
        .await
        .unwrap();
    assert_eq!(p.expires_at, NOW + 1234);
    h.held().await;
}
#[tokio::test]
async fn policy_ownership_revocation_dispatch_and_corrupt_execution_refuse() {
    for mode in 0..8 {
        let Some(h) = Harness::new(true).await else {
            return;
        };
        match mode {
            0 => {
                let mut g = h.call.grant.clone();
                g.policy.epoch += 1;
                h.ledger.publish_policy(&g).await.unwrap();
            }
            1 => {
                let mut g = h.call.grant.clone();
                g.ownership_epoch += 1;
                h.ledger.publish_policy(&g).await.unwrap();
            }
            2 => {
                h.put(
                    &format!(
                        "{}/revocations/grants/{}",
                        h.domain(),
                        URL_SAFE_NO_PAD.encode(&h.call.grant.gid)
                    ),
                    "operator-test-revoked",
                )
                .await
            }
            3 => h
                .ledger
                .authorize_dispatch(&h.call.grant, &h.call.grant_digest, &h.call.attempt_id)
                .await
                .unwrap(),
            4 => {
                h.put(
                    &format!(
                        "{}/attempts/{}/execution",
                        h.root(),
                        URL_SAFE_NO_PAD.encode(&h.call.attempt_id)
                    ),
                    "{}",
                )
                .await
            }
            5 => {
                h.put(
                    &format!("{}/restore-gate", h.ledger.namespace()),
                    "required",
                )
                .await
            }
            6 => {
                h.put(
                    &format!("{}/control-required", h.domain()),
                    "KF-ENFORCEMENT-CONTROL-0.1-draft",
                )
                .await
            }
            _ => {
                h.ledger
                    .authorize_dispatch(&h.call.grant, &h.call.grant_digest, &h.call.attempt_id)
                    .await
                    .unwrap();
                let attempt = h
                    .ledger
                    .status(&h.call.grant, &h.call.attempt_id)
                    .await
                    .unwrap();
                h.ledger
                    .finish(&h.call.grant, &attempt, "unknown")
                    .await
                    .unwrap();
            }
        }
        assert!(
            h.authorizer(h.ledger.clone())
                .authorize(&h.request(), &h.gateway)
                .await
                .is_err(),
            "mode {mode}"
        );
        assert!(h.read(&h.permit_key()).await.is_none());
    }
}
struct Fault {
    endpoint: String,
    expire_on_reply: AtomicBool,
    clock: Arc<Time>,
    pause: AtomicBool,
    drop_reply: AtomicBool,
    entered: Notify,
    release: Notify,
}
async fn proxy(State(f): State<Arc<Fault>>, Json(v): Json<Value>) -> (StatusCode, Json<Value>) {
    let permit = v["success"].as_array().unwrap().iter().any(|v| {
        v["request_put"]["key"].as_str().is_some_and(|s| {
            String::from_utf8(STANDARD.decode(s).unwrap())
                .unwrap()
                .ends_with("/credential-permit")
        })
    });
    if permit && f.pause.load(Ordering::SeqCst) {
        f.entered.notify_one();
        f.release.notified().await;
    }
    let reply: Value = reqwest::Client::new()
        .post(format!("{}/v3/kv/txn", f.endpoint))
        .json(&v)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    if permit && f.expire_on_reply.load(Ordering::SeqCst) {
        f.clock.0.store(NOW + 60000, Ordering::SeqCst);
    }
    (
        if permit && f.drop_reply.load(Ordering::SeqCst) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        },
        Json(reply),
    )
}
async fn fault_ledger(h: &Harness) -> (EtcdLedger, Arc<Fault>, tokio::task::JoinHandle<()>) {
    let f = Arc::new(Fault {
        endpoint: std::env::var("ETCD_ENDPOINT").unwrap(),
        expire_on_reply: AtomicBool::new(false),
        clock: h.clock.clone(),
        pause: AtomicBool::new(false),
        drop_reply: AtomicBool::new(false),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/v3/kv/txn", post(proxy))
        .with_state(f.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (
        EtcdLedger::new(reqwest::Client::new(), &endpoint, h.ledger.namespace())
            .unwrap()
            .with_clock(h.clock.clone()),
        f,
        task,
    )
}
#[tokio::test]
async fn lost_permit_reply_and_ledger_outage_never_authorize_retry() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (l, f, task) = fault_ledger(&h).await;
    f.drop_reply.store(true, Ordering::SeqCst);
    assert!(
        h.authorizer(l)
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    assert!(h.read(&h.permit_key()).await.is_some());
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
    h.held().await;
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let l = EtcdLedger::new(
        reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap(),
        &dead,
        h.ledger.namespace(),
    )
    .unwrap();
    assert!(
        h.authorizer(l)
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    assert!(h.read(&h.permit_key()).await.is_none());
    h.held().await;
}
#[tokio::test]
async fn revocation_after_snapshot_wins_permit_cas() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (l, f, task) = fault_ledger(&h).await;
    f.pause.store(true, Ordering::SeqCst);
    let a = h.authorizer(l);
    let r = h.request();
    let gateway = h.gateway.clone();
    let pending = tokio::spawn(async move { a.authorize(&r, &gateway).await });
    tokio::time::timeout(Duration::from_secs(3), f.entered.notified())
        .await
        .unwrap();
    h.put(
        &format!(
            "{}/revocations/roots/{}",
            h.domain(),
            URL_SAFE_NO_PAD.encode(&h.call.grant.root_id)
        ),
        "operator-test-revoked",
    )
    .await;
    f.release.notify_one();
    assert!(pending.await.unwrap().is_err());
    assert!(h.read(&h.permit_key()).await.is_none());
    task.abort();
    let _ = task.await;
}
#[test]
fn broker_permit_and_registration_are_closed() {
    let (call, _) = domain::call();
    let mut r = BrokerRegistration {
        gateway_workload: GATEWAY.into(),
        target_audience: "urn:test:target".into(),
        target_scope: "target:update".into(),
        max_lifetime_ms: 20000,
        tool: call.descriptor,
    };
    r.validate().unwrap();
    r.max_lifetime_ms = 999;
    assert!(r.validate().is_err());
    r.max_lifetime_ms = 300001;
    assert!(r.validate().is_err());
    r.max_lifetime_ms = 20000;
    r.target_scope = "target:update target:admin".into();
    assert!(r.validate().is_err());
    assert!(serde_json::from_value::<ExchangeRequest>(json!({"subject_token":"s","actor_token":"a","signed_grant":"g","grant_digest":"d","attempt_id":"i","audience":"a","scope":"s","unknown":true})).is_err());
    assert!(
        kedgeflow::broker_authorization::validate_permit(&json!({"profile":"invented"})).is_err()
    );
}

#[tokio::test]
async fn final_validity_check_refuses_expired_successful_permit_reply() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (l, f, task) = fault_ledger(&h).await;
    f.expire_on_reply.store(true, Ordering::SeqCst);
    let result = h.authorizer(l).authorize(&h.request(), &h.gateway).await;
    assert!(matches!(result,Err(Error::Refused(ref s)) if s.contains("after write")));
    assert!(h.read(&h.permit_key()).await.is_some());
    assert!(
        h.authorizer(h.ledger.clone())
            .authorize(&h.request(), &h.gateway)
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn independent_issuer_pins_and_registered_tool_cannot_be_substituted() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let mut grants = h.grants.clone();
    grants.keys = std::collections::BTreeMap::from([(
        "test-key".into(),
        ed25519_dalek::SigningKey::from_bytes(&[99; 32]).verifying_key(),
    )]);
    let a = BrokerAuthorizer::new(
        h.registration(),
        grants,
        h.ledger.clone(),
        h.provider.clone(),
        h.clock.clone(),
    )
    .unwrap();
    assert!(a.authorize(&h.request(), &h.gateway).await.is_err());
    assert_eq!(h.provider.calls.load(Ordering::SeqCst), 0);
    for mode in 0..4 {
        let mut r = h.registration();
        match mode {
            0 => r.tool.name = "another-tool".into(),
            1 => r.tool.resource.as_mut().unwrap().incarnation = "another-incarnation".into(),
            2 => r.tool.action.as_mut().unwrap().digest = hex::encode([0u8; 32]),
            _ => r.tool.adapter_contract["guard_primitive"] = json!("ETagIfMatch"),
        }
        match BrokerAuthorizer::new(
            r,
            h.grants.clone(),
            h.ledger.clone(),
            h.provider.clone(),
            h.clock.clone(),
        ) {
            Ok(a) => assert!(
                a.authorize(&h.request(), &h.gateway).await.is_err(),
                "mode {mode}"
            ),
            Err(_) => assert_eq!(mode, 3, "unexpected registration refusal"),
        }
        assert!(h.read(&h.permit_key()).await.is_none());
    }
    h.held().await;
}
