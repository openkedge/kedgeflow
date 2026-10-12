//! Native verified TLS and etcd, generated keys and a reference target credential.
#[path = "support/domain.rs"]
mod domain;
#[path = "support/exchange_identity.rs"]
mod identity;
mod support;
use async_trait::async_trait;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use identity::{AUDIENCE, Fixture, NOW};
use kedgeflow::{
    broker::{CredentialBroker, Rfc8693Broker, WorkloadAssertion},
    broker_authorization::{
        BrokerAuthorizer, BrokerRegistration, ExchangeIdentityProvider, ExchangePermit,
    },
    broker_service::{BrokerService, decode_exchange},
    clock::Clock,
    contracts::{GrantVerifier, sign_grant},
    error::{Error, Result},
    gateway::VerifiedCall,
    ledger::{AuthorityLedger, EtcdLedger},
    recovery::ExecutionRecord,
    target_token::{ReferenceTokenMinter, TargetTokenMinter, TargetTokenVerifier, TokenBinding},
    tls,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
const GATEWAY: &str = "spiffe://test/gateway";
struct Time(AtomicI64);
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Assertion(String);
#[async_trait]
impl WorkloadAssertion for Assertion {
    async fn assertion(&self, workload: &str) -> Result<String> {
        assert_eq!(workload, "spiffe://test/agent");
        Ok(self.0.clone())
    }
}
struct Minter {
    real: ReferenceTokenMinter,
    calls: AtomicUsize,
    mode: AtomicU8,
    clock: Arc<Time>,
    entered: Notify,
    release: Notify,
}
#[async_trait]
impl TargetTokenMinter for Minter {
    async fn mint(&self, p: &ExchangePermit, now: i64) -> Result<String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        let mut changed = p.clone();
        match self.mode.load(Ordering::SeqCst) {
            1 => {
                return Err(Error::Unavailable(
                    "synthetic mint failure with token-secret-never-reflect".into(),
                ));
            }
            2 => changed.target_scope = "target:admin".into(),
            3 => changed.expires_at += 1000,
            4 => return Ok("invalid.target.token-secret-never-reflect".into()),
            5 => {
                self.clock.0.store(p.expires_at, Ordering::SeqCst);
            }
            6 => self.release.notified().await,
            _ => (),
        }
        self.real.mint(&changed, now).await
    }
}
struct Harness {
    call: VerifiedCall,
    grants: GrantVerifier,
    ledger: EtcdLedger,
    fixture: Fixture,
    subject: String,
    actor: String,
    clock: Arc<Time>,
    minter: Arc<Minter>,
    pki: Vec<support::Pki>,
    url: String,
    address: std::net::SocketAddr,
    listener: Option<tokio::net::TcpListener>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Harness {
    async fn new(claim: bool) -> Option<Self> {
        Self::new_at(claim, NOW).await
    }
    async fn new_at(claim: bool, now: i64) -> Option<Self> {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(v) => v,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP broker HTTP: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("https://{address}/token");
        let mut fixture = Fixture::new();
        fixture.snapshot.actor_audience = url.clone();
        let delta = now - NOW;
        fixture.snapshot.not_before += delta;
        fixture.snapshot.expires_at += delta;
        for key in &mut fixture.snapshot.subject_keys {
            key.not_before += delta;
            key.expires_at += delta;
        }
        for key in &mut fixture.snapshot.actor_keys {
            key.not_before += delta;
            key.expires_at += delta;
        }
        let mut sc = fixture.subject_claims();
        sc["iat"] = json!(now / 1000);
        sc["exp"] = json!(now / 1000 + 240);
        let subject =
            fixture.subject_token(json!({"alg":"EdDSA","typ":"at+jwt","kid":"subject-1"}), sc);
        let mut ac = fixture.actor_claims();
        ac["aud"] = json!(url);
        ac["iat"] = json!(now / 1000);
        ac["exp"] = json!(now / 1000 + 200);
        let actor = fixture.actor_token(json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}), ac);
        let verified = fixture
            .provider()
            .verify(&subject, &actor, now)
            .await
            .unwrap();
        let (mut call, grants) = domain::call();
        call.grant.issued_at = now;
        call.grant.valid_from = now;
        call.grant.expires_at = now + 60000;
        call.identity = verified.identity;
        call.grant.subject = call.identity.subject.clone();
        call.grant.workload_id = call.identity.workload_id.clone();
        call.grant.dpop_jkt = call.identity.dpop_jkt.clone();
        call.grant.delegation_digest = call.identity.delegation_digest.clone();
        call.signed_grant =
            sign_grant(&call.grant, "test-key", &SigningKey::from_bytes(&[6; 32])).unwrap();
        call.grant_digest = grants.verify(&call.signed_grant, now).unwrap().digest;
        let clock = Arc::new(Time(AtomicI64::new(now)));
        let ledger = EtcdLedger::new(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            &endpoint,
            format!(
                "/kf-broker-http/{}/{:x}",
                std::process::id(),
                rand::random::<u64>()
            ),
        )
        .unwrap()
        .with_clock(clock.clone());
        ledger.publish_policy(&call.grant).await.unwrap();
        ledger.issue(&call.grant, &call.grant_digest).await.unwrap();
        if claim {
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
        let minter = Arc::new(Minter {
            real: ReferenceTokenMinter::new(
                url.clone(),
                "target-1".into(),
                SigningKey::from_bytes(&[11; 32]),
            )
            .unwrap(),
            calls: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
            clock: clock.clone(),
            entered: Notify::new(),
            release: Notify::new(),
        });
        Some(Self {
            call,
            grants,
            ledger,
            fixture,
            subject,
            actor,
            clock,
            minter,
            pki: support::pki_for_workloads(&[GATEWAY, "spiffe://test/agent"]),
            url,
            address,
            listener: Some(listener),
            task: None,
        })
    }
    fn registration(&self) -> BrokerRegistration {
        BrokerRegistration {
            gateway_workload: GATEWAY.into(),
            target_audience: "urn:test:target".into(),
            target_scope: "target:update".into(),
            max_lifetime_ms: 20000,
            tool: self.call.descriptor.clone(),
        }
    }
    fn verifier(&self) -> TargetTokenVerifier {
        TargetTokenVerifier::new(
            self.url.clone(),
            BTreeMap::from([(
                "target-1".into(),
                SigningKey::from_bytes(&[11; 32]).verifying_key(),
            )]),
        )
        .unwrap()
    }
    fn service(&self) -> Arc<BrokerService> {
        Arc::new(
            BrokerService::new(
                BrokerAuthorizer::new(
                    self.registration(),
                    self.grants.clone(),
                    self.ledger.clone(),
                    Arc::new(self.fixture.provider()),
                    self.clock.clone(),
                )
                .unwrap(),
                &self.url,
                self.minter.clone(),
                self.verifier(),
                self.clock.clone(),
            )
            .unwrap(),
        )
    }
    async fn start(&mut self) {
        let listener = self.listener.take().unwrap();
        let config = tls::server_config_pem(
            self.pki[0].server.as_bytes(),
            self.pki[0].server_key.as_bytes(),
            self.pki[0].ca.as_bytes(),
        )
        .unwrap();
        let router = self.service().router();
        self.task = Some(tokio::spawn(async move {
            let _ = kedgeflow::server::serve_router(listener, config, router).await;
        }));
    }
    fn client(&self, index: usize, timeout: Duration) -> reqwest::Client {
        tls::pinned_http_client_pem(
            self.pki[index].ca.as_bytes(),
            self.pki[index].client.as_bytes(),
            self.pki[index].client_key.as_bytes(),
            timeout,
        )
        .unwrap()
    }
    fn fields(&self) -> Vec<(String, String)> {
        vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
            ),
            ("subject_token", self.subject.clone()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token".into(),
            ),
            ("actor_token", self.actor.clone()),
            (
                "actor_token_type",
                "urn:ietf:params:oauth:token-type:jwt".into(),
            ),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token".into(),
            ),
            ("audience", "urn:test:target".into()),
            ("scope", "target:update".into()),
            (
                "kedgeflow_grant",
                URL_SAFE_NO_PAD.encode(&self.call.signed_grant),
            ),
            ("kedgeflow_grant_digest", self.call.grant_digest.clone()),
            ("kedgeflow_attempt_id", self.call.attempt_id.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect()
    }
    async fn held(&self) {
        assert!(matches!(
            self.ledger
                .claim(&self.call.grant, &self.call.grant_digest, "replacement")
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
fn encode(fields: &[(String, String)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish()
}
#[test]
fn form_decoder_rejects_duplicates_unknown_missing_and_malformed_encoding() {
    let fields = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", "subject"),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("actor_token", "actor"),
        ("actor_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", "target"),
        ("scope", "target:update"),
        ("kedgeflow_grant", "e30"),
        ("kedgeflow_grant_digest", "digest"),
        ("kedgeflow_attempt_id", "opaque-id"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect::<Vec<_>>();
    let valid = encode(&fields);
    assert_eq!(
        decode_exchange(valid.as_bytes()).unwrap().signed_grant,
        "{}"
    );
    for suffix in [
        "&scope=other",
        "&%73cope=other",
        "&resource=other",
        "&client_id=other",
        "&bad=%zz",
        "&scope=%+1",
        "&scope=%ff",
        "&",
        "&scope",
        "&scope=",
    ] {
        assert!(
            decode_exchange(format!("{valid}{suffix}").as_bytes()).is_err(),
            "{suffix}"
        );
    }
    assert!(
        decode_exchange(
            valid
                .replacen("subject_token=subject", "subject_token=%+1", 1)
                .as_bytes()
        )
        .is_err()
    );
    for i in 0..fields.len() {
        let mut changed = fields.clone();
        changed.remove(i);
        assert!(decode_exchange(encode(&changed).as_bytes()).is_err());
    }
    for key in [
        "grant_type",
        "subject_token_type",
        "actor_token_type",
        "requested_token_type",
        "kedgeflow_grant",
    ] {
        let mut changed = fields.clone();
        changed.iter_mut().find(|(k, _)| k == key).unwrap().1 = "wrong".into();
        assert!(
            decode_exchange(encode(&changed).as_bytes()).is_err(),
            "{key}"
        );
    }
    assert!(decode_exchange(&vec![b'x'; (2 << 20) + 1]).is_err());
}
#[tokio::test]
async fn shipped_client_exchanges_verified_tokens_for_exact_target_credential() {
    let Some(mut h) = Harness::new(true).await else {
        return;
    };
    h.start().await;
    let p = &h.pki[0];
    let client = tls::pinned_client_pem(
        p.ca.as_bytes(),
        p.client.as_bytes(),
        p.client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let broker = Rfc8693Broker::new(
        &h.url,
        "urn:test:target".into(),
        "target:update".into(),
        client,
        Arc::new(Assertion(h.actor.clone())),
        h.clock.clone(),
        Duration::from_secs(5),
    )
    .unwrap();
    let credential = broker
        .exchange(
            &h.call,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    let binding = TokenBinding {
        grant_digest: h.call.grant_digest.clone(),
        root_id: h.call.grant.root_id.clone(),
        attempt_id: h.call.attempt_id.clone(),
        gateway_workload: GATEWAY.into(),
        audience: "urn:test:target".into(),
        scope: "target:update".into(),
        max_expires_at: h.call.grant.expires_at,
    };
    let claims = h
        .verifier()
        .verify(&credential.token, &binding, NOW)
        .unwrap();
    assert_eq!(claims.exp * 1000, NOW + 20000);
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 1);
    assert!(
        broker
            .exchange(
                &h.call,
                tokio::time::Instant::now() + Duration::from_secs(5)
            )
            .await
            .is_err()
    );
    h.held().await;
}
#[tokio::test]
async fn native_gateway_identity_and_endpoint_carriage_refuse_before_mint() {
    let Some(mut h) = Harness::new(true).await else {
        return;
    };
    h.start().await;
    let client = h.client(0, Duration::from_secs(5));
    let fields = h.fields();
    let wrong = h
        .client(1, Duration::from_secs(5))
        .post(&h.url)
        .form(&fields)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    for response in [
        client.get(&h.url).send().await.unwrap(),
        client
            .post(format!("{}?x=1", h.url))
            .form(&fields)
            .send()
            .await
            .unwrap(),
        client
            .post(&h.url)
            .header("origin", "https://browser.test")
            .form(&fields)
            .send()
            .await
            .unwrap(),
        client
            .post(&h.url)
            .header("host", "wrong.test")
            .form(&fields)
            .send()
            .await
            .unwrap(),
        client.post(&h.url).json(&json!({})).send().await.unwrap(),
    ] {
        assert!(!response.status().is_success());
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 0);
    h.held().await;
}
#[tokio::test]
async fn native_bad_form_and_invalid_identity_or_target_never_mint() {
    let Some(mut h) = Harness::new(true).await else {
        return;
    };
    h.start().await;
    let client = h.client(0, Duration::from_secs(5));
    let body = format!("{}&%73cope=target:admin", encode(&h.fields()));
    let response = client
        .post(&h.url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    for key in [
        "subject_token",
        "actor_token",
        "audience",
        "scope",
        "kedgeflow_attempt_id",
        "kedgeflow_grant_digest",
    ] {
        let mut fields = h.fields();
        fields.iter_mut().find(|(k, _)| k == key).unwrap().1 = "wrong-secret-never-reflect".into();
        let response = client.post(&h.url).form(&fields).send().await.unwrap();
        assert!(!response.status().is_success());
        let raw = response.text().await.unwrap();
        assert!(!raw.contains("secret"));
    }
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 0);
    h.held().await;
}
#[tokio::test]
async fn native_unclaimed_execution_never_mints() {
    let Some(mut h) = Harness::new(false).await else {
        return;
    };
    h.start().await;
    let r = h
        .client(0, Duration::from_secs(5))
        .post(&h.url)
        .form(&h.fields())
        .send()
        .await
        .unwrap();
    assert!(!r.status().is_success());
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn concurrent_exchange_and_recreated_service_invoke_one_mint() {
    let Some(mut h) = Harness::new(true).await else {
        return;
    };
    h.start().await;
    let client = h.client(0, Duration::from_secs(5));
    let fields = h.fields();
    let (a, b) = tokio::join!(
        client.post(&h.url).form(&fields).send(),
        client.post(&h.url).form(&fields).send()
    );
    assert_eq!(
        usize::from(a.unwrap().status().is_success())
            + usize::from(b.unwrap().status().is_success()),
        1
    );
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 1);
    let old = h.task.take().unwrap();
    old.abort();
    let _ = old.await;
    let listener = tokio::net::TcpListener::bind(h.address).await.unwrap();
    h.listener = Some(listener);
    h.start().await;
    assert!(
        !h.client(0, Duration::from_secs(5))
            .post(&h.url)
            .form(&fields)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 1);
    h.held().await;
}
#[tokio::test]
async fn failed_broader_expired_or_invalid_mint_remains_consumed_without_retry() {
    for mode in 1..=5 {
        let Some(mut h) = Harness::new(true).await else {
            return;
        };
        h.minter.mode.store(mode, Ordering::SeqCst);
        h.start().await;
        let client = h.client(0, Duration::from_secs(5));
        let fields = h.fields();
        let r = client.post(&h.url).form(&fields).send().await.unwrap();
        assert!(!r.status().is_success(), "mode {mode}");
        let raw = r.text().await.unwrap();
        assert!(!raw.contains("secret"));
        h.clock.0.store(NOW, Ordering::SeqCst);
        h.minter.mode.store(0, Ordering::SeqCst);
        assert!(
            !client
                .post(&h.url)
                .form(&fields)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(h.minter.calls.load(Ordering::SeqCst), 1);
        h.held().await;
    }
}
#[tokio::test]
async fn dropped_client_reply_does_not_cancel_or_repeat_mint() {
    let Some(mut h) = Harness::new(true).await else {
        return;
    };
    h.minter.mode.store(6, Ordering::SeqCst);
    h.start().await;
    let client = h.client(0, Duration::from_millis(1000));
    let url = h.url.clone();
    let fields = h.fields();
    let send = tokio::spawn(async move { client.post(url).form(&fields).send().await });
    tokio::time::timeout(Duration::from_secs(3), h.minter.entered.notified())
        .await
        .unwrap();
    assert!(send.await.unwrap().is_err());
    h.minter.release.notify_one();
    let reply = h
        .client(0, Duration::from_secs(5))
        .post(&h.url)
        .form(&h.fields())
        .send()
        .await
        .unwrap();
    assert!(!reply.status().is_success());
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 1);
    h.held().await;
}
#[tokio::test]
async fn mint_timeout_holds_permit_and_never_calls_provider_again() {
    let Some(mut h) = Harness::new(true).await else {
        return;
    };
    h.minter.mode.store(6, Ordering::SeqCst);
    h.start().await;
    let client = h.client(0, Duration::from_secs(8));
    let r = client.post(&h.url).form(&h.fields()).send().await.unwrap();
    assert_eq!(r.status(), 503);
    h.minter.mode.store(0, Ordering::SeqCst);
    assert!(
        !client
            .post(&h.url)
            .form(&h.fields())
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert_eq!(h.minter.calls.load(Ordering::SeqCst), 1);
    h.held().await;
}
fn permit() -> ExchangePermit {
    ExchangePermit {
        profile: kedgeflow::broker_authorization::PROFILE.into(),
        permit_id: "a".repeat(64),
        registration_digest: "b".repeat(64),
        grant_digest: "c".repeat(64),
        root_id: "root".into(),
        attempt_id: "attempt".into(),
        gateway_workload: GATEWAY.into(),
        target_audience: "urn:test:target".into(),
        target_scope: "target:update".into(),
        authorized_at: NOW,
        expires_at: NOW + 20999,
    }
}
#[tokio::test]
async fn target_verifier_refuses_binding_scope_key_expiry_and_closed_claim_substitution() {
    let p = permit();
    let key = SigningKey::from_bytes(&[11; 32]);
    let minter = ReferenceTokenMinter::new(
        "https://broker.test/token".into(),
        "target-1".into(),
        key.clone(),
    )
    .unwrap();
    let verifier = TargetTokenVerifier::new(
        "https://broker.test/token".into(),
        BTreeMap::from([("target-1".into(), key.verifying_key())]),
    )
    .unwrap();
    let token = minter.mint(&p, NOW).await.unwrap();
    let claims = verifier.verify_permit(&token, &p, NOW).unwrap();
    assert_eq!(claims.exp * 1000, NOW + 20000);
    let binding = TokenBinding::from(&p);
    for field in [
        "attempt", "grant", "root", "gateway", "scope", "audience", "expiry",
    ] {
        let mut b = binding.clone();
        match field {
            "attempt" => b.attempt_id = "other".into(),
            "grant" => b.grant_digest = "d".repeat(64),
            "root" => b.root_id = "other".into(),
            "gateway" => b.gateway_workload = "spiffe://test/other".into(),
            "scope" => b.scope = "other".into(),
            "audience" => b.audience = "other".into(),
            _ => b.max_expires_at = NOW + 19999,
        };
        assert!(verifier.verify(&token, &b, NOW).is_err());
    }
    assert!(verifier.verify(&token, &binding, NOW + 20000).is_err());
    assert!(verifier.verify(&token, &binding, NOW - 1).is_err());
    let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
    parts[2] = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[12; 32])
            .sign(format!("{}.{}", parts[0], parts[1]).as_bytes())
            .to_bytes(),
    );
    assert!(verifier.verify(&parts.join("."), &binding, NOW).is_err());
    let mut value = serde_json::to_value(claims).unwrap();
    value["extra"] = json!(true);
    let input = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    );
    let token = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    );
    assert!(verifier.verify(&token, &binding, NOW).is_err());
    assert!(minter.mint(&p, NOW + 19500).await.is_err());
    assert!(verifier.verify(&"x".repeat(16385), &binding, NOW).is_err());
}
#[tokio::test]
async fn independent_target_and_grant_roles_cannot_overlap() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let verifier = TargetTokenVerifier::new(h.url.clone(), h.grants.keys.clone()).unwrap();
    let authorizer = BrokerAuthorizer::new(
        h.registration(),
        h.grants.clone(),
        h.ledger.clone(),
        Arc::new(h.fixture.provider()),
        h.clock.clone(),
    )
    .unwrap();
    assert!(
        BrokerService::new(
            authorizer,
            &h.url,
            h.minter.clone(),
            verifier,
            h.clock.clone()
        )
        .is_err()
    );
}
#[tokio::test]
async fn shipping_broker_check_validates_material_without_network_authority_use() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let path = |name: &str| temp.path().join(name);
    let mut config = configuration(&h, &temp);
    let run = |config: &Value| {
        std::fs::write(path("config.json"), serde_json::to_vec(config).unwrap()).unwrap();
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-broker"))
            .args(["--config", path("config.json").to_str().unwrap(), "--check"])
            .output()
            .unwrap()
    };
    let out = run(&config);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("no records queried or written"));
    config["allow_unmanaged_fixture"] = json!(false);
    assert!(!run(&config).status.success());
    config["installed_trust_digest"] = json!("a".repeat(64));
    assert!(run(&config).status.success());
    std::fs::write(path("epoch-floor"), "2").unwrap();
    assert!(!run(&config).status.success());
    std::fs::write(path("epoch-floor"), "1").unwrap();
    config["target_verification_keys"]["target-1"] = config["grant_keys"]["test-key"].clone();
    assert!(!run(&config).status.success());
    config["untrusted"] = json!(true);
    assert!(
        kedgeflow::broker_config::BrokerConfig::decode(&serde_json::to_vec(&config).unwrap())
            .is_err()
    );
}

fn configuration(h: &Harness, temp: &tempfile::TempDir) -> Value {
    let path = |name: &str| temp.path().join(name);
    for (name, raw) in [
        ("ca.pem", h.pki[0].ca.clone()),
        ("server.pem", h.pki[0].server.clone()),
        ("server.key", h.pki[0].server_key.clone()),
        ("client.pem", h.pki[0].client.clone()),
        ("client.key", h.pki[0].client_key.clone()),
        ("etcd-token", "protected-software-token".into()),
        ("epoch-floor", "1".into()),
        ("target-key", STANDARD.encode([11; 32])),
    ] {
        std::fs::write(path(name), raw).unwrap();
    }
    std::fs::write(
        path("snapshot.json"),
        serde_json::to_vec(&h.fixture.snapshot).unwrap(),
    )
    .unwrap();
    let config = json!({"listen":h.address,"external_url":h.url,"certificate":path("server.pem"),"private_key":path("server.key"),"workload_ca":path("ca.pem"),"etcd_endpoint":"https://127.0.0.1:1","etcd_prefix":h.ledger.namespace(),"etcd_ca":path("ca.pem"),"etcd_certificate":path("client.pem"),"etcd_private_key":path("client.key"),"etcd_token_file":path("etcd-token"),"gateway_audience":h.grants.audience,"delegation_audience":AUDIENCE,"grant_keys":{"test-key":STANDARD.encode(SigningKey::from_bytes(&[6;32]).verifying_key().as_bytes())},"registration":h.registration(),"identity_snapshot_file":path("snapshot.json"),"identity_epoch_floor_file":path("epoch-floor"),"target_key_id":"target-1","target_signing_key_file":path("target-key"),"target_verification_keys":{"target-1":STANDARD.encode(SigningKey::from_bytes(&[11;32]).verifying_key().as_bytes())},"allow_unmanaged_fixture":true});

    config
}

struct Process(std::process::Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test]
async fn shipping_broker_restart_preserves_one_shot_exchange() {
    let now = kedgeflow::clock::SystemClock.now_ms();
    let Some(mut h) = Harness::new_at(true, now).await else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let mut config = configuration(&h, &temp);
    config["etcd_endpoint"] = json!(std::env::var("ETCD_ENDPOINT").unwrap());
    let file = temp.path().join("config.json");
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    drop(h.listener.take());
    let spawn = || {
        Process(
            std::process::Command::new(env!("CARGO_BIN_EXE_kf-broker"))
                .args(["--config", file.to_str().unwrap()])
                .stdout(std::process::Stdio::null())
                .stderr(std::fs::File::create(temp.path().join("broker.log")).unwrap())
                .spawn()
                .unwrap(),
        )
    };
    let client = h.client(0, Duration::from_secs(3));
    let ready = |mut child: Process| {
        let client = client.clone();
        let url = h.url.clone();
        let log = temp.path().join("broker.log");
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    panic!(
                        "broker exited {status}: {}",
                        std::fs::read_to_string(&log).unwrap()
                    );
                }
                if let Ok(response) = client.get(&url).send().await {
                    assert_eq!(response.status(), 405);
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "broker startup: {}",
                    std::fs::read_to_string(&log).unwrap()
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            child
        }
    };
    let child = ready(spawn()).await;
    let response = client.post(&h.url).form(&h.fields()).send().await.unwrap();
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    let value: Value = response.json().await.unwrap();
    let token = value["access_token"].as_str().unwrap();
    let binding = TokenBinding {
        grant_digest: h.call.grant_digest.clone(),
        root_id: h.call.grant.root_id.clone(),
        attempt_id: h.call.attempt_id.clone(),
        gateway_workload: GATEWAY.into(),
        audience: "urn:test:target".into(),
        scope: "target:update".into(),
        max_expires_at: h.call.grant.expires_at,
    };
    assert!(
        h.verifier()
            .verify(token, &binding, kedgeflow::clock::SystemClock.now_ms())
            .is_ok()
    );
    drop(child);
    let _restarted = ready(spawn()).await;
    let response = client.post(&h.url).form(&h.fields()).send().await.unwrap();
    assert!(!response.status().is_success());
    h.held().await;
}
