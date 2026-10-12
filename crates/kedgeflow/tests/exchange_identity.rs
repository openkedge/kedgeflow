//! Software keys with real signatures; these are not enterprise provider evidence.
#[path = "support/domain.rs"]
mod domain;
use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    auth::{DualAuthenticator, WorkloadIdentity},
    broker_authorization::{
        BrokerAuthorizer, BrokerRegistration, ExchangeIdentityProvider, ExchangeRequest,
    },
    clock::Clock,
    contracts::{Subject, canonical, sign_grant},
    exchange_identity::{
        ActorKey, PROFILE, PinnedExchangeIdentityProvider, SubjectKey, TrustSnapshot,
        validate_snapshot,
    },
    ledger::{AuthorityLedger, EtcdLedger},
    recovery::ExecutionRecord,
    shared_auth::SubjectWorkload,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
const NOW: i64 = domain::NOW;
const ISSUER: &str = "https://identity.test";
const AUDIENCE: &str = "https://gateway.test/mcp";
const ACTOR_AUDIENCE: &str = "https://broker.test/exchange";
const AGENT: &str = "spiffe://test/agent";
struct Fixture {
    subject: SigningKey,
    actor: EcdsaKeyPair,
    proof: SigningKey,
    snapshot: TrustSnapshot,
}
fn compact(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    )
}
fn workload(uri: &str) -> WorkloadIdentity {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    let c = p.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
    WorkloadIdentity::from_verified_cert_der(c.der()).unwrap()
}
impl Fixture {
    fn new() -> Self {
        let subject = SigningKey::from_bytes(&[3; 32]);
        let proof = SigningKey::from_bytes(&[7; 32]);
        let rng = SystemRandom::new();
        let pkcs = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let actor = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs.as_ref(), &rng)
            .unwrap();
        let snapshot = TrustSnapshot {
            profile: PROFILE.into(),
            epoch: 1,
            not_before: NOW,
            expires_at: NOW + 120000,
            issuer: ISSUER.into(),
            subject_audience: AUDIENCE.into(),
            actor_audience: ACTOR_AUDIENCE.into(),
            subject_keys: vec![SubjectKey {
                kid: "subject-1".into(),
                public_key: URL_SAFE_NO_PAD.encode(subject.verifying_key().as_bytes()),
                not_before: NOW,
                expires_at: NOW + 300000,
            }],
            actor_keys: vec![ActorKey {
                kid: "actor-1".into(),
                trust_domain: "test".into(),
                alg: "ES256".into(),
                r#use: "jwt-svid".into(),
                public_key: URL_SAFE_NO_PAD.encode(actor.public_key().as_ref()),
                not_before: NOW,
                expires_at: NOW + 300000,
            }],
            registrations: vec![SubjectWorkload {
                subject: Subject {
                    iss: ISSUER.into(),
                    sub: "user".into(),
                },
                workload_id: AGENT.into(),
                allowed_scopes: BTreeSet::from([
                    "mutate".into(),
                    "read".into(),
                    "kf.status".into(),
                ]),
            }],
            withdrawn_subject_tokens: vec![],
        };
        Self {
            subject,
            actor,
            proof,
            snapshot,
        }
    }
    fn provider(&self) -> PinnedExchangeIdentityProvider {
        PinnedExchangeIdentityProvider::new(self.snapshot.clone(), 1).unwrap()
    }
    fn jwk(&self) -> Value {
        json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(self.proof.verifying_key().as_bytes())})
    }
    fn subject_claims(&self) -> Value {
        json!({"iss":ISSUER,"sub":"user","aud":AUDIENCE,"exp":NOW/1000+240,"iat":NOW/1000,"scope":"read mutate kf.status","cnf":{"jkt":URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&self.jwk()).unwrap()))}})
    }
    fn actor_claims(&self) -> Value {
        json!({"sub":AGENT,"aud":ACTOR_AUDIENCE,"exp":NOW/1000+200,"iat":NOW/1000})
    }
    fn subject_token(&self, header: Value, claims: Value) -> String {
        let input = compact(&header, &claims);
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(self.subject.sign(input.as_bytes()).to_bytes())
        )
    }
    fn actor_token(&self, header: Value, claims: Value) -> String {
        let input = compact(&header, &claims);
        self.actor_input(&input)
    }
    fn actor_input(&self, input: &str) -> String {
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(
                self.actor
                    .sign(&SystemRandom::new(), input.as_bytes())
                    .unwrap()
                    .as_ref()
            )
        )
    }
    fn tokens(&self) -> (String, String) {
        (
            self.subject_token(
                json!({"alg":"EdDSA","typ":"at+jwt","kid":"subject-1"}),
                self.subject_claims(),
            ),
            self.actor_token(
                json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),
                self.actor_claims(),
            ),
        )
    }
}
#[tokio::test]
async fn verifies_real_signatures_with_identical_admission_delegation() {
    let f = Fixture::new();
    let (subject, actor) = f.tokens();
    let verified = f.provider().verify(&subject, &actor, NOW).await.unwrap();
    let input = compact(
        &json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":f.jwk()}),
        &json!({"jti":"fresh","htm":"POST","htu":AUDIENCE,"iat":NOW/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(subject.as_bytes()))}),
    );
    let proof = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(f.proof.sign(input.as_bytes()).to_bytes())
    );
    let mut h = HeaderMap::new();
    h.insert(
        "authorization",
        HeaderValue::from_str(&format!("DPoP {subject}")).unwrap(),
    );
    h.insert("dpop", HeaderValue::from_str(&proof).unwrap());
    let admitted = DualAuthenticator::new(
        ISSUER,
        AUDIENCE,
        AUDIENCE,
        f.subject.verifying_key().to_bytes(),
    )
    .unwrap()
    .authenticate_at(&h, &workload(AGENT), NOW / 1000)
    .unwrap();
    assert_eq!(
        verified.identity.delegation_digest,
        admitted.delegation_digest
    );
    assert_eq!(verified.identity.subject, admitted.subject);
    assert_eq!(verified.identity.dpop_jkt, admitted.dpop_jkt);
    assert_eq!(verified.identity.scopes, admitted.scopes);
    assert_eq!(verified.identity.workload_id, AGENT);
    assert_eq!(verified.subject_valid_until, NOW + 120000);
    assert_eq!(verified.actor_valid_until, NOW + 120000);
}
#[tokio::test]
async fn subject_algorithm_signature_issuer_scope_and_confirmation_substitutions_refuse() {
    let f = Fixture::new();
    let (_, actor) = f.tokens();
    let provider = f.provider();
    for field in ["iss", "aud", "sub", "scope", "cnf", "exp", "iat", "unknown"] {
        let mut claims = f.subject_claims();
        match field {
            "scope" => claims[field] = json!("admin"),
            "cnf" => claims[field] = json!({"jkt":"invalid"}),
            "exp" => claims[field] = json!(NOW / 1000),
            "iat" => claims[field] = json!(NOW / 1000 + 6),
            _ => claims[field] = json!("wrong"),
        };
        assert!(
            provider
                .verify(
                    &f.subject_token(
                        json!({"alg":"EdDSA","typ":"at+jwt","kid":"subject-1"}),
                        claims
                    ),
                    &actor,
                    NOW
                )
                .await
                .is_err(),
            "{field}"
        );
    }
    for header in [
        json!({"alg":"none","typ":"at+jwt","kid":"subject-1"}),
        json!({"alg":"EdDSA","typ":"JWT","kid":"subject-1"}),
        json!({"alg":"EdDSA","typ":"at+jwt"}),
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"other"}),
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"subject-1","jwk":f.jwk()}),
    ] {
        assert!(
            provider
                .verify(&f.subject_token(header, f.subject_claims()), &actor, NOW)
                .await
                .is_err()
        );
    }
    let (subject, _) = f.tokens();
    let mut parts = subject.split('.').map(str::to_owned).collect::<Vec<_>>();
    parts[2] = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(
        provider
            .verify(&parts.join("."), &actor, NOW)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn actor_domain_audience_algorithm_and_signature_substitutions_refuse() {
    let f = Fixture::new();
    let (subject, _) = f.tokens();
    let provider = f.provider();
    for field in ["sub", "aud", "exp", "iat", "nbf", "extra"] {
        let mut claims = f.actor_claims();
        match field {
            "sub" => claims[field] = json!("spiffe://foreign/agent"),
            "aud" => claims[field] = json!([ACTOR_AUDIENCE, "other"]),
            "exp" => claims[field] = json!(NOW / 1000),
            "iat" | "nbf" => claims[field] = json!(NOW / 1000 + 1),
            _ => claims[field] = json!(true),
        };
        assert!(
            provider
                .verify(
                    &subject,
                    &f.actor_token(json!({"alg":"ES256","kid":"actor-1"}), claims),
                    NOW
                )
                .await
                .is_err(),
            "{field}"
        );
    }
    for header in [
        json!({"alg":"EdDSA","kid":"actor-1"}),
        json!({"alg":"ES256"}),
        json!({"alg":"ES256","kid":"other"}),
        json!({"alg":"ES256","kid":"actor-1","typ":"at+jwt"}),
        json!({"alg":"ES256","kid":"actor-1","jwk":{}}),
    ] {
        assert!(
            provider
                .verify(&subject, &f.actor_token(header, f.actor_claims()), NOW)
                .await
                .is_err()
        );
    }
    let (_, actor) = f.tokens();
    let mut parts = actor.split('.').map(str::to_owned).collect::<Vec<_>>();
    parts[2] = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(
        provider
            .verify(&subject, &parts.join("."), NOW)
            .await
            .is_err()
    );
    let other = Fixture::new();
    let (_, actor) = other.tokens();
    assert!(provider.verify(&subject, &actor, NOW).await.is_err());
}
#[tokio::test]
async fn single_array_audience_optional_type_and_time_claims_are_supported() {
    let f = Fixture::new();
    let (subject, _) = f.tokens();
    let mut claims = f.actor_claims();
    claims["aud"] = json!([ACTOR_AUDIENCE]);
    claims.as_object_mut().unwrap().remove("iat");
    for header in [
        json!({"alg":"ES256","kid":"actor-1"}),
        json!({"alg":"ES256","kid":"actor-1","typ":"JOSE"}),
    ] {
        assert!(
            f.provider()
                .verify(&subject, &f.actor_token(header, claims.clone()), NOW + 999)
                .await
                .is_ok()
        );
    }
}
#[tokio::test]
async fn freshness_key_intervals_and_expiry_bound_both_credentials() {
    let mut f = Fixture::new();
    f.snapshot.subject_keys[0].expires_at = NOW + 3500;
    f.snapshot.actor_keys[0].expires_at = NOW + 2100;
    let (subject, actor) = f.tokens();
    let provider = f.provider();
    let verified = provider.verify(&subject, &actor, NOW + 999).await.unwrap();
    assert_eq!(verified.subject_valid_until, NOW + 3500);
    assert_eq!(verified.actor_valid_until, NOW + 2100);
    for now in [-1, NOW - 1, NOW + 2100, NOW + 120000, i64::MAX] {
        assert!(provider.verify(&subject, &actor, now).await.is_err());
    }
    let f = Fixture::new();
    let (subject, actor) = f.tokens();
    let mut s = f.snapshot.clone();
    s.subject_keys[0].not_before = NOW + 1;
    assert!(
        PinnedExchangeIdentityProvider::new(s, 1)
            .unwrap()
            .verify(&subject, &actor, NOW)
            .await
            .is_err()
    );
    let mut s = f.snapshot.clone();
    s.actor_keys[0].not_before = NOW + 1;
    assert!(
        PinnedExchangeIdentityProvider::new(s, 1)
            .unwrap()
            .verify(&subject, &actor, NOW)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn overlapping_key_rotation_then_retirement_is_shared_across_clones() {
    let f = Fixture::new();
    let second = Fixture::new();
    let newsubject = SigningKey::from_bytes(&[4; 32]);
    let (old_subject, old_actor) = f.tokens();
    let provider = f.provider();
    let clone = provider.clone();
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    let mut sk = next.subject_keys[0].clone();
    sk.kid = "subject-2".into();
    sk.public_key = URL_SAFE_NO_PAD.encode(newsubject.verifying_key().as_bytes());
    next.subject_keys.push(sk);
    let mut ak = next.actor_keys[0].clone();
    ak.kid = "actor-2".into();
    ak.public_key = URL_SAFE_NO_PAD.encode(second.actor.public_key().as_ref());
    next.actor_keys.push(ak);
    provider.replace(next.clone()).unwrap();
    let input = compact(
        &json!({"alg":"EdDSA","typ":"at+jwt","kid":"subject-2"}),
        &f.subject_claims(),
    );
    let new_subject = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(newsubject.sign(input.as_bytes()).to_bytes())
    );
    let new_actor = second.actor_token(json!({"alg":"ES256","kid":"actor-2"}), f.actor_claims());
    assert!(clone.verify(&old_subject, &old_actor, NOW).await.is_ok());
    assert!(clone.verify(&new_subject, &new_actor, NOW).await.is_ok());
    next.epoch = 3;
    next.subject_keys.remove(0);
    next.actor_keys.remove(0);
    clone.replace(next.clone()).unwrap();
    assert!(
        provider
            .verify(&old_subject, &new_actor, NOW)
            .await
            .is_err()
    );
    assert!(
        provider
            .verify(&new_subject, &old_actor, NOW)
            .await
            .is_err()
    );
    assert!(provider.verify(&new_subject, &new_actor, NOW).await.is_ok());
    assert!(provider.replace(f.snapshot.clone()).is_err());
    assert!(PinnedExchangeIdentityProvider::new(f.snapshot.clone(), 3).is_err());
    assert!(
        PinnedExchangeIdentityProvider::new(next, 3)
            .unwrap()
            .verify(&new_subject, &new_actor, NOW)
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn withdrawn_token_and_workload_registration_refuse_future_verification() {
    let f = Fixture::new();
    let (subject, actor) = f.tokens();
    let provider = f.provider();
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    next.withdrawn_subject_tokens
        .push(hex::encode(Sha256::digest(subject.as_bytes())));
    provider.replace(next).unwrap();
    assert!(provider.verify(&subject, &actor, NOW).await.is_err());
    let mut next = f.snapshot.clone();
    next.epoch = 3;
    next.registrations[0].workload_id = "spiffe://test/other".into();
    provider.replace(next).unwrap();
    assert!(provider.verify(&subject, &actor, NOW).await.is_err());
}
#[tokio::test]
async fn invalid_snapshot_and_realm_updates_leave_current_verification_intact() {
    let f = Fixture::new();
    let (subject, actor) = f.tokens();
    let provider = f.provider();
    for variant in [
        "epoch",
        "issuer",
        "audience",
        "time",
        "duplicate",
        "algorithm",
        "use",
        "domain",
        "weak",
        "withdrawn",
    ] {
        let mut next = f.snapshot.clone();
        next.epoch = 2;
        match variant {
            "epoch" => next.epoch = 1,
            "issuer" => next.issuer = "https://other.test".into(),
            "audience" => next.actor_audience = "other".into(),
            "time" => next.not_before = NOW - 1,
            "duplicate" => next.actor_keys.push(next.actor_keys[0].clone()),
            "algorithm" => next.actor_keys[0].alg = "EdDSA".into(),
            "use" => next.actor_keys[0].r#use = "sig".into(),
            "domain" => next.actor_keys[0].trust_domain = "test/other".into(),
            "weak" => next.subject_keys[0].public_key = URL_SAFE_NO_PAD.encode([0; 32]),
            _ => next.withdrawn_subject_tokens.push("bad".into()),
        };
        assert!(provider.replace(next).is_err(), "{variant}");
        assert!(provider.verify(&subject, &actor, NOW).await.is_ok());
    }
    let mut value = serde_json::to_value(&f.snapshot).unwrap();
    value["admin"] = json!(true);
    assert!(validate_snapshot(&value).is_err());
    assert!(serde_json::from_value::<TrustSnapshot>(value).is_err());
    let mut next = f.snapshot.clone();
    next.expires_at = NOW + 300001;
    assert!(provider.replace(next).is_err());
    assert!(PinnedExchangeIdentityProvider::new(f.snapshot.clone(), 0).is_err());
}
#[tokio::test]
async fn duplicate_json_and_unsafe_token_times_refuse() {
    let f = Fixture::new();
    let (subject, _) = f.tokens();
    let provider = f.provider();
    let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"actor-1","kid":"actor-1"}"#);
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&f.actor_claims()).unwrap());
    assert!(
        provider
            .verify(&subject, &f.actor_input(&format!("{head}.{claims}")), NOW)
            .await
            .is_err()
    );
    let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"actor-1"}"#);
    let claims = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"sub":"{AGENT}","aud":"{ACTOR_AUDIENCE}","exp":1800000200,"exp":1800000200}}"#
    ));
    assert!(
        provider
            .verify(&subject, &f.actor_input(&format!("{head}.{claims}")), NOW)
            .await
            .is_err()
    );
    for value in [json!(i64::MAX), json!(i64::MIN), json!(1.5), Value::Null] {
        let mut claims = f.actor_claims();
        claims["exp"] = value;
        assert!(
            provider
                .verify(
                    &subject,
                    &f.actor_token(json!({"alg":"ES256","kid":"actor-1"}), claims),
                    NOW
                )
                .await
                .is_err()
        );
    }
    assert!(
        provider
            .verify(&subject, &"x".repeat(16385), NOW)
            .await
            .is_err()
    );
}
struct Time;
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        NOW
    }
}
#[tokio::test]
async fn verified_tokens_authorize_only_the_original_real_etcd_claim() {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
            eprintln!("SKIP provider broker: ETCD_ENDPOINT absent");
            return;
        }
    };
    let f = Fixture::new();
    let (subject, actor) = f.tokens();
    let provider = Arc::new(f.provider());
    let verified = provider.verify(&subject, &actor, NOW).await.unwrap();
    let (mut call, grants) = domain::call();
    call.identity = verified.identity;
    call.grant.subject = call.identity.subject.clone();
    call.grant.workload_id = call.identity.workload_id.clone();
    call.grant.dpop_jkt = call.identity.dpop_jkt.clone();
    call.grant.delegation_digest = call.identity.delegation_digest.clone();
    call.signed_grant =
        sign_grant(&call.grant, "test-key", &SigningKey::from_bytes(&[6; 32])).unwrap();
    call.grant_digest = grants.verify(&call.signed_grant, NOW).unwrap().digest;
    let ledger = EtcdLedger::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap(),
        &endpoint,
        format!(
            "/kf-provider/{}/{:x}",
            std::process::id(),
            rand::random::<u64>()
        ),
    )
    .unwrap()
    .with_clock(Arc::new(Time));
    ledger.publish_policy(&call.grant).await.unwrap();
    ledger.issue(&call.grant, &call.grant_digest).await.unwrap();
    let registration = BrokerRegistration {
        gateway_workload: "spiffe://test/gateway".into(),
        target_audience: "urn:test:target".into(),
        target_scope: "target:update".into(),
        max_lifetime_ms: 20000,
        tool: call.descriptor.clone(),
    };
    let a = BrokerAuthorizer::new(
        registration.clone(),
        grants.clone(),
        ledger.clone(),
        provider.clone(),
        Arc::new(Time),
    )
    .unwrap();
    let b = BrokerAuthorizer::new(
        registration.clone(),
        grants,
        ledger.clone(),
        provider.clone(),
        Arc::new(Time),
    )
    .unwrap();
    let req = ExchangeRequest {
        subject_token: subject,
        actor_token: actor,
        signed_grant: String::from_utf8(call.signed_grant).unwrap(),
        grant_digest: call.grant_digest.clone(),
        attempt_id: call.attempt_id.clone(),
        audience: registration.target_audience,
        scope: registration.target_scope,
    };
    let gateway = workload("spiffe://test/gateway");
    assert!(a.authorize(&req, &gateway).await.is_err());
    ledger
        .claim_recorded(
            &call.grant,
            &call.grant_digest,
            &call.attempt_id,
            &ExecutionRecord {
                signed_grant: req.signed_grant.clone(),
                tool: call.descriptor.name,
                parameters: call.request.params.arguments,
            },
        )
        .await
        .unwrap();
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    next.registrations[0].workload_id = "spiffe://test/withdrawn".into();
    provider.replace(next).unwrap();
    assert!(a.authorize(&req, &gateway).await.is_err());
    let mut next = f.snapshot.clone();
    next.epoch = 3;
    provider.replace(next).unwrap();
    let (x, y) = tokio::join!(a.authorize(&req, &gateway), b.authorize(&req, &gateway));
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    let permit = x.or(y).unwrap();
    assert_eq!(permit.expires_at, NOW + 20000);
    assert!(a.authorize(&req, &gateway).await.is_err());
    assert!(
        ledger
            .claim(&call.grant, &call.grant_digest, "replacement")
            .await
            .is_err()
    );
    assert_eq!(
        ledger
            .status(&call.grant, &call.attempt_id)
            .await
            .unwrap()
            .status,
        "claimed"
    );
}

#[test]
fn closed_snapshot_loader_rejects_duplicate_fields_and_retained_epoch_rollback() {
    let f = Fixture::new();
    let raw = serde_json::to_vec(&f.snapshot).unwrap();
    assert!(PinnedExchangeIdentityProvider::from_json(&raw, 1).is_ok());
    assert!(PinnedExchangeIdentityProvider::from_json(&raw, 2).is_err());
    let duplicate =
        String::from_utf8(raw)
            .unwrap()
            .replacen("\"epoch\":1", "\"epoch\":1,\"epoch\":1", 1);
    assert!(PinnedExchangeIdentityProvider::from_json(duplicate.as_bytes(), 1).is_err());
    assert!(PinnedExchangeIdentityProvider::from_json(&vec![b' '; (1 << 20) + 1], 1).is_err());
}
#[tokio::test]
async fn present_null_optional_actor_fields_refuse() {
    let f = Fixture::new();
    let (subject, _) = f.tokens();
    for field in ["iat", "nbf"] {
        let mut claims = f.actor_claims();
        claims[field] = Value::Null;
        let actor = f.actor_token(json!({"alg":"ES256","kid":"actor-1"}), claims);
        assert!(f.provider().verify(&subject, &actor, NOW).await.is_err());
    }
    let actor = f.actor_token(
        json!({"alg":"ES256","kid":"actor-1","typ":null}),
        f.actor_claims(),
    );
    assert!(f.provider().verify(&subject, &actor, NOW).await.is_err());
}
#[test]
fn concurrent_same_epoch_updates_have_one_winner() {
    let f = Fixture::new();
    let provider = f.provider();
    let barrier = std::sync::Barrier::new(2);
    let mut next = f.snapshot.clone();
    next.epoch = 2;
    let wins = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            provider.replace(next.clone()).is_ok()
        });
        let b = scope.spawn(|| {
            barrier.wait();
            provider.replace(next.clone()).is_ok()
        });
        usize::from(a.join().unwrap()) + usize::from(b.join().unwrap())
    });
    assert_eq!(wins, 1);
    assert!(provider.replace(next).is_err());
}
