//! Reusable generated software identity keys, not provider qualification.
#![allow(dead_code)]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    auth::WorkloadIdentity,
    contracts::{Subject, canonical},
    exchange_identity::{
        ActorKey, PROFILE, PinnedExchangeIdentityProvider, SubjectKey, TrustSnapshot,
    },
    shared_auth::SubjectWorkload,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub const NOW: i64 = 1_800_000_000_000;
pub const ISSUER: &str = "https://identity.test";
pub const AUDIENCE: &str = "https://gateway.test/mcp";
pub const ACTOR_AUDIENCE: &str = "https://broker.test/exchange";
pub const AGENT: &str = "spiffe://test/agent";
pub struct Fixture {
    pub subject: SigningKey,
    pub actor: EcdsaKeyPair,
    pub proof: SigningKey,
    pub snapshot: TrustSnapshot,
}
pub fn compact(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    )
}
pub fn workload(uri: &str) -> WorkloadIdentity {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    let c = p.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
    WorkloadIdentity::from_verified_cert_der(c.der()).unwrap()
}
impl Fixture {
    pub fn new() -> Self {
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
    pub fn provider(&self) -> PinnedExchangeIdentityProvider {
        PinnedExchangeIdentityProvider::new(self.snapshot.clone(), 1).unwrap()
    }
    pub fn jwk(&self) -> Value {
        json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(self.proof.verifying_key().as_bytes())})
    }
    pub fn subject_claims(&self) -> Value {
        json!({"iss":ISSUER,"sub":"user","aud":AUDIENCE,"exp":NOW/1000+240,"iat":NOW/1000,"scope":"read mutate kf.status","cnf":{"jkt":URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&self.jwk()).unwrap()))}})
    }
    pub fn actor_claims(&self) -> Value {
        json!({"sub":AGENT,"aud":ACTOR_AUDIENCE,"exp":NOW/1000+200,"iat":NOW/1000})
    }
    pub fn subject_token(&self, header: Value, claims: Value) -> String {
        let input = compact(&header, &claims);
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(self.subject.sign(input.as_bytes()).to_bytes())
        )
    }
    pub fn actor_token(&self, header: Value, claims: Value) -> String {
        let input = compact(&header, &claims);
        self.actor_input(&input)
    }
    pub fn actor_input(&self, input: &str) -> String {
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
    pub fn tokens(&self) -> (String, String) {
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
