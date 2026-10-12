//! Operator-pinned subject/JWT-SVID verification. Refresh authentication and
//! independently retained epoch custody are integration responsibilities.
use crate::{
    auth::{access_token_key_id, valid_spiffe_id, verify_access_token},
    broker_authorization::{ExchangeIdentityProvider, VerifiedExchangeIdentity},
    contracts::strict_value,
    error::{Error, Result},
    shared_auth::{SharedAuthConfig, SubjectWorkload},
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, RwLock},
};

pub const PROFILE: &str = "KF-PINNED-EXCHANGE-IDENTITY-0.1-draft";
const SAFE_MS: i64 = 9_007_199_254_740_991;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectKey {
    pub kid: String,
    /// Base64url without padding, Ed25519 public bytes.
    pub public_key: String,
    pub not_before: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorKey {
    pub kid: String,
    pub trust_domain: String,
    pub alg: String,
    pub r#use: String,
    /// Base64url without padding, uncompressed P-256 SEC1 point.
    pub public_key: String,
    pub not_before: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSnapshot {
    pub profile: String,
    pub epoch: u64,
    pub not_before: i64,
    pub expires_at: i64,
    pub issuer: String,
    pub subject_audience: String,
    pub actor_audience: String,
    pub subject_keys: Vec<SubjectKey>,
    pub actor_keys: Vec<ActorKey>,
    pub registrations: Vec<SubjectWorkload>,
    pub withdrawn_subject_tokens: Vec<String>,
}
fn interval(start: i64, end: i64) -> bool {
    start >= 0 && end <= SAFE_MS && start < end
}
fn name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 2048 && s.is_ascii() && !s.bytes().any(|c| c <= b' ' || c == 127)
}
fn bytes(s: &str, length: usize) -> Result<Vec<u8>> {
    let v = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| invalid("invalid pinned public encoding"))?;
    if v.len() != length || URL_SAFE_NO_PAD.encode(&v) != s {
        return Err(invalid("invalid pinned public key length/encoding"));
    }
    Ok(v)
}
impl TrustSnapshot {
    pub fn validate(&self) -> Result<()> {
        validate_snapshot(&serde_json::to_value(self)?)?;
        if self.profile != PROFILE
            || self.epoch == 0
            || self.epoch > SAFE_MS as u64
            || !interval(self.not_before, self.expires_at)
            || self.expires_at - self.not_before > 300000
            || !name(&self.issuer)
            || !name(&self.subject_audience)
            || !name(&self.actor_audience)
            || !(1..=32).contains(&self.subject_keys.len())
            || !(1..=64).contains(&self.actor_keys.len())
            || self.withdrawn_subject_tokens.len() > 4096
        {
            return Err(invalid("invalid exchange trust snapshot"));
        }
        SharedAuthConfig {
            capacity: 1,
            registrations: self.registrations.clone(),
        }
        .validate(&self.issuer)?;
        let mut subjects = BTreeSet::new();
        for k in &self.subject_keys {
            if !name(&k.kid) || !interval(k.not_before, k.expires_at) || !subjects.insert(&k.kid) {
                return Err(invalid("invalid or duplicate subject key"));
            }
            let raw: [u8; 32] = bytes(&k.public_key, 32)?
                .try_into()
                .expect("checked length");
            let key = VerifyingKey::from_bytes(&raw)
                .map_err(|_| invalid("invalid Ed25519 subject key"))?;
            if key.is_weak() {
                return Err(invalid("weak Ed25519 subject key"));
            }
        }
        let mut actors = BTreeSet::new();
        for k in &self.actor_keys {
            if !name(&k.kid)
                || !valid_spiffe_id(&format!("spiffe://{}", k.trust_domain))
                || k.trust_domain.contains('/')
                || k.alg != "ES256"
                || k.r#use != "jwt-svid"
                || !interval(k.not_before, k.expires_at)
                || !actors.insert((&k.trust_domain, &k.kid))
            {
                return Err(invalid("invalid or duplicate actor key"));
            }
            if bytes(&k.public_key, 65)?[0] != 4 {
                return Err(invalid("uncompressed P-256 key required"));
            }
            // ring checks that the point is on the curve during signature verification.
        }
        let mut withdrawn = BTreeSet::new();
        for d in &self.withdrawn_subject_tokens {
            if d.len() != 64
                || !d
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || !withdrawn.insert(d)
            {
                return Err(invalid("invalid or duplicate withdrawn token digest"));
            }
        }
        Ok(())
    }
}
pub fn validate_snapshot(v: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let s = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/exchange-identity-v0.1.schema.json"
            ))
            .expect("embedded exchange identity schema"),
        )
        .expect("valid exchange identity schema")
    });
    if !s.is_valid(v) {
        return Err(invalid("closed exchange trust snapshot mismatch"));
    }
    Ok(())
}
#[derive(Clone)]
pub struct PinnedExchangeIdentityProvider {
    snapshot: Arc<RwLock<TrustSnapshot>>,
}
impl PinnedExchangeIdentityProvider {
    /// The minimum epoch must come from independently retained trusted custody.
    pub fn new(snapshot: TrustSnapshot, minimum_epoch: u64) -> Result<Self> {
        snapshot.validate()?;
        if minimum_epoch == 0 || snapshot.epoch < minimum_epoch {
            return Err(refused("exchange trust epoch below retained floor"));
        }
        Ok(Self {
            snapshot: Arc::new(RwLock::new(snapshot)),
        })
    }
    /// Parse protected configuration without collapsing duplicate JSON fields.
    pub fn from_json(raw: &[u8], minimum_epoch: u64) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(invalid("exchange trust snapshot exceeds bound"));
        }
        let value = strict_value(raw)?;
        validate_snapshot(&value)?;
        let snapshot = serde_json::from_value(value)
            .map_err(|_| invalid("invalid exchange trust snapshot"))?;
        Self::new(snapshot, minimum_epoch)
    }
    /// Trusted administration only. Validate completely before atomic replacement.
    pub fn replace(&self, next: TrustSnapshot) -> Result<()> {
        next.validate()?;
        let mut current = self.snapshot.write().map_err(|_| unavailable())?;
        if next.epoch <= current.epoch
            || next.not_before < current.not_before
            || next.issuer != current.issuer
            || next.subject_audience != current.subject_audience
            || next.actor_audience != current.actor_audience
        {
            return Err(refused("exchange trust rollback or realm change"));
        }
        *current = next;
        Ok(())
    }
    fn verify_at(
        &self,
        subject: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<VerifiedExchangeIdentity> {
        if !(0..=SAFE_MS).contains(&now_ms) {
            return Err(refused("invalid provider clock"));
        }
        if subject.len() > 16384 || actor.len() > 16384 {
            return Err(refused("exchange JWT exceeds profile bound"));
        }
        let s = self.snapshot.read().map_err(|_| unavailable())?;
        if now_ms < s.not_before || now_ms >= s.expires_at {
            return Err(refused("exchange trust snapshot is not fresh"));
        }
        let token_digest = hex::encode(Sha256::digest(subject.as_bytes()));
        if s.withdrawn_subject_tokens.contains(&token_digest) {
            return Err(refused("subject token withdrawn"));
        }
        let kid = access_token_key_id(subject)?;
        let key = s
            .subject_keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| refused("subject signing key not enrolled"))?;
        if now_ms < key.not_before || now_ms >= key.expires_at {
            return Err(refused("subject key outside acceptance interval"));
        }
        let raw: [u8; 32] = bytes(&key.public_key, 32)?
            .try_into()
            .expect("validated key length");
        let public = VerifyingKey::from_bytes(&raw).map_err(|_| invalid("invalid subject key"))?;
        let access = verify_access_token(
            subject,
            &s.issuer,
            &s.subject_audience,
            &public,
            now_ms / 1000,
        )?;
        let (head, claims, input, sig) = actor_jwt(actor)?;
        if head.alg != "ES256" || head.typ.as_ref().is_some_and(|t| t != "JWT" && t != "JOSE") {
            return Err(refused("unsupported JWT-SVID header"));
        }
        if !valid_spiffe_id(&claims.sub)
            || !claims.aud.matches(&s.actor_audience)
            || claims.exp <= now_ms / 1000
            || claims.exp > SAFE_MS / 1000
            || claims
                .iat
                .is_some_and(|t| t < 0 || t > now_ms / 1000 || t >= claims.exp)
            || claims
                .nbf
                .is_some_and(|t| t < 0 || t > now_ms / 1000 || t >= claims.exp)
        {
            return Err(refused("invalid JWT-SVID identity/audience/time"));
        }
        let domain = claims
            .sub
            .strip_prefix("spiffe://")
            .expect("validated SPIFFE ID")
            .split('/')
            .next()
            .expect("SPIFFE domain");
        let actor_key = s
            .actor_keys
            .iter()
            .find(|k| k.kid == head.kid && k.trust_domain == domain)
            .ok_or_else(|| refused("JWT-SVID key/domain not enrolled"))?;
        if now_ms < actor_key.not_before || now_ms >= actor_key.expires_at {
            return Err(refused("actor key outside acceptance interval"));
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, bytes(&actor_key.public_key, 65)?)
            .verify(input.as_bytes(), &sig)
            .map_err(|_| refused("invalid JWT-SVID signature"))?;
        let identity = access.identity(subject, &claims.sub)?;
        let jkt = URL_SAFE_NO_PAD
            .decode(&identity.dpop_jkt)
            .map_err(|_| refused("invalid subject confirmation thumbprint"))?;
        if jkt.len() != 32 || URL_SAFE_NO_PAD.encode(&jkt) != identity.dpop_jkt {
            return Err(refused("invalid subject confirmation thumbprint"));
        }
        if !s.registrations.iter().any(|r| {
            r.subject == identity.subject
                && r.workload_id == identity.workload_id
                && identity.scopes.is_subset(&r.allowed_scopes)
        }) {
            return Err(refused("subject/workload/scope is not registered"));
        }
        Ok(VerifiedExchangeIdentity {
            identity,
            subject_valid_until: access.expires_at().min(key.expires_at).min(s.expires_at),
            actor_valid_until: (claims.exp * 1000)
                .min(actor_key.expires_at)
                .min(s.expires_at),
        })
    }
}
#[async_trait]
impl ExchangeIdentityProvider for PinnedExchangeIdentityProvider {
    async fn verify(
        &self,
        subject_token: &str,
        actor_token: &str,
        now_ms: i64,
    ) -> Result<VerifiedExchangeIdentity> {
        self.verify_at(subject_token, actor_token, now_ms)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorHeader {
    alg: String,
    kid: String,
    #[serde(default, deserialize_with = "present_string")]
    typ: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    List(Vec<String>),
}
impl Audience {
    fn matches(&self, expected: &str) -> bool {
        match self {
            Self::One(v) => v == expected,
            Self::List(v) => v.len() == 1 && v[0] == expected,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorClaims {
    sub: String,
    aud: Audience,
    exp: i64,
    #[serde(default, deserialize_with = "present_integer")]
    iat: Option<i64>,
    #[serde(default, deserialize_with = "present_integer")]
    nbf: Option<i64>,
}
fn present_integer<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<i64>, D::Error> {
    i64::deserialize(d).map(Some)
}
fn present_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn actor_jwt(token: &str) -> Result<(ActorHeader, ActorClaims, String, Vec<u8>)> {
    if token.len() > 16384 {
        return Err(refused("JWT-SVID exceeds profile bound"));
    }
    let p: Vec<_> = token.split('.').collect();
    if p.len() != 3 || p.iter().any(|s| s.is_empty()) {
        return Err(refused("invalid JWT-SVID framing"));
    }
    let decode = |v| {
        URL_SAFE_NO_PAD
            .decode(v)
            .map_err(|_| refused("invalid JWT-SVID encoding"))
    };
    let head = serde_json::from_value(strict_value(&decode(p[0])?)?)
        .map_err(|_| refused("invalid closed JWT-SVID header"))?;
    let claims = serde_json::from_value(strict_value(&decode(p[1])?)?)
        .map_err(|_| refused("invalid closed JWT-SVID claims"))?;
    let sig = decode(p[2])?;
    if sig.len() != 64 {
        return Err(refused("invalid ES256 signature length"));
    }
    Ok((head, claims, format!("{}.{}", p[0], p[1]), sig))
}
fn invalid(s: &str) -> Error {
    Error::Invalid(s.into())
}
fn refused(s: &str) -> Error {
    Error::Refused(s.into())
}
fn unavailable() -> Error {
    Error::Unavailable("exchange trust lock poisoned".into())
}
