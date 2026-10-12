//! Named reference target credential; accepting a token does not establish a
//! target effect, final dispatch approval or target transaction/deduplication.
use crate::{
    broker_authorization::{ExchangePermit, validate_permit},
    contracts::{canonical, strict_value},
    error::{Error, Result},
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub const PROFILE: &str = "KF-TARGET-TOKEN-0.1-draft";
const SAFE_MS: i64 = 9_007_199_254_740_991;
#[async_trait]
pub trait TargetTokenMinter: Send + Sync {
    /// Trusted integration call, once after winning the original permit CAS.
    async fn mint(&self, permit: &ExchangePermit, now_ms: i64) -> Result<String>;
}
#[derive(Clone, Debug)]
pub struct TokenBinding {
    pub grant_digest: String,
    pub root_id: String,
    pub attempt_id: String,
    pub gateway_workload: String,
    pub audience: String,
    pub scope: String,
    pub max_expires_at: i64,
}
impl From<&ExchangePermit> for TokenBinding {
    fn from(p: &ExchangePermit) -> Self {
        Self {
            grant_digest: p.grant_digest.clone(),
            root_id: p.root_id.clone(),
            attempt_id: p.attempt_id.clone(),
            gateway_workload: p.gateway_workload.clone(),
            audience: p.target_audience.clone(),
            scope: p.target_scope.clone(),
            max_expires_at: p.expires_at,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetClaims {
    pub profile: String,
    pub iss: String,
    pub aud: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub permit_id: String,
    pub grant_digest: String,
    pub root_id: String,
    pub attempt_id: String,
    pub gateway_workload: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}
pub struct ReferenceTokenMinter {
    issuer: String,
    kid: String,
    signer: SigningKey,
}
impl ReferenceTokenMinter {
    pub fn new(issuer: String, kid: String, signer: SigningKey) -> Result<Self> {
        crate::endpoint::EndpointPolicy::new(&issuer)?;
        if kid.is_empty() || kid.len() > 1024 {
            return Err(Error::Invalid("invalid target signing key ID".into()));
        }
        Ok(Self {
            issuer,
            kid,
            signer,
        })
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}
#[async_trait]
impl TargetTokenMinter for ReferenceTokenMinter {
    async fn mint(&self, p: &ExchangePermit, now_ms: i64) -> Result<String> {
        validate_permit(&serde_json::to_value(p)?)?;
        if now_ms < p.authorized_at
            || now_ms > SAFE_MS
            || p.expires_at / 1000 * 1000 - now_ms < 1000
        {
            return Err(Error::Refused("target mint validity exhausted".into()));
        }
        let claims = TargetClaims {
            profile: PROFILE.into(),
            iss: self.issuer.clone(),
            aud: p.target_audience.clone(),
            scope: p.target_scope.clone(),
            iat: now_ms / 1000,
            exp: p.expires_at / 1000,
            permit_id: p.permit_id.clone(),
            grant_digest: p.grant_digest.clone(),
            root_id: p.root_id.clone(),
            attempt_id: p.attempt_id.clone(),
            gateway_workload: p.gateway_workload.clone(),
        };
        let value = serde_json::to_value(&claims)?;
        validate_claims(&value)?;
        if claims.exp - claims.iat > 300 {
            return Err(Error::Refused(
                "target mint lifetime exceeds profile".into(),
            ));
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(canonical(
                &json!({"alg":"EdDSA","typ":"kf-target+jwt","kid":self.kid})
            )?),
            URL_SAFE_NO_PAD.encode(canonical(&value)?)
        );
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(self.signer.sign(input.as_bytes()).to_bytes())
        ))
    }
}
pub struct TargetTokenVerifier {
    issuer: String,
    keys: BTreeMap<String, VerifyingKey>,
}
impl TargetTokenVerifier {
    pub fn new(issuer: String, keys: BTreeMap<String, VerifyingKey>) -> Result<Self> {
        crate::endpoint::EndpointPolicy::new(&issuer)?;
        if keys.is_empty()
            || keys.len() > 32
            || keys
                .iter()
                .any(|(id, k)| id.is_empty() || id.len() > 1024 || k.is_weak())
        {
            return Err(Error::Invalid("invalid target verifier keys".into()));
        }
        Ok(Self { issuer, keys })
    }
    pub(crate) fn keys(&self) -> impl Iterator<Item = &VerifyingKey> {
        self.keys.values()
    }
    /// All expected bindings must come from verified target-side request/context.
    pub fn verify(
        &self,
        token: &str,
        expected: &TokenBinding,
        now_ms: i64,
    ) -> Result<TargetClaims> {
        if !(0..=SAFE_MS).contains(&now_ms)
            || !(0..=SAFE_MS).contains(&expected.max_expires_at)
            || token.len() > 16384
        {
            return Err(refused());
        }
        let p: Vec<_> = token.split('.').collect();
        if p.len() != 3 || p.iter().any(|v| v.is_empty()) {
            return Err(refused());
        }
        let decode = |s| URL_SAFE_NO_PAD.decode(s).map_err(|_| refused());
        let header: Header =
            serde_json::from_value(strict_value(&decode(p[0])?)?).map_err(|_| refused())?;
        if header.alg != "EdDSA" || header.typ != "kf-target+jwt" {
            return Err(refused());
        }
        let key = self.keys.get(&header.kid).ok_or_else(refused)?;
        let sig = Signature::from_slice(&decode(p[2])?).map_err(|_| refused())?;
        key.verify_strict(format!("{}.{}", p[0], p[1]).as_bytes(), &sig)
            .map_err(|_| refused())?;
        let value = strict_value(&decode(p[1])?)?;
        validate_claims(&value)?;
        let c: TargetClaims = serde_json::from_value(value)?;
        if c.profile != PROFILE
            || c.iss != self.issuer
            || c.aud != expected.audience
            || c.scope != expected.scope
            || c.grant_digest != expected.grant_digest
            || c.root_id != expected.root_id
            || c.attempt_id != expected.attempt_id
            || c.gateway_workload != expected.gateway_workload
            || !crate::auth::valid_spiffe_id(&c.gateway_workload)
            || c.iat > now_ms / 1000
            || c.iat >= c.exp
            || c.exp - c.iat > 300
            || c.exp * 1000 <= now_ms
            || c.exp * 1000 > expected.max_expires_at
        {
            return Err(refused());
        }
        Ok(c)
    }
    pub fn verify_permit(
        &self,
        token: &str,
        permit: &ExchangePermit,
        now_ms: i64,
    ) -> Result<TargetClaims> {
        validate_permit(&serde_json::to_value(permit)?)?;
        let claims = self.verify(token, &TokenBinding::from(permit), now_ms)?;
        if claims.permit_id != permit.permit_id || claims.iat < permit.authorized_at / 1000 {
            return Err(refused());
        }
        Ok(claims)
    }
}
pub fn validate_claims(v: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let s = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/target-token-v0.1.schema.json"
            ))
            .expect("embedded target token schema"),
        )
        .expect("valid target token schema")
    });
    if !s.is_valid(v) {
        return Err(Error::Invalid("closed target token claims mismatch".into()));
    }
    Ok(())
}
fn refused() -> Error {
    Error::Refused("target credential binding/signature/time mismatch".into())
}
