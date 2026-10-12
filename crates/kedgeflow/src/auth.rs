//! Narrow pinned-Ed25519 OAuth/DPoP authentication and an independently verified
//! SPIFFE workload context. Authentication is not human transaction approval.
//! This module never treats caller identity headers as workload authentication.
use crate::{
    contracts::{Subject, digest, strict_value},
    error::{Error, Result},
};
use async_trait::async_trait;
use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

const MAX_JWT_BYTES: usize = 16 * 1024;
const DEFAULT_REPLAY_CAPACITY: usize = 16_384;
const PROOF_WINDOW_SECONDS: i64 = 60;
const FUTURE_SKEW_SECONDS: i64 = 5;
const REPLAY_TTL_SECONDS: i64 = PROOF_WINDOW_SECONDS + FUTURE_SKEW_SECONDS + 1;
const SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: Subject,
    pub workload_id: String,
    pub dpop_jkt: String,
    pub delegation_digest: String,
    pub access_token: String,
    pub scopes: BTreeSet<String>,
}

/// Immutable context extracted from the leaf of a completed verified mTLS
/// connection. The constructor parses the leaf; the rustls acceptor must already
/// have verified its chain, client purpose and time against enrolled workload CAs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadIdentity {
    spiffe_id: String,
}

impl WorkloadIdentity {
    pub fn from_verified_cert_der(der: &[u8]) -> Result<Self> {
        let (remainder, cert) =
            X509Certificate::from_der(der).map_err(|_| invalid("invalid workload certificate"))?;
        if !remainder.is_empty() {
            return Err(invalid("trailing workload certificate bytes"));
        }
        let san = cert
            .subject_alternative_name()
            .map_err(|_| invalid("ambiguous workload subject alternative names"))?
            .ok_or_else(|| refused("workload certificate lacks a SPIFFE URI"))?;
        let mut workload = None;
        for name in &san.value.general_names {
            if let GeneralName::URI(uri) = name {
                // Other SAN types do not authenticate an agent workload.
                if uri
                    .split(':')
                    .next()
                    .is_some_and(|s| s.eq_ignore_ascii_case("spiffe"))
                {
                    if workload.is_some() || !valid_spiffe_id(uri) {
                        return Err(refused("invalid or multiple SPIFFE identities"));
                    }
                    workload = Some((*uri).to_owned());
                }
            }
        }
        Ok(Self {
            spiffe_id: workload
                .ok_or_else(|| refused("workload certificate lacks a SPIFFE URI"))?,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.spiffe_id
    }
}

pub(crate) fn valid_spiffe_id(uri: &str) -> bool {
    // Avoid URL normalizers: the authenticated identifier must preserve its exact
    // registered bytes. Narrow X.509-SVID URI profile, no port/userinfo/escapes.
    let Some(rest) = uri.strip_prefix("spiffe://") else {
        return false;
    };
    if uri.len() > 2048 || !uri.is_ascii() || rest.contains(['?', '#', '%', '\\', '@']) {
        return false;
    }
    let (domain, path) = rest.split_once('/').map_or((rest, ""), |(d, p)| (d, p));
    if domain.is_empty()
        || domain.len() > 255
        || !domain
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-_".contains(&c))
    {
        return false;
    }
    if !path.is_empty()
        && path.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c))
        })
    {
        return false;
    }
    // A root identity has no trailing slash; paths have nonempty segments.
    !rest.ends_with('/')
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Protected MCP requests use POST. The gateway rejects other HTTP methods
    /// before calling this verifier; the DPoP proof method is therefore POST.
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
    ) -> Result<Identity>;
}

#[derive(Clone)]
pub struct DualAuthenticator {
    issuer: String,
    audience: String,
    external_url: String,
    issuer_key: VerifyingKey,
    seen: Arc<Mutex<HashMap<String, i64>>>,
    replay_capacity: usize,
    shared: Option<crate::shared_auth::SharedAuthentication>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtHeader {
    alg: String,
    typ: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, deserialize_with = "present_jwk")]
    jwk: Option<serde_json::Value>,
}

fn present_jwk<'de, D>(deserializer: D) -> std::result::Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Even an explicitly null field is present; access tokens cannot carry a
    // caller-selected key field in this pinned profile.
    serde_json::Value::deserialize(deserializer).map(Some)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    jkt: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    scope: String,
    cnf: Confirmation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    ath: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdJwk {
    kty: String,
    crv: String,
    x: String,
}

impl DualAuthenticator {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        external_url: impl Into<String>,
        issuer_key: [u8; 32],
    ) -> Result<Self> {
        Self::with_replay_capacity(
            issuer,
            audience,
            external_url,
            issuer_key,
            DEFAULT_REPLAY_CAPACITY,
        )
    }

    /// A bounded cache fails closed on saturation; it never evicts an unexpired
    /// proof to admit another. Replicas need a shared replay or nonce profile.
    pub fn with_replay_capacity(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        external_url: impl Into<String>,
        issuer_key: [u8; 32],
        replay_capacity: usize,
    ) -> Result<Self> {
        let issuer = issuer.into();
        let audience = audience.into();
        let external_url = external_url.into();
        if issuer.is_empty() || audience.is_empty() || replay_capacity == 0 {
            return Err(invalid("incomplete pinned identity configuration"));
        }
        crate::endpoint::EndpointPolicy::new(&external_url)?;
        let issuer_key = VerifyingKey::from_bytes(&issuer_key)
            .map_err(|_| invalid("invalid issuer Ed25519 key"))?;
        Ok(Self {
            issuer,
            audience,
            external_url,
            issuer_key,
            seen: Arc::new(Mutex::new(HashMap::new())),
            replay_capacity,
            shared: None,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn external_url(&self) -> &str {
        &self.external_url
    }

    pub fn with_shared_replay(
        mut self,
        ledger: crate::ledger::EtcdLedger,
        config: crate::shared_auth::SharedAuthConfig,
    ) -> Result<Self> {
        self.shared = Some(crate::shared_auth::SharedAuthentication::new(
            ledger,
            config,
            &self.issuer,
            &self.audience,
            &self.external_url,
        )?);
        Ok(self)
    }

    /// Deterministic async entrypoint; time must come from a trusted service clock.
    pub async fn authenticate_shared_at(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
        now_seconds: i64,
    ) -> Result<Identity> {
        let Some(shared) = &self.shared else {
            return self.authenticate_at(headers, workload, now_seconds);
        };
        let (identity, jti, iat) = self.verify_at(headers, workload, now_seconds)?;
        shared.consume(&identity, &jti, iat, now_seconds).await?;
        Ok(identity)
    }

    /// Public for deterministic conformance vectors. Production entrypoint uses
    /// UTC now. The caller must not select this time from request data.
    pub fn authenticate_at(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
        now_seconds: i64,
    ) -> Result<Identity> {
        if self.shared.is_some() {
            return Err(Error::Unavailable(
                "shared authentication requires async consumption".into(),
            ));
        }
        let (identity, jti, _) = self.verify_at(headers, workload, now_seconds)?;
        let replay_key = format!("{}:{}", identity.dpop_jkt, jti);
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| Error::Unavailable("DPoP replay state poisoned".into()))?;
            seen.retain(|_, expiry| *expiry > now_seconds);
            if seen.contains_key(&replay_key) {
                return Err(refused("DPoP proof already consumed"));
            }
            if seen.len() >= self.replay_capacity {
                return Err(Error::Unavailable("DPoP replay cache at capacity".into()));
            }
            seen.insert(replay_key, now_seconds + REPLAY_TTL_SECONDS);
        }
        Ok(identity)
    }

    fn verify_at(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
        now_seconds: i64,
    ) -> Result<(Identity, String, i64)> {
        if !(0..=SAFE_INTEGER_MAX / 1000).contains(&now_seconds) {
            return Err(refused("invalid verifier clock"));
        }
        let authorization = one_header(headers, "authorization")?;
        let proof = one_header(headers, "dpop")?;
        let mut parts = authorization.split(' ');
        if parts.next() != Some("DPoP") {
            return Err(refused("DPoP access-token scheme required"));
        }
        let token = parts
            .next()
            .ok_or_else(|| refused("missing access token"))?;
        if token.is_empty() || parts.next().is_some() {
            return Err(refused("invalid authorization carriage"));
        }
        let access = verify_access_token(
            token,
            &self.issuer,
            &self.audience,
            &self.issuer_key,
            now_seconds,
        )?;
        let (proof_header, proof_body, proof_input, proof_signature) = decode_jwt(proof)?;
        if proof_header.alg != "EdDSA" || proof_header.typ != "dpop+jwt" {
            return Err(refused("unsupported DPoP header"));
        }
        let jwk: EdJwk = serde_json::from_value(
            proof_header
                .jwk
                .ok_or_else(|| refused("missing DPoP public key"))?,
        )
        .map_err(|_| refused("invalid DPoP public key"))?;
        if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
            return Err(refused("unsupported DPoP key"));
        }
        let key_bytes = URL_SAFE_NO_PAD
            .decode(&jwk.x)
            .map_err(|_| refused("invalid DPoP key encoding"))?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| refused("invalid DPoP key length"))?;
        let proof_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| refused("invalid DPoP key"))?;
        proof_key
            .verify_strict(proof_input.as_bytes(), &proof_signature)
            .map_err(|_| refused("invalid DPoP signature"))?;
        let jwk_value =
            serde_json::to_value(&jwk).map_err(|_| invalid("JWK serialization failed"))?;
        let thumbprint =
            URL_SAFE_NO_PAD.encode(Sha256::digest(crate::contracts::canonical(&jwk_value)?));
        if access.claims.cnf.jkt != thumbprint {
            return Err(refused("DPoP confirmation key mismatch"));
        }
        let proof_claims: DpopClaims = closed_decode(&proof_body)?;
        if proof_claims.jti.is_empty()
            || proof_claims.jti.len() > 512
            || proof_claims.htm != "POST"
            || proof_claims.htu != self.external_url
            || proof_claims.iat < 0
            || proof_claims.iat < now_seconds - PROOF_WINDOW_SECONDS
            || proof_claims.iat > now_seconds + FUTURE_SKEW_SECONDS
            || proof_claims.ath != URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
        {
            return Err(refused("invalid DPoP request/token binding"));
        }
        Ok((
            access.identity(token, workload.as_str())?,
            proof_claims.jti,
            proof_claims.iat,
        ))
    }
}

#[async_trait]
impl Authenticator for DualAuthenticator {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
    ) -> Result<Identity> {
        self.authenticate_shared_at(headers, workload, Utc::now().timestamp())
            .await
    }
}

/// Shared with the independent broker verifier; this does not consume DPoP.
pub(crate) struct VerifiedAccess {
    claims: AccessClaims,
}
impl VerifiedAccess {
    pub(crate) fn expires_at(&self) -> i64 {
        self.claims.exp * 1000
    }
    pub(crate) fn identity(&self, token: &str, workload: &str) -> Result<Identity> {
        let scope_list: Vec<&str> = self.claims.scope.split_whitespace().collect();
        if scope_list.is_empty() || scope_list.len() > 128 {
            return Err(refused("invalid access-token scope"));
        }
        let scopes = scope_list
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>();
        if scopes.len() != scope_list.len() {
            return Err(refused("duplicate access-token scope"));
        }
        let delegation = serde_json::json!({
            "access_token_digest": hex_lower(&Sha256::digest(token.as_bytes())),
            "dpop_jkt": self.claims.cnf.jkt,
            "authorization_server": self.claims.iss,
            "token_audience": self.claims.aud,
            "scopes": scope_list,
            "expires_at": self.expires_at()
        });
        Ok(Identity {
            subject: Subject {
                iss: self.claims.iss.clone(),
                sub: self.claims.sub.clone(),
            },
            workload_id: workload.to_owned(),
            dpop_jkt: self.claims.cnf.jkt.clone(),
            delegation_digest: digest("delegation", &delegation)?,
            access_token: token.to_owned(),
            scopes,
        })
    }
}
pub(crate) fn access_token_key_id(token: &str) -> Result<String> {
    decode_jwt(token)?
        .0
        .kid
        .ok_or_else(|| refused("explicit subject key ID required"))
}
pub(crate) fn verify_access_token(
    token: &str,
    issuer: &str,
    audience: &str,
    key: &VerifyingKey,
    now_seconds: i64,
) -> Result<VerifiedAccess> {
    if !(0..=SAFE_INTEGER_MAX / 1000).contains(&now_seconds) {
        return Err(refused("invalid verifier clock"));
    }
    let (header, claims, input, signature) = decode_jwt(token)?;
    if header.alg != "EdDSA" || header.typ != "at+jwt" || header.jwk.is_some() {
        return Err(refused("unsupported access-token header"));
    }
    key.verify_strict(input.as_bytes(), &signature)
        .map_err(|_| refused("invalid access-token signature"))?;
    let access: AccessClaims = closed_decode(&claims)?;
    if access.iss != issuer
        || access.aud != audience
        || access.sub.is_empty()
        || access.sub.len() > 1024
        || access.exp <= now_seconds
        || access.exp > SAFE_INTEGER_MAX / 1000
        || access.iat < 0
        || access.iat > now_seconds + FUTURE_SKEW_SECONDS
        || access.iat >= access.exp
        || access.cnf.jkt.is_empty()
    {
        return Err(refused("invalid access-token identity or time"));
    }
    Ok(VerifiedAccess { claims: access })
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| refused("missing dual-identity header"))?;
    if values.next().is_some() {
        return Err(refused("duplicate dual-identity header"));
    }
    value
        .to_str()
        .map_err(|_| refused("invalid dual-identity header encoding"))
}

fn decode_jwt(token: &str) -> Result<(JwtHeader, Vec<u8>, String, Signature)> {
    if token.len() > MAX_JWT_BYTES {
        return Err(refused("JWT exceeds profile bound"));
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(refused("invalid JWT framing"));
    }
    let head = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| refused("invalid JWT header encoding"))?;
    let body = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| refused("invalid JWT claims encoding"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| refused("invalid JWT signature encoding"))?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| refused("invalid JWT signature length"))?;
    Ok((
        closed_decode(&head)?,
        body,
        format!("{}.{}", parts[0], parts[1]),
        signature,
    ))
}

fn closed_decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    // strict_value catches duplicates before Value would collapse them.
    let value = strict_value(raw)?;
    serde_json::from_value(value).map_err(|_| refused("invalid closed JWT object"))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn invalid(s: &str) -> Error {
    Error::Invalid(s.to_owned())
}
fn refused(s: &str) -> Error {
    Error::Refused(s.to_owned())
}
