//! RFC 8693 client with a named KedgeFlow AS extension. The configured AS must
//! validate the grant and claimed attempt before issuing target authority.
use crate::{
    clock::Clock,
    contracts::strict_value,
    error::{Error, Result},
    gateway::VerifiedCall,
    grant_reference::{bounded_response, fixed_https},
    tls::PinnedClient,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, time::Instant};

#[derive(Clone)]
pub struct TargetCredential {
    pub token: String,
    pub expires_at_ms: i64,
    pub audience: String,
}
#[async_trait]
pub trait CredentialBroker: Send + Sync {
    async fn exchange(&self, call: &VerifiedCall, deadline: Instant) -> Result<TargetCredential>;
}
#[async_trait]
pub trait WorkloadAssertion: Send + Sync {
    async fn assertion(&self, workload_id: &str) -> Result<String>;
}
/// Operator-managed, rotating JWT-SVID file. Its issuance and protection are
/// deployment responsibilities; this client never invents an actor assertion.
pub struct FileAssertion {
    pub workload_id: String,
    pub path: PathBuf,
}
#[async_trait]
impl WorkloadAssertion for FileAssertion {
    async fn assertion(&self, workload_id: &str) -> Result<String> {
        if workload_id != self.workload_id {
            return Err(Error::Refused("workload assertion scope mismatch".into()));
        }
        // Bound file acquisition too; reject nonregular or oversized sources.
        let file = tokio::fs::File::open(&self.path).await?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() || metadata.len() > 64 * 1024 {
            return Err(Error::Unavailable("invalid assertion file".into()));
        }
        let mut raw = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut raw).await?;
        if raw.len() > 64 * 1024 {
            return Err(Error::Unavailable("assertion exceeds bound".into()));
        }
        let token = std::str::from_utf8(&raw)
            .map_err(|_| Error::Unavailable("invalid assertion encoding".into()))?
            .trim();
        if token.is_empty() {
            return Err(Error::Unavailable("empty assertion".into()));
        }
        Ok(token.to_owned())
    }
}

pub struct Rfc8693Broker {
    endpoint: reqwest::Url,
    target_audience: String,
    target_scope: String,
    client: PinnedClient,
    assertion: Arc<dyn WorkloadAssertion>,
    clock: Arc<dyn Clock>,
    timeout: Duration,
}
impl Rfc8693Broker {
    pub fn new(
        endpoint: &str,
        target_audience: String,
        target_scope: String,
        client: PinnedClient,
        assertion: Arc<dyn WorkloadAssertion>,
        clock: Arc<dyn Clock>,
        timeout: Duration,
    ) -> Result<Self> {
        if target_audience.is_empty() || target_scope.is_empty() || timeout.is_zero() {
            return Err(Error::Invalid("incomplete broker configuration".into()));
        }
        Ok(Self {
            endpoint: fixed_https(endpoint)?,
            target_audience,
            target_scope,
            client,
            assertion,
            clock,
            timeout,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse {
    access_token: String,
    issued_token_type: String,
    token_type: String,
    expires_in: i64,
    scope: String,
}
#[async_trait]
impl CredentialBroker for Rfc8693Broker {
    async fn exchange(
        &self,
        call: &VerifiedCall,
        parent_deadline: Instant,
    ) -> Result<TargetCredential> {
        let started = self.clock.now_ms();
        let remaining = call
            .grant
            .expires_at
            .checked_sub(started)
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::Refused("grant expired before exchange".into()))?;
        if call.grant_digest.is_empty() || call.signed_grant.is_empty() {
            return Err(Error::Invalid("missing signed grant boundary".into()));
        }
        let budget = self.timeout.min(Duration::from_millis(remaining as u64));
        let deadline = parent_deadline.min(Instant::now() + budget);
        tokio::time::timeout_at(deadline, async {
            let actor = self.assertion.assertion(&call.identity.workload_id).await?;
            if actor.is_empty()
                || self.clock.now_ms() >= call.grant.expires_at
                || Instant::now() >= deadline
            {
                return Err(Error::Unavailable(
                    "assertion unavailable within grant budget".into(),
                ));
            }
            let signed = URL_SAFE_NO_PAD.encode(&call.signed_grant);
            let fields = [
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", call.identity.access_token.as_str()),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("actor_token", actor.as_str()),
                ("actor_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("audience", self.target_audience.as_str()),
                ("scope", self.target_scope.as_str()),
                ("kedgeflow_grant", signed.as_str()),
                ("kedgeflow_grant_digest", call.grant_digest.as_str()),
                ("kedgeflow_attempt_id", call.attempt_id.as_str()),
            ];
            let response = self
                .client
                .client()
                .post(self.endpoint.clone())
                .form(&fields)
                .send()
                .await?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(Error::Unavailable("token exchange refused".into()));
            }
            let raw = bounded_response(response, 65536).await?;
            let received = self.clock.now_ms();
            let token: TokenResponse = serde_json::from_value(strict_value(&raw)?)?;
            if token.access_token.is_empty()
                || token.token_type != "Bearer"
                || token.issued_token_type != "urn:ietf:params:oauth:token-type:access_token"
                || !(1..=300).contains(&token.expires_in)
                || token.scope != self.target_scope
            {
                return Err(Error::Refused("invalid target token".into()));
            }
            let lifetime = token.expires_in * 1000;
            let expires = started + lifetime;
            // Receipt time bounds issuer expiry above; exchange start bounds
            // local usability below. Never clamp an overbroad target token.
            if received + lifetime > call.grant.expires_at
                || received >= call.grant.expires_at
                || self.clock.now_ms() >= expires
                || Instant::now() >= deadline
            {
                return Err(Error::Refused(
                    "target token exceeds or exhausts grant lifetime".into(),
                ));
            }
            Ok(TargetCredential {
                token: token.access_token,
                expires_at_ms: expires,
                audience: self.target_audience.clone(),
            })
        })
        .await
        .map_err(|_| Error::Unavailable("token exchange timed out".into()))?
    }
}
