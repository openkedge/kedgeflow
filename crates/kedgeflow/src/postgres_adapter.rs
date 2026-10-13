//! Fixed native SQL client, available as a trusted integration library. The
//! gateway CLI's mock binding is not implicitly widened by this adapter.
use crate::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::Identity,
    broker::TargetCredential,
    clock::Clock,
    contracts::GrantVerifier,
    error::{Error, Result},
    gateway::{Request, VerifiedCall},
    grant_reference::{bounded_response, fixed_https},
    postgres_action::{Outcome, Parameters, Status},
    postgres_target::{Dispatch, PROFILE, Registration, bind_dispatch},
    target_token::TargetTokenVerifier,
    tls::PinnedClient,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::sync::Arc;

pub struct PostgresAdapter {
    endpoint: reqwest::Url,
    client: PinnedClient,
    registration: Registration,
    grants: GrantVerifier,
    tokens: TargetTokenVerifier,
    clock: Arc<dyn Clock>,
}
impl PostgresAdapter {
    pub fn new(
        url: &str,
        client: PinnedClient,
        registration: Registration,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        registration.validate()?;
        crate::endpoint::EndpointPolicy::new(&grants.audience)?;
        if grants.keys.is_empty() || tokens.keys().any(|t| grants.keys.values().any(|g| g == t)) {
            return Err(Error::Invalid("invalid SQL adapter key roles".into()));
        }
        Ok(Self {
            endpoint: fixed_https(url)?,
            client,
            registration,
            grants,
            tokens,
            clock,
        })
    }
}
#[async_trait]
impl ResourceAdapter for PostgresAdapter {
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        let now = self.clock.now_ms();
        if credential.audience != self.registration.target_audience
            || now >= credential.expires_at_ms
            || credential.expires_at_ms > call.grant.expires_at
        {
            return Err(Error::Refused("SQL adapter credential bounds".into()));
        }
        let parameters = Parameters::decode(&serde_json::to_vec(&call.request.params.arguments)?)?;
        let request = Dispatch {
            profile: PROFILE.into(),
            operation: "dispatch".into(),
            signed_grant: URL_SAFE_NO_PAD.encode(&call.signed_grant),
            attempt_id: call.attempt_id.clone(),
            parameters,
        };
        let expected = bind_dispatch(
            &self.registration,
            &self.grants,
            &self.tokens,
            now,
            request.clone(),
            &credential.token,
        )?;
        if expected.grant_digest != call.grant_digest
            || expected.root_id != call.grant.root_id
            || credential.expires_at_ms as u64 > expected.expires_at
        {
            return Err(Error::Refused("SQL adapter original grant mismatch".into()));
        }
        let response = self
            .client
            .client()
            .post(self.endpoint.clone())
            .bearer_auth(&credential.token)
            .json(&request)
            .send()
            .await
            .map_err(|_| Error::Unknown("SQL target reply unavailable".into()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unknown("SQL target reply unavailable".into()));
        }
        let raw = bounded_response(response, 32 * 1024)
            .await
            .map_err(|_| Error::Unknown("SQL target reply unavailable".into()))?;
        let outcome = Outcome::verify(&raw, &expected)
            .map_err(|_| Error::Unknown("SQL target reply uncorrelated".into()))?;
        Ok(AdapterResult {
            status: match outcome.status {
                Status::Committed => "committed",
                Status::GuardRejected => "state_guard_violation",
            }
            .into(),
            result: json!({"resultType":"complete","isError":outcome.status==Status::GuardRejected,
            "structuredContent":{"kedgeflow_postgres_outcome":outcome}}),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Err(Error::Refused(
            "SQL adapter has no generic read operation".into(),
        ))
    }
}
