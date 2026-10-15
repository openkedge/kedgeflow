//! Explicit native inverse adapter. Original proof/binding come from the
//! protected ledger, never from agent metadata. No mutation retry on reply loss.
use crate::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::Identity,
    broker::TargetCredential,
    clock::Clock,
    compensation_target::{Dispatch, PROFILE, TargetTrust},
    contracts::GrantVerifier,
    error::{Error, Result},
    gateway::{Request, VerifiedCall},
    grant_reference::{bounded_response, fixed_https},
    ledger::EtcdLedger,
    postgres_action::Status,
    postgres_compensation::Outcome,
    target_token::TargetTokenVerifier,
    tls::PinnedClient,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::sync::Arc;
pub struct CompensationAdapter {
    endpoint: reqwest::Url,
    client: PinnedClient,
    trust: TargetTrust,
    grants: GrantVerifier,
    tokens: TargetTokenVerifier,
    ledger: EtcdLedger,
    clock: Arc<dyn Clock>,
}
impl CompensationAdapter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        url: &str,
        client: PinnedClient,
        trust: TargetTrust,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        ledger: EtcdLedger,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        trust.validate(&grants)?;
        Ok(Self {
            endpoint: fixed_https(url)?,
            client,
            trust,
            grants,
            tokens,
            ledger,
            clock,
        })
    }
}
#[async_trait]
impl ResourceAdapter for CompensationAdapter {
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        let now = self.clock.now_ms();
        if credential.audience != self.trust.registration.target_audience
            || now >= credential.expires_at_ms
            || credential.expires_at_ms > call.grant.expires_at
        {
            return Err(Error::Refused("inverse credential bounds refused".into()));
        }
        let (binding, qualification) = self
            .ledger
            .compensation_dispatch_material(&call.grant, &call.grant_digest, &call.attempt_id)
            .await?;
        if crate::contracts::digest("parameters", &call.request.params.arguments)?
            != binding.payload.parameters_digest
        {
            return Err(Error::Refused(
                "inverse arguments differ from original authority".into(),
            ));
        }
        let request = Dispatch {
            profile: PROFILE.into(),
            operation: "dispatch".into(),
            signed_grant: URL_SAFE_NO_PAD.encode(&call.signed_grant),
            attempt_id: call.attempt_id.clone(),
            qualification,
            binding,
        };
        let expected =
            self.trust
                .bind(&self.grants, &self.tokens, &request, &credential.token, now)?;
        if expected.grant_digest != call.grant_digest
            || expected.root_id != call.grant.root_id
            || credential.expires_at_ms as u64 > expected.expires_at
        {
            return Err(Error::Refused("inverse original grant mismatch".into()));
        }
        let response = self
            .client
            .client()
            .post(self.endpoint.clone())
            .bearer_auth(&credential.token)
            .json(&request)
            .send()
            .await
            .map_err(|_| {
                Error::Unknown("inverse reply unavailable; query original attempt".into())
            })?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unknown(
                "inverse reply unavailable; query original attempt".into(),
            ));
        }
        let raw = bounded_response(response, 32 * 1024)
            .await
            .map_err(|_| Error::Unknown("inverse reply unavailable".into()))?;
        let outcome = Outcome::verify(&raw, &expected)
            .map_err(|_| Error::Unknown("uncorrelated inverse reply".into()))?;
        Ok(AdapterResult {
            status: match outcome.status {
                Status::Committed => "committed",
                Status::GuardRejected => "state_guard_violation",
            }
            .into(),
            result: json!({"resultType":"complete","isError":outcome.status==Status::GuardRejected,"structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":call.attempt_id,"grant_digest":call.grant_digest,"resource":call.grant.resources[0],"fence":call.grant.fence,"status":if outcome.status==Status::Committed{"committed"}else{"state_guard_violation"},"post_version":outcome.post_version},"kedgeflow_postgres_inverse_outcome":outcome}}),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Err(Error::Refused(
            "inverse adapter has no generic read port".into(),
        ))
    }
}
