//! Explicit Level C adapter: native commit is durable controller acceptance.
//! The independent physical layer alone can report observed drain completion.
use crate::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::Identity,
    broker::TargetCredential,
    clock::Clock,
    contracts::{GrantVerifier, canonical, strict_value},
    error::{Error, Result},
    gateway::{Request, VerifiedCall},
    grant_reference::{bounded_response, fixed_https},
    kube_drain::PROFILE,
    kube_drain_http::Accept,
    kube_drain_journal::State,
    kube_drain_proof::{Signed, Trust},
    target_token::{TargetTokenVerifier, TokenBinding},
    tls::PinnedClient,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
fn refuse() -> Error {
    Error::Refused("explicit Level C controller adapter refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub trust: Trust,
    pub token_issuer: String,
    pub target_keys: BTreeMap<String, String>,
    pub gateway_workload: String,
    pub target_audience: String,
    pub target_scope: String,
}
impl Config {
    pub fn validate(&self, grants: &GrantVerifier) -> Result<()> {
        self.trust.validate()?;
        let native = self.trust.control()?;
        if self.profile != PROFILE
            || native.operation.grants.keys != grants.keys
            || native.operation.grants.audience != grants.audience
            || self.target_scope.is_empty()
            || !crate::auth::valid_spiffe_id(&self.gateway_workload)
        {
            return Err(refuse());
        }
        fixed_https(&self.target_audience)?;
        let tokens = TargetTokenVerifier::new(
            self.token_issuer.clone(),
            crate::control_config::keys(&self.target_keys)?,
        )?;
        if tokens.keys().any(|k| {
            grants.keys.values().any(|v| v == k)
                || self
                    .trust
                    .controller
                    .keys
                    .values()
                    .chain(self.trust.observer.keys.values())
                    .any(|p| crate::config::key(p).is_ok_and(|v| v == *k.as_bytes()))
        }) {
            return Err(refuse());
        }
        Ok(())
    }
}
pub struct Adapter {
    config: Config,
    grants: GrantVerifier,
    tokens: TargetTokenVerifier,
    endpoint: reqwest::Url,
    client: PinnedClient,
    clock: Arc<dyn Clock>,
}
impl Adapter {
    pub fn new(
        endpoint: &str,
        client: PinnedClient,
        config: Config,
        grants: GrantVerifier,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        config.validate(&grants)?;
        if endpoint != config.target_audience {
            return Err(refuse());
        }
        let tokens = TargetTokenVerifier::new(
            config.token_issuer.clone(),
            crate::control_config::keys(&config.target_keys)?,
        )?;
        Ok(Self {
            config,
            grants,
            tokens,
            endpoint: fixed_https(endpoint)?,
            client,
            clock,
        })
    }
}
#[async_trait]
impl ResourceAdapter for Adapter {
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        let now = self.clock.now_ms();
        let v = self.grants.verify(&call.signed_grant, now)?;
        let c = &self.config.trust.contract;
        if v.grant != call.grant
            || v.digest != call.grant_digest
            || credential.audience != self.config.target_audience
            || now >= credential.expires_at_ms
            || call.grant.resources != [c.resource()?]
            || call.grant.action.id != crate::kube_drain::ACTION
            || call.grant.action.version != "1.0"
            || call.request.params.arguments
                != json!({"node":c.node.name,"expected_version":c.generation})
            || call.grant.adapter_contract != crate::kube_drain::adapter_contract()
        {
            return Err(refuse());
        }
        self.tokens.verify(
            &credential.token,
            &TokenBinding {
                grant_digest: call.grant_digest.clone(),
                root_id: call.grant.root_id.clone(),
                attempt_id: call.attempt_id.clone(),
                gateway_workload: self.config.gateway_workload.clone(),
                audience: self.config.target_audience.clone(),
                scope: self.config.target_scope.clone(),
                max_expires_at: call.grant.expires_at,
            },
            now,
        )?;
        let request = Accept {
            profile: PROFILE.into(),
            operation: "accept".into(),
            signed_grant: URL_SAFE_NO_PAD.encode(&call.signed_grant),
            attempt_id: call.attempt_id.clone(),
            parameters: call.request.params.arguments.clone(),
        };
        let response = self
            .client
            .client()
            .post(self.endpoint.clone())
            .bearer_auth(&credential.token)
            .json(&request)
            .send()
            .await
            .map_err(|_| {
                Error::Unknown("original controller acceptance reply unavailable".into())
            })?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unknown(
                "original controller acceptance ambiguous".into(),
            ));
        }
        let raw = bounded_response(response, crate::kube_drain_journal::MAX_STATE).await?;
        let accepted: Signed<State> = serde_json::from_value(strict_value(&raw)?)?;
        accepted.verify("controller_state", &self.config.trust.controller)?;
        accepted.body.validate(c, &call.grant)?;
        let a = &accepted.body.accepted;
        if a.grant_digest != call.grant_digest
            || a.attempt_id != call.attempt_id
            || canonical(&strict_value(a.signed_grant.as_bytes())?)?
                != canonical(&strict_value(&call.signed_grant)?)?
        {
            return Err(Error::Unknown(
                "original controller acceptance uncorrelated".into(),
            ));
        }
        Ok(AdapterResult {
            status: "committed".into(),
            result: json!({"resultType":"complete","isError":false,"structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":call.attempt_id,"grant_digest":call.grant_digest,"resource":call.grant.resources[0],"fence":call.grant.fence,"status":"committed","post_version":c.generation},"kedgeflow_drain_acceptance":accepted,"physical_status":"unresolved","commit_point":"controller_acceptance"}}),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Err(refuse())
    }
}
