//! Selected physical controller query: native commit means acceptance only.
//! A 404 or transport failure never establishes physical no-effect.
use crate::{
    contracts::strict_value,
    error::{Error, Result},
    grant_reference::{bounded_response, fixed_https, valid_reference},
    ledger::{AuthoritativeObservation, OutcomeQuerier},
};
use async_trait::async_trait;
use serde_json::json;
use std::time::Duration;

pub struct ControllerQuery {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    token: String,
}
impl ControllerQuery {
    pub fn new(client: reqwest::Client, endpoint: &str, token: String) -> Result<Self> {
        if token.len() < 32 || token.len() > 16384 || token.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(Error::Invalid(
                "protected drain query credential required".into(),
            ));
        }
        Ok(Self {
            client,
            endpoint: fixed_https(endpoint)?,
            token,
        })
    }
}
#[async_trait]
impl OutcomeQuerier for ControllerQuery {
    async fn query(&self, attempt: &str) -> Result<AuthoritativeObservation> {
        if attempt.is_empty() || attempt.len() > 256 {
            return Err(Error::Invalid(
                "original drain attempt query required".into(),
            ));
        }
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(&self.token)
            .json(&json!({"attempt_id":attempt}))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if response.url() != &self.endpoint || response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unavailable(
                "original controller acceptance query unavailable".into(),
            ));
        }
        let value = strict_value(&bounded_response(response, 65536).await?)?;
        crate::recovery::validate(&value)?;
        let observation: AuthoritativeObservation = serde_json::from_value(value)?;
        if observation.attempt_id != attempt
            || observation.status != "committed"
            || observation
                .target_reference
                .strip_prefix("kube-controller-accepted:")
                .is_none_or(|s| !valid_reference(s))
        {
            return Err(Error::Unknown(
                "original controller acceptance uncorrelated".into(),
            ));
        }
        Ok(observation)
    }
}
