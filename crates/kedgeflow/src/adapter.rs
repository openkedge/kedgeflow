//! Fixed mock-resource adapter. MCP success alone cannot prove a committed effect.
use crate::{
    auth::Identity,
    broker::TargetCredential,
    clock::Clock,
    contracts::{Resource, strict_value},
    error::{Error, Result},
    gateway::{PROTOCOL_VERSION, Request, VerifiedCall},
    grant_reference::{bounded_response, fixed_https},
    tls::PinnedClient,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub struct AdapterResult {
    pub result: Value,
    pub status: String,
}
#[async_trait]
pub trait ResourceAdapter: Send + Sync {
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult>;
    async fn read(&self, request: &Request, identity: &Identity) -> Result<Value>;
}
pub struct HttpAdapter {
    endpoint: reqwest::Url,
    client: PinnedClient,
    audience: String,
    read_token: String,
    clock: Arc<dyn Clock>,
}
impl HttpAdapter {
    pub fn new(
        endpoint: &str,
        client: PinnedClient,
        audience: String,
        read_token: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        if audience.is_empty() {
            return Err(Error::Invalid("target audience required".into()));
        }
        Ok(Self {
            endpoint: fixed_https(endpoint)?,
            client,
            audience,
            read_token,
            clock,
        })
    }
    async fn post(&self, request: &Request, token: &str) -> Result<AdapterResult> {
        let response = self
            .client
            .client()
            .post(self.endpoint.clone())
            .json(request)
            .bearer_auth(token)
            .send()
            .await?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unknown("ambiguous target response".into()));
        }
        let raw = bounded_response(response, 1 << 20).await?;
        let reply = strict_value(&raw)?;
        let object = reply
            .as_object()
            .ok_or_else(|| Error::Unknown("invalid target response".into()))?;
        if object
            .keys()
            .any(|k| !["jsonrpc", "id", "result", "error"].contains(&k.as_str()))
            || reply.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || reply.get("id") != Some(&request.id)
            || (reply.get("result").is_some() == reply.get("error").is_some())
        {
            return Err(Error::Unknown("invalid correlated target response".into()));
        }
        if let Some(error) = reply.get("error") {
            if error.get("message").and_then(Value::as_str) == Some("STATE_GUARD_VIOLATION") {
                return Ok(AdapterResult {
                    result: Value::Null,
                    status: "state_guard_violation".into(),
                });
            }
            return Err(Error::Unknown(
                "target failed without effect contract".into(),
            ));
        }
        let result = reply["result"].clone();
        if result.get("resultType").and_then(Value::as_str) != Some("complete")
            || result
                .get("isError")
                .is_some_and(|v| v.as_bool() != Some(false))
        {
            return Err(Error::Unknown("nonterminal or tool error result".into()));
        }
        Ok(AdapterResult {
            result,
            status: "complete".into(),
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MockTerminalReceipt {
    attempt_id: String,
    grant_digest: String,
    resource: Resource,
    fence: u64,
    status: String,
    post_version: u64,
}
fn strip_meta(request: &mut Request) {
    request.params.meta = std::collections::BTreeMap::from([
        (
            "io.modelcontextprotocol/protocolVersion".into(),
            json!(PROTOCOL_VERSION),
        ),
        (
            "io.modelcontextprotocol/clientCapabilities".into(),
            json!({}),
        ),
    ]);
}
#[async_trait]
impl ResourceAdapter for HttpAdapter {
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        if credential.audience != self.audience
            || credential.token.is_empty()
            || self.clock.now_ms() >= credential.expires_at_ms
        {
            return Err(Error::Refused("credential scope or expiry".into()));
        }
        let mut request = call.request.clone();
        let args = request
            .params
            .arguments
            .as_object_mut()
            .ok_or_else(|| Error::Invalid("invalid arguments".into()))?;
        args.insert(
            call.descriptor.fence_parameter.clone(),
            json!(call.grant.fence),
        );
        args.insert("kf_attempt_id".into(), json!(call.attempt_id));
        args.insert("kf_grant_digest".into(), json!(call.grant_digest));
        args.insert(
            "kf_resource_incarnation".into(),
            json!(call.grant.resources[0].incarnation),
        );
        strip_meta(&mut request);
        let result = self.post(&request, &credential.token).await?;
        if result.status == "state_guard_violation" {
            return Ok(result);
        }
        let receipt: MockTerminalReceipt = serde_json::from_value(
            result.result["structuredContent"]["kedgeflow_terminal_receipt"].clone(),
        )
        .map_err(|_| Error::Unknown("missing target terminal receipt".into()))?;
        if receipt.attempt_id != call.attempt_id
            || receipt.grant_digest != call.grant_digest
            || receipt.resource != call.grant.resources[0]
            || receipt.fence != call.grant.fence
            || receipt.status != "committed"
            || receipt.post_version == 0
            || receipt.post_version > crate::contracts::MAX_SAFE_INTEGER
        {
            return Err(Error::Unknown(
                "uncorrelated target terminal receipt".into(),
            ));
        }
        Ok(AdapterResult {
            result: result.result,
            status: "committed".into(),
        })
    }
    async fn read(&self, request: &Request, _: &Identity) -> Result<Value> {
        if self.read_token.trim().is_empty() {
            return Err(Error::Refused("read credential not configured".into()));
        }
        let mut request = request.clone();
        strip_meta(&mut request);
        let result = self.post(&request, &self.read_token).await?;
        if result.status != "complete" {
            return Err(Error::Unavailable("read failed".into()));
        }
        Ok(result.result)
    }
}
