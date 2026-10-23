//! Fixed mTLS controller acceptance and original native-acceptance query.
use crate::{
    auth::WorkloadIdentity,
    contracts::strict_value,
    endpoint::EndpointPolicy,
    error::{Error, Result},
    kube_drain::PROFILE,
    kube_drain_runtime::Controller,
    ledger::AuthoritativeObservation,
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    pub profile: String,
    pub operation: String,
    pub signed_grant: String,
    pub attempt_id: String,
    pub parameters: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    attempt_id: String,
}
pub struct Service {
    controller: Arc<Controller>,
    dispatch: EndpointPolicy,
    query: EndpointPolicy,
    gateway_workload: String,
    query_workload: String,
    query_token: [u8; 32],
    slots: Arc<tokio::sync::Semaphore>,
}
impl Service {
    pub fn new(
        controller: Arc<Controller>,
        dispatch: &str,
        query: &str,
        gateway_workload: String,
        query_workload: String,
        query_token: &str,
    ) -> Result<Self> {
        let dispatch = EndpointPolicy::new(dispatch)?;
        let query = EndpointPolicy::new(query)?;
        if dispatch.authority() != query.authority()
            || dispatch.path() == query.path()
            || gateway_workload == query_workload
            || query_token.len() < 32
            || query_token.len() > 16384
            || !crate::auth::valid_spiffe_id(&gateway_workload)
            || !crate::auth::valid_spiffe_id(&query_workload)
        {
            return Err(Error::Invalid(
                "fixed drain service roles/endpoints required".into(),
            ));
        }
        Ok(Self {
            controller,
            dispatch,
            query,
            gateway_workload,
            query_workload,
            query_token: Sha256::digest(query_token.as_bytes()).into(),
            slots: Arc::new(tokio::sync::Semaphore::new(16)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn accept(&self, raw: &[u8], token: &str) -> Result<Value> {
        let a: Accept = serde_json::from_value(strict_value(raw)?)?;
        if a.profile != PROFILE
            || a.operation != "accept"
            || a.attempt_id.is_empty()
            || a.attempt_id.len() > 256
        {
            return Err(Error::Invalid(
                "closed original drain acceptance required".into(),
            ));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&a.signed_grant)
            .map_err(|_| Error::Invalid("grant carriage".into()))?;
        if bytes.len() > 1 << 20 || URL_SAFE_NO_PAD.encode(&bytes) != a.signed_grant {
            return Err(Error::Invalid("grant carriage bound".into()));
        }
        let raw = String::from_utf8(bytes).map_err(|_| Error::Invalid("grant UTF8".into()))?;
        Ok(json!(
            Box::pin(
                self.controller
                    .accept(raw, a.attempt_id, a.parameters, token)
            )
            .await?
        ))
    }
    async fn query(&self, raw: &[u8]) -> Result<Option<Value>> {
        let q: Query = serde_json::from_value(strict_value(raw)?)?;
        if q.attempt_id.is_empty() || q.attempt_id.len() > 256 {
            return Err(Error::Invalid("original drain query".into()));
        }
        let Some(s) = self.controller.state().await? else {
            return Ok(None);
        };
        if s.body.accepted.attempt_id != q.attempt_id {
            return Ok(None);
        }
        let grant: crate::contracts::Envelope =
            serde_json::from_value(strict_value(s.body.accepted.signed_grant.as_bytes())?)?;
        Ok(Some(json!(AuthoritativeObservation {
            attempt_id: q.attempt_id,
            root_id: grant.payload["root_id"]
                .as_str()
                .ok_or_else(|| Error::Invalid("original root".into()))?
                .into(),
            grant_digest: s.body.accepted.grant_digest.clone(),
            target_reference: format!("kube-controller-accepted:{}", s.body.accepted.operation()?),
            status: "committed".into()
        })))
    }
}
fn reply(code: StatusCode, v: Value) -> Response {
    (code, Json(v)).into_response()
}
async fn handle(
    State(s): State<Arc<Service>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    let query = request.uri().path() == s.query.path();
    let endpoint = if query { &s.query } else { &s.dispatch };
    if let Some(code) = endpoint.rejection_status(request.headers(), request.uri()) {
        return reply(code, json!({"error":"invalid_endpoint"}));
    }
    if request.method() != Method::POST {
        return reply(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error":"invalid_method"}),
        );
    }
    if workload.as_str()
        != if query {
            &s.query_workload
        } else {
            &s.gateway_workload
        }
    {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error":"invalid_workload"}),
        );
    }
    let mut auth = request.headers().get_all("authorization").iter();
    let token = auth
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| {
            !s.is_empty() && s.len() <= 16384 && !s.bytes().any(|b| b.is_ascii_whitespace())
        })
        .map(str::to_owned);
    if token.is_none() || auth.next().is_some() {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error":"invalid_credential"}),
        );
    }
    let token = token.unwrap();
    if query && <[u8; 32]>::from(Sha256::digest(token.as_bytes())) != s.query_token {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error":"invalid_credential"}),
        );
    }
    let mut types = request.headers().get_all("content-type").iter();
    if types.next().and_then(|v| v.to_str().ok()) != Some("application/json")
        || types.next().is_some()
    {
        return reply(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({"error":"invalid_content_type"}),
        );
    }
    let slot = match s.slots.clone().try_acquire_owned() {
        Ok(s) => s,
        Err(_) => {
            return reply(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"unavailable"}),
            );
        }
    };
    let raw = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), 2 << 20),
    )
    .await
    {
        Ok(Ok(b)) => b,
        _ => return reply(StatusCode::BAD_REQUEST, json!({"error":"invalid_body"})),
    };
    let task = tokio::spawn(async move {
        let _slot = slot;
        let future = async {
            if query {
                s.query(&raw).await
            } else {
                s.accept(&raw, &token).await.map(Some)
            }
        };
        match tokio::time::timeout(Duration::from_secs(10), future).await {
            Ok(Ok(Some(v))) => reply(StatusCode::OK, v),
            Ok(Ok(None)) => reply(
                StatusCode::NOT_FOUND,
                json!({"error":"original_acceptance_unknown"}),
            ),
            Ok(Err(Error::Invalid(_))) => {
                reply(StatusCode::BAD_REQUEST, json!({"error":"invalid_request"}))
            }
            Ok(Err(Error::Refused(_))) => {
                reply(StatusCode::FORBIDDEN, json!({"error":"request_refused"}))
            }
            _ => reply(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"original_status_unknown"}),
            ),
        }
    });
    task.await.unwrap_or_else(|_| {
        reply(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"original_status_unknown"}),
        )
    })
}
