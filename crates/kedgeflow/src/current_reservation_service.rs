//! Fixed mTLS and separate credential boundary for the one-use SQL source query.
use crate::{
    auth::WorkloadIdentity,
    contracts::strict_value,
    current_reservation::{Query, Witness},
    current_reservation_provider::Provider,
    endpoint::EndpointPolicy,
    error::{Error, Result},
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
pub struct Service {
    provider: Arc<Provider>,
    endpoint: EndpointPolicy,
    evidence_endpoint: EndpointPolicy,
    evidence_workload: String,
    evidence_token: [u8; 32],
    workload: String,
    token: [u8; 32],
    slots: Arc<tokio::sync::Semaphore>,
}
impl Service {
    pub fn new(provider: Arc<Provider>, token: &str, evidence_token: &str) -> Result<Self> {
        if token == evidence_token
            || [token, evidence_token].into_iter().any(|token| {
                token.len() < 32
                    || token.len() > 16384
                    || token.bytes().any(|b| b.is_ascii_whitespace())
            })
        {
            return Err(Error::Refused(
                "protected current SQL query credential required".into(),
            ));
        }
        Ok(Self {
            endpoint: EndpointPolicy::new(&provider.enrollment().current_sql.endpoint)?,
            workload: provider.enrollment().controller_workload.clone(),
            evidence_endpoint: EndpointPolicy::new(
                &provider.enrollment().current_sql.evidence_endpoint,
            )?,
            evidence_workload: provider.enrollment().evidence_workload.clone(),
            evidence_token: Sha256::digest(evidence_token.as_bytes()).into(),
            provider,
            token: Sha256::digest(token.as_bytes()).into(),
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn query(&self, raw: &[u8]) -> Result<Witness> {
        let q: Query = serde_json::from_value(strict_value(raw)?)?;
        self.provider.query(&q).await
    }
}
fn reply(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({"error":error}))).into_response()
}
async fn handle(
    State(s): State<Arc<Service>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    let admission = request.uri().path() == s.evidence_endpoint.path();
    let endpoint = if admission {
        &s.evidence_endpoint
    } else {
        &s.endpoint
    };
    if let Some(code) = endpoint.rejection_status(request.headers(), request.uri()) {
        return reply(code, "invalid_endpoint");
    }
    if request.method() != Method::POST {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "invalid_method");
    }
    if workload.as_str()
        != if admission {
            &s.evidence_workload
        } else {
            &s.workload
        }
    {
        return reply(StatusCode::UNAUTHORIZED, "invalid_workload");
    }
    let mut auth = request.headers().get_all("authorization").iter();
    let token = auth
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| {
            s.len() >= 32 && s.len() <= 16384 && !s.bytes().any(|b| b.is_ascii_whitespace())
        });
    if auth.next().is_some()
        || token.is_none_or(|v| {
            <[u8; 32]>::from(Sha256::digest(v.as_bytes()))
                != if admission { s.evidence_token } else { s.token }
        })
    {
        return reply(StatusCode::UNAUTHORIZED, "invalid_credential");
    }
    let mut types = request.headers().get_all("content-type").iter();
    if types.next().and_then(|v| v.to_str().ok()) != Some("application/json")
        || types.next().is_some()
    {
        return reply(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_content_type");
    }
    let slot = match s.slots.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE, "source_busy"),
    };
    let raw = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), 4 << 20),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return reply(StatusCode::BAD_REQUEST, "invalid_body"),
    };
    let task = tokio::spawn(async move {
        let _slot = slot;
        let result = if admission {
            let query = strict_value(&raw).and_then(|value| {
                serde_json::from_value::<crate::managed_drain_preflight::Request>(value)
                    .map_err(Into::into)
            });
            match query {
                Ok(query) => s.provider.admission(&query).await.map(|value| json!(value)),
                Err(error) => Err(error),
            }
        } else {
            s.query(&raw).await.map(|value| json!(value))
        };
        match result {
            Ok(value) => (StatusCode::OK, Json(value)).into_response(),
            Err(Error::Invalid(_)) => reply(StatusCode::BAD_REQUEST, "invalid_query"),
            Err(Error::Refused(_)) => reply(StatusCode::FORBIDDEN, "source_refused"),
            _ => reply(StatusCode::SERVICE_UNAVAILABLE, "source_unknown"),
        }
    });
    task.await
        .unwrap_or_else(|_| reply(StatusCode::SERVICE_UNAVAILABLE, "source_unknown"))
}
