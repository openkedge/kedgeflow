//! Optional extension endpoint mounted beside the native control service.
use crate::{
    a2a_root::{MAX_BYTES, PROFILE, ResolveRequest, RootResolver, activation},
    auth::{DualAuthenticator, WorkloadIdentity},
    clock::Clock,
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
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
pub struct RootResolutionService {
    resolver: RootResolver,
    auth: DualAuthenticator,
    endpoint: EndpointPolicy,
    clock: Arc<dyn Clock>,
    slots: tokio::sync::Semaphore,
}
impl RootResolutionService {
    pub fn new(
        resolver: RootResolver,
        auth: DualAuthenticator,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let r = resolver.registration();
        if auth.external_url() != r.authority_endpoint
            || r.readers.iter().any(|p| p.subject.iss != auth.issuer())
        {
            return Err(Error::Invalid(
                "root reader authentication pin mismatch".into(),
            ));
        }
        let endpoint = EndpointPolicy::new(auth.external_url())?;
        Ok(Self {
            resolver,
            auth,
            endpoint,
            clock,
            slots: tokio::sync::Semaphore::new(64),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route(crate::a2a_root::PATH, axum::routing::any(handle))
            .with_state(self)
    }
}
fn reply(status: StatusCode, value: Value) -> Response {
    (status, [("cache-control", "no-store")], Json(value)).into_response()
}
fn failure(status: StatusCode, code: &str) -> Response {
    reply(
        status,
        json!({"profile":PROFILE,"operation":"failure","code":code}),
    )
}
async fn handle(
    State(s): State<Arc<RootResolutionService>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    if let Some(status) = s
        .endpoint
        .rejection_status(request.headers(), request.uri())
    {
        return failure(status, "invalid_endpoint");
    }
    if request.method() != Method::POST {
        return failure(StatusCode::METHOD_NOT_ALLOWED, "invalid_method");
    }
    let headers = request.headers().clone();
    if headers.get_all("content-type").iter().count() != 1
        || headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json")
    {
        return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_record");
    }
    if activation(&headers).is_err() {
        return failure(StatusCode::BAD_REQUEST, "unsupported_activation");
    }
    let raw = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), MAX_BYTES),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_record"),
    };
    let request = match ResolveRequest::decode(&raw) {
        Ok(v) => v,
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_record"),
    };
    let _permit = match s.slots.try_acquire() {
        Ok(p) => p,
        _ => return failure(StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
    };
    let identity = match s
        .auth
        .authenticate_shared_at(&headers, &workload, s.clock.now_ms() / 1000)
        .await
    {
        Ok(i) => i,
        Err(Error::Unavailable(_)) => {
            return failure(StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable");
        }
        _ => return failure(StatusCode::UNAUTHORIZED, "unauthenticated"),
    };
    match tokio::time::timeout(
        Duration::from_secs(5),
        s.resolver.resolve(&identity, &request),
    )
    .await
    {
        Ok(Ok(v)) => match serde_json::to_value(v) {
            Ok(v) => reply(StatusCode::OK, v),
            _ => failure(StatusCode::INTERNAL_SERVER_ERROR, "invalid_record"),
        },
        Ok(Err(Error::Refused(_))) => failure(StatusCode::FORBIDDEN, "forbidden"),
        // Retained corruption is an unavailable authority, never a synthesized view.
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
    }
}
