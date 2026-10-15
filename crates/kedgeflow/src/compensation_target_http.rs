//! Fixed mTLS inverse target endpoints. Query and barrier have separate workload
//! and token pins; none accepts caller-selected routes, keys, SQL or restore data.
use crate::{
    auth::{WorkloadIdentity, valid_spiffe_id},
    clock::Clock,
    compensation_target::{Dispatch, PROFILE, TargetTrust},
    contracts::{GrantVerifier, strict_value},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    ledger::AuthoritativeObservation,
    postgres_action::Status,
    postgres_compensation::{CompensationStore, Outcome},
    reserved_lineage::Bundle,
    target_token::TargetTokenVerifier,
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    profile: String,
    operation: String,
    attempt_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BarrierRequest {
    profile: String,
    operation: String,
    forward: Bundle,
}
pub struct Service {
    pub(crate) trust: TargetTrust,
    grants: GrantVerifier,
    tokens: TargetTokenVerifier,
    store: Arc<dyn CompensationStore>,
    clock: Arc<dyn Clock>,
    endpoints: [EndpointPolicy; 3],
    barrier_workload: String,
    credentials: [[u8; 32]; 2],
    barrier_key_id: String,
    barrier_key: SigningKey,
    lifetime_ms: i64,
    slots: Arc<tokio::sync::Semaphore>,
}
impl Service {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust: TargetTrust,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        store: Arc<dyn CompensationStore>,
        clock: Arc<dyn Clock>,
        urls: [&str; 3],
        query_token: &str,
        barrier_token: &str,
        barrier_workload: String,
        key_id: String,
        key: SigningKey,
        lifetime_ms: i64,
    ) -> Result<Self> {
        trust.validate(&grants)?;
        let endpoints = [
            EndpointPolicy::new(urls[0])?,
            EndpointPolicy::new(urls[1])?,
            EndpointPolicy::new(urls[2])?,
        ];
        let barrier_keys = crate::control_config::keys(&trust.contract.barrier_keys)?;
        let app_keys = crate::control_config::keys(&trust.contract.applicability_keys)?;
        if endpoints
            .iter()
            .any(|e| e.authority() != endpoints[0].authority())
            || endpoints[0].path() == endpoints[1].path()
            || endpoints[0].path() == endpoints[2].path()
            || endpoints[1].path() == endpoints[2].path()
            || [query_token, barrier_token]
                .iter()
                .any(|t| t.len() < 32 || t.len() > 16384 || t.trim() != *t)
            || query_token == barrier_token
            || !valid_spiffe_id(&barrier_workload)
            || barrier_workload == trust.registration.gateway_workload
            || barrier_workload == trust.registration.query_workload
            || barrier_keys.get(&key_id) != Some(&key.verifying_key())
            || !(1..=60000).contains(&lifetime_ms)
            || tokens.keys().any(|t| {
                grants
                    .keys
                    .values()
                    .chain(barrier_keys.values())
                    .chain(app_keys.values())
                    .chain(trust.outcome_keys.values())
                    .any(|k| k == t)
            })
        {
            return Err(Error::Refused(
                "inverse target endpoint or role pins refused".into(),
            ));
        }
        Ok(Self {
            trust,
            grants,
            tokens,
            store,
            clock,
            endpoints,
            barrier_workload,
            credentials: [
                Sha256::digest(query_token.as_bytes()).into(),
                Sha256::digest(barrier_token.as_bytes()).into(),
            ],
            barrier_key_id: key_id,
            barrier_key: key,
            lifetime_ms,
            slots: Arc::new(tokio::sync::Semaphore::new(16)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    pub async fn dispatch(&self, raw: &[u8], token: &str) -> Result<Outcome> {
        let request = Dispatch::decode(raw)?;
        let bound = self.trust.bind(
            &self.grants,
            &self.tokens,
            &request,
            token,
            self.clock.now_ms(),
        )?;
        let outcome = self.store.apply(&bound).await?;
        Outcome::verify(&serde_json::to_vec(&outcome)?, &bound)
    }
    async fn operation(&self, kind: usize, raw: &[u8], token: &str) -> Result<Option<Value>> {
        if kind == 0 {
            return Ok(Some(serde_json::to_value(
                self.dispatch(raw, token).await?,
            )?));
        }
        let v = strict_value(raw)?;
        if kind == 2 {
            let q: BarrierRequest = serde_json::from_value(v)?;
            if q.profile != PROFILE || q.operation != "barrier" {
                return Err(Error::Invalid("invalid barrier request".into()));
            }
            let b = Bundle::decode(&serde_json::to_vec(&q.forward)?)?;
            let s = self
                .trust
                .barrier(
                    self.store.as_ref(),
                    &b,
                    self.clock.now_ms(),
                    self.lifetime_ms,
                    &self.barrier_key_id,
                    &self.barrier_key,
                )
                .await?;
            if s.payload["expires_at"]
                .as_i64()
                .is_none_or(|at| self.clock.now_ms() >= at)
            {
                return Err(Error::Refused("barrier window exhausted".into()));
            }
            return Ok(Some(serde_json::to_value(s)?));
        }
        let q: Query = serde_json::from_value(v)?;
        if q.profile != crate::recovery::PROFILE
            || q.operation != "query"
            || q.attempt_id.is_empty()
            || q.attempt_id.len() > 128
        {
            return Err(Error::Invalid("invalid original inverse query".into()));
        }
        let Some(o) = self
            .store
            .lookup(&self.trust.registration.tenant, &q.attempt_id)
            .await?
        else {
            return Ok(None);
        };
        Outcome::verify(&serde_json::to_vec(&o)?, &o.request)?;
        let r = &o.request;
        let pin = &self.trust.registration;
        if r.resource != pin.resource
            || r.conflict_domain != pin.conflict_domain
            || r.gateway_workload != pin.gateway_workload
            || r.contract_digest != self.trust.contract.digest()?
        {
            return Err(Error::Refused(
                "inverse query outside protected scope".into(),
            ));
        }
        Ok(Some(json!(AuthoritativeObservation {
            attempt_id: r.attempt_id.clone(),
            root_id: r.root_id.clone(),
            grant_digest: r.grant_digest.clone(),
            target_reference: format!(
                "postgres-inverse:{}:{}:{}",
                r.tenant, r.resource.id, r.attempt_id
            ),
            status: match o.status {
                Status::Committed => "committed",
                Status::GuardRejected => "fenced_no_effect",
            }
            .into()
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
    let fail = |code, msg: &str| reply(code, json!({"error":msg}));
    let Some(kind) = s
        .endpoints
        .iter()
        .position(|e| request.uri().path() == e.path())
    else {
        return fail(StatusCode::NOT_FOUND, "invalid_endpoint");
    };
    if let Some(code) = s.endpoints[kind].rejection_status(request.headers(), request.uri()) {
        return fail(code, "invalid_endpoint");
    }
    if request.method() != Method::POST {
        return fail(StatusCode::METHOD_NOT_ALLOWED, "invalid_method");
    }
    let expected = match kind {
        0 => &s.trust.registration.gateway_workload,
        1 => &s.trust.registration.query_workload,
        _ => &s.barrier_workload,
    };
    if workload.as_str() != expected {
        return fail(StatusCode::UNAUTHORIZED, "invalid_workload");
    }
    let mut headers = request.headers().get_all("authorization").iter();
    let Some(token) = headers
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty() && v.len() <= 16384)
        .map(str::to_owned)
    else {
        return fail(StatusCode::UNAUTHORIZED, "invalid_credential");
    };
    if headers.next().is_some()
        || (kind > 0
            && <[u8; 32]>::from(Sha256::digest(token.as_bytes())) != s.credentials[kind - 1])
    {
        return fail(StatusCode::UNAUTHORIZED, "invalid_credential");
    }
    let mut types = request.headers().get_all("content-type").iter();
    if types.next().and_then(|v| v.to_str().ok()) != Some("application/json")
        || types.next().is_some()
    {
        return fail(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_content_type");
    }
    let Ok(slot) = s.slots.clone().try_acquire_owned() else {
        return fail(StatusCode::SERVICE_UNAVAILABLE, "target_unavailable");
    };
    let raw = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), 768 << 10),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return fail(StatusCode::BAD_REQUEST, "invalid_body"),
    };
    // Retain ownership across an HTTP disconnect. Timeout/drop is unknown; the
    // original SQL transaction may have committed and is resolved only by query.
    match tokio::spawn(async move {
        let _slot = slot;
        match tokio::time::timeout(Duration::from_secs(10), s.operation(kind, &raw, &token)).await {
            Ok(Ok(Some(v))) => reply(StatusCode::OK, v),
            Ok(Ok(None)) => reply(StatusCode::NOT_FOUND, json!({"error":"unknown_outcome"})),
            Ok(Err(Error::Invalid(_))) => {
                reply(StatusCode::BAD_REQUEST, json!({"error":"invalid_request"}))
            }
            Ok(Err(Error::Refused(_))) => {
                reply(StatusCode::FORBIDDEN, json!({"error":"request_refused"}))
            }
            _ => reply(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"outcome_unavailable"}),
            ),
        }
    })
    .await
    {
        Ok(v) => v,
        Err(_) => fail(StatusCode::INTERNAL_SERVER_ERROR, "outcome_unavailable"),
    }
}
