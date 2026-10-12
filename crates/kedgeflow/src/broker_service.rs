//! Closed token-exchange binding. An immutable permit precedes one trusted mint;
//! failures never retry minting or release original claimed authority.
use crate::{
    auth::WorkloadIdentity,
    broker_authorization::{BrokerAuthorizer, ExchangeRequest},
    clock::Clock,
    endpoint::EndpointPolicy,
    error::{Error, Result},
    target_token::{TargetTokenMinter, TargetTokenVerifier},
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
pub const PROFILE: &str = "KF-BROKER-TOKEN-HTTP-0.1-draft";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const FIELDS: [&str; 11] = [
    "grant_type",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "requested_token_type",
    "audience",
    "scope",
    "kedgeflow_grant",
    "kedgeflow_grant_digest",
    "kedgeflow_attempt_id",
];
/// Reject malformed percent/UTF-8 instead of URL parser lossy normalization.
fn component(raw: &[u8]) -> Result<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => out.push(b' '),
            b'%' => {
                if i + 2 >= raw.len() || !raw[i + 1..i + 3].iter().all(u8::is_ascii_hexdigit) {
                    return Err(invalid());
                }
                let pair = std::str::from_utf8(&raw[i + 1..i + 3]).map_err(|_| invalid())?;
                out.push(u8::from_str_radix(pair, 16).map_err(|_| invalid())?);
                i += 2;
            }
            c => out.push(c),
        };
        i += 1;
    }
    String::from_utf8(out).map_err(|_| invalid())
}
pub fn decode_exchange(raw: &[u8]) -> Result<ExchangeRequest> {
    if raw.is_empty() || raw.len() > 2 << 20 {
        return Err(invalid());
    }
    let mut values = BTreeMap::new();
    for field in raw.split(|c| *c == b'&') {
        let pos = field.iter().position(|c| *c == b'=').ok_or_else(invalid)?;
        let key = component(&field[..pos])?;
        let value = component(&field[pos + 1..])?;
        if !FIELDS.contains(&key.as_str())
            || value.is_empty()
            || values.insert(key, value).is_some()
        {
            return Err(invalid());
        }
    }
    if values.len() != FIELDS.len()
        || values["grant_type"] != EXCHANGE
        || values["subject_token_type"] != ACCESS
        || values["actor_token_type"] != "urn:ietf:params:oauth:token-type:jwt"
        || values["requested_token_type"] != ACCESS
    {
        return Err(invalid());
    }
    let encoded = &values["kedgeflow_grant"];
    let signed = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
    if signed.is_empty() || signed.len() > 1 << 20 || URL_SAFE_NO_PAD.encode(&signed) != *encoded {
        return Err(invalid());
    }
    let signed_grant = String::from_utf8(signed).map_err(|_| invalid())?;
    Ok(ExchangeRequest {
        subject_token: values.remove("subject_token").expect("required"),
        actor_token: values.remove("actor_token").expect("required"),
        signed_grant,
        grant_digest: values.remove("kedgeflow_grant_digest").expect("required"),
        attempt_id: values.remove("kedgeflow_attempt_id").expect("required"),
        audience: values.remove("audience").expect("required"),
        scope: values.remove("scope").expect("required"),
    })
}
pub struct BrokerService {
    authorizer: BrokerAuthorizer,
    endpoint: EndpointPolicy,
    gateway: String,
    minter: Arc<dyn TargetTokenMinter>,
    verifier: TargetTokenVerifier,
    clock: Arc<dyn Clock>,
    slots: Arc<tokio::sync::Semaphore>,
}
impl BrokerService {
    pub fn new(
        authorizer: BrokerAuthorizer,
        external_url: &str,
        minter: Arc<dyn TargetTokenMinter>,
        verifier: TargetTokenVerifier,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let gateway = authorizer.gateway_workload().to_owned();
        if verifier
            .keys()
            .any(|k| authorizer.grant_keys().any(|g| g == k))
        {
            return Err(Error::Invalid("target/grant signing roles overlap".into()));
        }
        Ok(Self {
            authorizer,
            endpoint: EndpointPolicy::new(external_url)?,
            gateway,
            minter,
            verifier,
            clock,
            slots: Arc::new(tokio::sync::Semaphore::new(64)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn exchange(&self, request: ExchangeRequest, gateway: WorkloadIdentity) -> Result<Value> {
        let permit = self.authorizer.authorize(&request, &gateway).await?;
        let now = self.clock.now_ms();
        if now < permit.authorized_at || permit.expires_at - now < 1000 {
            return Err(Error::Refused("mint budget exhausted".into()));
        }
        let budget =
            Duration::from_millis((permit.expires_at - now) as u64).min(Duration::from_secs(5));
        let token = tokio::time::timeout(budget, self.minter.mint(&permit, now))
            .await
            .map_err(|_| Error::Unavailable("mint timed out".into()))?
            .map_err(|_| Error::Unavailable("mint provider failed".into()))?;
        let returned = self.clock.now_ms();
        if returned < now || returned >= permit.expires_at {
            return Err(Error::Refused("mint validity exhausted".into()));
        }
        let claims = self
            .verifier
            .verify_permit(&token, &permit, returned)
            .map_err(|_| Error::Unavailable("minted credential verification failed".into()))?;
        let replied = self.clock.now_ms();
        if replied < returned || replied >= permit.expires_at {
            return Err(Error::Refused("reply validity exhausted".into()));
        }
        let seconds = (claims.exp * 1000 - replied) / 1000;
        if !(1..=300).contains(&seconds) {
            return Err(Error::Refused("usable target lifetime exhausted".into()));
        }
        Ok(
            json!({"access_token":token,"issued_token_type":ACCESS,"token_type":"Bearer","expires_in":seconds,"scope":permit.target_scope}),
        )
    }
}
fn reply(status: StatusCode, v: Value) -> Response {
    (
        status,
        [("cache-control", "no-store"), ("pragma", "no-cache")],
        Json(v),
    )
        .into_response()
}
fn failure(status: StatusCode, code: &str) -> Response {
    reply(status, json!({"error":code}))
}
async fn handle(
    State(s): State<Arc<BrokerService>>,
    Extension(gateway): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    if let Some(status) = s
        .endpoint
        .rejection_status(request.headers(), request.uri())
    {
        return failure(status, "invalid_request");
    }
    if request.method() != Method::POST {
        return failure(StatusCode::METHOD_NOT_ALLOWED, "invalid_request");
    }
    if gateway.as_str() != s.gateway {
        return failure(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let mut content = request.headers().get_all("content-type").iter();
    if content.next().and_then(|v| v.to_str().ok()) != Some("application/x-www-form-urlencoded")
        || content.next().is_some()
    {
        return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_request");
    }
    let slot = match s.slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    };
    let raw = match tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(request.into_body(), 2 << 20),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let request = match decode_exchange(&raw) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    match tokio::spawn(async move {
        let _slot = slot;
        match tokio::time::timeout(Duration::from_secs(10), s.exchange(request, gateway)).await {
            Ok(Ok(v)) => reply(StatusCode::OK, v),
            Ok(Err(Error::Invalid(_))) => failure(StatusCode::BAD_REQUEST, "invalid_request"),
            Ok(Err(Error::Refused(_) | Error::NonceConsumed)) => {
                failure(StatusCode::BAD_REQUEST, "invalid_grant")
            }
            _ => failure(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        }
    })
    .await
    {
        Ok(r) => r,
        Err(_) => failure(StatusCode::INTERNAL_SERVER_ERROR, "temporarily_unavailable"),
    }
}
fn invalid() -> Error {
    Error::Invalid("closed token exchange form mismatch".into())
}
