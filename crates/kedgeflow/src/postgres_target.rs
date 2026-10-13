//! RFC 0024 native target binding. The credential and original signed grant are
//! independently verified before fixed SQL operations; query is a separate role.
use crate::{
    auth::{WorkloadIdentity, valid_spiffe_id},
    clock::Clock,
    contracts::{Action, GrantVerifier, Resource, canonical, digest, strict_value},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    ledger::AuthoritativeObservation,
    postgres_action::{self, DispatchRequest, Outcome, Parameters, Status},
    postgres_store::ReservationStore,
    target_token::{TargetTokenVerifier, TokenBinding},
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

pub const PROFILE: &str = "KF-POSTGRES-TARGET-HTTP-0.1-draft";

pub fn validate(value: &Value) -> Result<()> {
    static PIN: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let pin = PIN.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/postgres-target-http-v0.1.schema.json"
            ))
            .expect("embedded target schema"),
        )
        .expect("local target schema")
    });
    if !pin.is_valid(value) {
        return Err(Error::Invalid("closed SQL target request mismatch".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub tenant: String,
    pub conflict_domain: String,
    pub action: Action,
    pub resource: Resource,
    pub adapter_contract: Value,
    pub predicate_id: String,
    pub predicate_version: String,
    pub gateway_workload: String,
    pub query_workload: String,
    pub target_audience: String,
    pub target_scope: String,
}
impl Registration {
    pub fn validate(&self) -> Result<()> {
        let sample = DispatchRequest {
            profile: postgres_action::PROFILE.into(),
            action: postgres_action::ACTION.into(),
            tenant: self.tenant.clone(),
            conflict_domain: self.conflict_domain.clone(),
            attempt_id: "validation".into(),
            grant_digest: "a".repeat(64),
            root_id: "validation".into(),
            resource: self.resource.clone(),
            expected_version: 1,
            fence: 1,
            reservation: "validation".into(),
            gateway_workload: self.gateway_workload.clone(),
            expires_at: 1,
        };
        postgres_action::validate(&serde_json::to_value(sample)?)?;
        crate::contracts::validate_adapter_contract(
            &self.adapter_contract,
            &self.resource,
            Some("fence"),
        )?;
        if self.action.id.is_empty()
            || self.action.version.is_empty()
            || !crate::grant_reference::valid_reference(&self.action.digest)
            || self.predicate_id.is_empty()
            || self.predicate_version.is_empty()
            || !valid_spiffe_id(&self.gateway_workload)
            || !valid_spiffe_id(&self.query_workload)
            || self.gateway_workload == self.query_workload
            || self.target_scope.is_empty()
        {
            return Err(Error::Invalid(
                "invalid PostgreSQL target registration".into(),
            ));
        }
        EndpointPolicy::new(&self.target_audience)?;
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dispatch {
    pub profile: String,
    pub operation: String,
    pub signed_grant: String,
    pub attempt_id: String,
    pub parameters: Parameters,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    profile: String,
    operation: String,
    attempt_id: String,
}

pub struct TargetService {
    registration: Registration,
    grants: GrantVerifier,
    tokens: TargetTokenVerifier,
    store: Arc<dyn ReservationStore>,
    clock: Arc<dyn Clock>,
    dispatch_endpoint: EndpointPolicy,
    query_endpoint: EndpointPolicy,
    query_token_digest: [u8; 32],
    slots: Arc<tokio::sync::Semaphore>,
}
impl TargetService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration: Registration,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        store: Arc<dyn ReservationStore>,
        clock: Arc<dyn Clock>,
        dispatch_url: &str,
        query_url: &str,
        query_token: &str,
    ) -> Result<Self> {
        registration.validate()?;
        let dispatch_endpoint = EndpointPolicy::new(dispatch_url)?;
        let query_endpoint = EndpointPolicy::new(query_url)?;
        EndpointPolicy::new(&grants.audience)?;
        if grants.keys.is_empty()
            || query_token.len() < 32
            || query_token.len() > 16384
            || query_token.trim() != query_token
            || dispatch_endpoint.authority() != query_endpoint.authority()
            || dispatch_endpoint.path() == query_endpoint.path()
            || tokens.keys().any(|t| grants.keys.values().any(|g| g == t))
        {
            return Err(Error::Invalid(
                "invalid target endpoint/key/role pins".into(),
            ));
        }
        Ok(Self {
            registration,
            grants,
            tokens,
            store,
            clock,
            dispatch_endpoint,
            query_endpoint,
            query_token_digest: Sha256::digest(query_token.as_bytes()).into(),
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn dispatch(&self, raw: &[u8], token: &str) -> Result<Outcome> {
        let value = strict_value(raw)?;
        validate(&value)?;
        let request: Dispatch = serde_json::from_value(value)?;
        let bound = bind_dispatch(
            &self.registration,
            &self.grants,
            &self.tokens,
            self.clock.now_ms(),
            request,
            token,
        )?;
        let result = self.store.apply(&bound).await?;
        Outcome::verify(&serde_json::to_vec(&result)?, &bound)
    }
    async fn query(&self, raw: &[u8]) -> Result<Option<AuthoritativeObservation>> {
        let value = strict_value(raw)?;
        validate(&value)?;
        let q: Query = serde_json::from_value(value)?;
        if q.profile != crate::recovery::PROFILE
            || q.operation != "query"
            || q.attempt_id.is_empty()
            || q.attempt_id.len() > 128
        {
            return Err(Error::Invalid("invalid target outcome query".into()));
        }
        let Some(outcome) = self
            .store
            .lookup(&self.registration.tenant, &q.attempt_id)
            .await?
        else {
            return Ok(None);
        };
        // Verify stored semantic shape as well as the fixed service's disclosure scope.
        Outcome::verify(&serde_json::to_vec(&outcome)?, &outcome.request)?;
        let r = &outcome.request;
        if r.tenant != self.registration.tenant
            || r.attempt_id != q.attempt_id
            || r.resource != self.registration.resource
            || r.conflict_domain != self.registration.conflict_domain
            || r.gateway_workload != self.registration.gateway_workload
        {
            return Err(Error::Unknown("out-of-scope retained SQL result".into()));
        }
        Ok(Some(AuthoritativeObservation {
            attempt_id: r.attempt_id.clone(),
            root_id: r.root_id.clone(),
            grant_digest: r.grant_digest.clone(),
            status: match outcome.status {
                Status::Committed => "committed",
                Status::GuardRejected => "fenced_no_effect",
            }
            .into(),
            target_reference: format!("postgres:{}:{}:{}", r.tenant, r.resource.id, r.attempt_id),
        }))
    }
}
pub(crate) fn bind_dispatch(
    pin: &Registration,
    grants: &GrantVerifier,
    tokens: &TargetTokenVerifier,
    now: i64,
    request: Dispatch,
    token: &str,
) -> Result<DispatchRequest> {
    if request.profile != PROFILE || request.operation != "dispatch" {
        return Err(Error::Invalid("unsupported target dispatch profile".into()));
    }
    let parameters = serde_json::to_value(&request.parameters)?;
    postgres_action::validate(&parameters)?;
    let signed = URL_SAFE_NO_PAD
        .decode(&request.signed_grant)
        .map_err(|_| Error::Invalid("invalid signed grant carriage".into()))?;
    if signed.len() > 1 << 20 || URL_SAFE_NO_PAD.encode(&signed) != request.signed_grant {
        return Err(Error::Invalid("invalid signed grant carriage".into()));
    }
    let verified = grants.verify(&signed, now)?;
    let grant = &verified.grant;

    let predicate = json!({"id":pin.predicate_id,"version":pin.predicate_version,
            "language":"kf-conjunction-v1","clauses":[{"kind":"version_eq",
            "resource":pin.resource,"expected_version":request.parameters.expected_version.to_string()}]});
    if grant.action != pin.action
        || grant.resources != [pin.resource.clone()]
        || request.parameters.resource_id != pin.resource.id
        || grant.conflict_domain != pin.conflict_domain
        || grant.parameters_digest != digest("parameters", &parameters)?
        || canonical(&grant.adapter_contract)? != canonical(&pin.adapter_contract)?
        || canonical(&grant.predicate_descriptor)? != canonical(&predicate)?
    {
        return Err(Error::Refused(
            "SQL grant/registered action mismatch".into(),
        ));
    }
    let claims = tokens.verify(
        token,
        &TokenBinding {
            grant_digest: verified.digest.clone(),
            root_id: grant.root_id.clone(),
            attempt_id: request.attempt_id.clone(),
            gateway_workload: pin.gateway_workload.clone(),
            audience: pin.target_audience.clone(),
            scope: pin.target_scope.clone(),
            max_expires_at: grant.expires_at,
        },
        now,
    )?;
    let bound = DispatchRequest {
        profile: postgres_action::PROFILE.into(),
        action: postgres_action::ACTION.into(),
        tenant: pin.tenant.clone(),
        conflict_domain: pin.conflict_domain.clone(),
        attempt_id: request.attempt_id,
        grant_digest: verified.digest,
        root_id: grant.root_id.clone(),
        resource: pin.resource.clone(),
        expected_version: request.parameters.expected_version,
        fence: grant.fence,
        reservation: request.parameters.reservation,
        gateway_workload: pin.gateway_workload.clone(),
        expires_at: (claims.exp * 1000) as u64,
    };
    postgres_action::validate(&serde_json::to_value(&bound)?)?;
    Ok(bound)
}

fn bearer(headers: &HeaderMap) -> Result<String> {
    let mut values = headers.get_all("authorization").iter();
    let value = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty() && v.len() <= 16384)
        .ok_or_else(|| Error::Refused("target credential required".into()))?;
    if values.next().is_some() {
        return Err(Error::Refused("duplicate target credential".into()));
    }
    Ok(value.into())
}
fn reply(status: StatusCode, value: Value) -> Response {
    (
        status,
        [("cache-control", "no-store"), ("pragma", "no-cache")],
        Json(value),
    )
        .into_response()
}
async fn handle(
    State(s): State<Arc<TargetService>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    let failure = |status, code: &str| reply(status, json!({"error":code}));
    let query = request.uri().path() == s.query_endpoint.path();
    let endpoint = if query {
        &s.query_endpoint
    } else {
        &s.dispatch_endpoint
    };
    if let Some(status) = endpoint.rejection_status(request.headers(), request.uri()) {
        return failure(status, "invalid_endpoint");
    }
    if request.method() != Method::POST {
        return failure(StatusCode::METHOD_NOT_ALLOWED, "invalid_method");
    }
    if workload.as_str()
        != if query {
            &s.registration.query_workload
        } else {
            &s.registration.gateway_workload
        }
    {
        return failure(StatusCode::UNAUTHORIZED, "invalid_workload");
    }
    let token = match bearer(request.headers()) {
        Ok(t) => t,
        Err(_) => return failure(StatusCode::UNAUTHORIZED, "invalid_credential"),
    };
    let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if query && token_digest != s.query_token_digest {
        return failure(StatusCode::UNAUTHORIZED, "invalid_credential");
    }
    let mut types = request.headers().get_all("content-type").iter();
    if types.next().and_then(|v| v.to_str().ok()) != Some("application/json")
        || types.next().is_some()
    {
        return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_content_type");
    }
    let slot = match s.slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "target_unavailable"),
    };
    let raw = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), 2 << 20),
    )
    .await
    {
        Ok(Ok(b)) => b,
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_body"),
    };
    match tokio::spawn(async move {
        let _slot = slot;
        let operation = async {
            if query {
                s.query(&raw)
                    .await
                    .map(|v| v.map(|v| serde_json::to_value(v).expect("observation")))
            } else {
                s.dispatch(&raw, &token)
                    .await
                    .map(|v| Some(serde_json::to_value(v).expect("outcome")))
            }
        };
        match tokio::time::timeout(Duration::from_secs(10), operation).await {
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
        Ok(r) => r,
        Err(_) => failure(StatusCode::INTERNAL_SERVER_ERROR, "outcome_unavailable"),
    }
}
