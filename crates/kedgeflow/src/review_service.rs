//! Fixed native review-client endpoint; no browser, enrollment or execution route.
use crate::{
    auth::{DualAuthenticator, WorkloadIdentity},
    clock::Clock,
    contracts::strict_value,
    endpoint::EndpointPolicy,
    error::{Error, Result},
    ledger::EtcdLedger,
    review::{Approval, ReviewAssertion, ReviewFact},
    review_evidence::{Context, PROFILE, ReviewRegistration},
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RequestBody {
    Begin {
        profile: String,
        request_id: String,
        credential_id: String,
        proposal: String,
        descriptor: String,
        verdict: String,
    },
    Complete {
        profile: String,
        request_id: String,
        proposal: String,
        descriptor: String,
        approval: Box<Approval>,
        assertion: ReviewAssertion,
    },
}
pub struct ReviewService {
    registration: ReviewRegistration,
    ledger: EtcdLedger,
    clock: Arc<dyn Clock>,
    auth: DualAuthenticator,
    endpoint: EndpointPolicy,
    scope: String,
    reviewer_workload: String,
    key_id: String,
    signer: SigningKey,
    slots: Arc<tokio::sync::Semaphore>,
}
impl ReviewService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration: ReviewRegistration,
        ledger: EtcdLedger,
        clock: Arc<dyn Clock>,
        auth: DualAuthenticator,
        scope: String,
        reviewer_workload: String,
        key_id: String,
        signer: SigningKey,
    ) -> Result<Self> {
        registration.validate()?;
        if scope.is_empty()
            || scope.len() > 256
            || !crate::auth::valid_spiffe_id(&reviewer_workload)
            || reviewer_workload == registration.initiating_workload
            || key_id.is_empty()
            || registration
                .rule
                .credentials
                .values()
                .any(|e| e.reviewer.iss != auth.issuer())
            || crate::control_config::keys(&registration.proposal_keys)?
                .values()
                .chain(crate::control_config::keys(&registration.registry_keys)?.values())
                .any(|key| *key == signer.verifying_key())
        {
            return Err(Error::Invalid(
                "inconsistent review registration or signer role".into(),
            ));
        }
        let endpoint = EndpointPolicy::new(auth.external_url())?;
        if endpoint.path() != "/review" {
            return Err(Error::Invalid("review endpoint requires /review".into()));
        }
        Ok(Self {
            registration,
            ledger,
            clock,
            auth,
            endpoint,
            scope,
            reviewer_workload,
            key_id,
            signer,
            slots: Arc::new(tokio::sync::Semaphore::new(64)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn complete(
        &self,
        context: Context,
        approval: Approval,
        assertion: ReviewAssertion,
    ) -> Result<String> {
        if !self.registration.matches(&context.approval, &approval) {
            return Err(Error::Refused(
                "review approval changes server context".into(),
            ));
        }
        let fact = match self
            .ledger
            .resolved_review(&approval, &assertion, self.clock.as_ref())
            .await?
        {
            Some(fact) => fact,
            None => {
                let extra = self
                    .ledger
                    .review_context_compares(&self.registration, &context)
                    .await?;
                let verified = self
                    .ledger
                    .consume_review_checked(&approval, &assertion, self.clock.as_ref(), extra)
                    .await?;
                ReviewFact {
                    profile: crate::review_evidence::RESULT_PROFILE.into(),
                    approved: approval.verdict == "approve",
                    hardware_bound: false,
                    credential_id: assertion.credential_id.clone(),
                    enrollment_digest: crate::contracts::digest(
                        "review-enrollment",
                        &serde_json::to_value(
                            self.registration
                                .rule
                                .credentials
                                .get(&assertion.credential_id)
                                .ok_or_else(|| {
                                    Error::Refused("unknown review credential".into())
                                })?,
                        )?,
                    )?,
                    approval: verified.approval().clone(),
                    assertion_digest: verified.assertion_digest().into(),
                    sign_count: verified.sign_count(),
                    verified_at: verified.verified_at(),
                }
            }
        };
        self.ledger
            .publish_review(
                &self.registration,
                &context,
                &fact,
                &self.key_id,
                &self.signer,
                self.clock.as_ref(),
            )
            .await
    }
    async fn execute(
        &self,
        headers: &HeaderMap,
        workload: &WorkloadIdentity,
        raw: &[u8],
    ) -> Response {
        let identity = match self
            .auth
            .authenticate_shared_at(headers, workload, self.clock.now_ms() / 1000)
            .await
        {
            Ok(identity) => identity,
            Err(Error::Unavailable(_)) => {
                return failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "unavailable",
                    "authority_unavailable",
                );
            }
            Err(_) => return failure(StatusCode::UNAUTHORIZED, "unavailable", "unauthenticated"),
        };
        if identity.workload_id != self.reviewer_workload || !identity.scopes.contains(&self.scope)
        {
            return failure(StatusCode::FORBIDDEN, "unavailable", "forbidden");
        }
        let value = match strict_value(raw) {
            Ok(value) => value,
            Err(_) => return failure(StatusCode::BAD_REQUEST, "unavailable", "invalid_record"),
        };
        let id = value["request_id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .unwrap_or("unavailable")
            .to_owned();
        if !validate_request(&value) {
            return failure(StatusCode::BAD_REQUEST, &id, "invalid_record");
        }
        let body: RequestBody = match serde_json::from_value(value) {
            Ok(body) => body,
            Err(_) => return failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
        };
        let credential = match &body {
            RequestBody::Begin { credential_id, .. } => credential_id,
            RequestBody::Complete { assertion, .. } => &assertion.credential_id,
        };
        if self
            .registration
            .rule
            .credentials
            .get(credential)
            .is_none_or(|e| e.reviewer != identity.subject)
        {
            return failure(StatusCode::FORBIDDEN, &id, "forbidden");
        }
        let result=match body{
            RequestBody::Begin{profile,request_id,credential_id,proposal,descriptor,verdict} if profile==PROFILE=>{
                async {
                    let context=self.registration.context(&proposal,&descriptor,&credential_id,&verdict,self.clock.now_ms())?;
                    let extra=self.ledger.review_context_compares(&self.registration,&context).await?;
                    let approval=self.ledger.issue_review_checked(&credential_id,context.approval,self.clock.as_ref(),extra).await?;
                    Ok::<_,Error>(json!({"profile":PROFILE,"operation":"challenge","request_id":request_id,"credential_id":credential_id,"challenge":approval.challenge()?,"approval":approval,"rendered":context.rendered}))
                }.await
            }
            RequestBody::Complete{profile,request_id,proposal,descriptor,approval,assertion} if profile==PROFILE=>{
                async {
                    let context=self.registration.context(&proposal,&descriptor,&assertion.credential_id,&approval.verdict,self.clock.now_ms())?;
                    let witness=self.complete(context,*approval,assertion).await?;
                    Ok::<_,Error>(json!({"profile":PROFILE,"operation":"evidence","request_id":request_id,"witness":witness}))
                }.await
            }
            _=>Err(Error::Invalid("unsupported review request".into())),
        };
        match result {
            Ok(value) => ([("cache-control", "no-store")], Json(value)).into_response(),
            Err(Error::Invalid(_)) => failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
            Err(Error::Refused(_)) => failure(StatusCode::FORBIDDEN, &id, "forbidden"),
            _ => failure(
                StatusCode::SERVICE_UNAVAILABLE,
                &id,
                "authority_unavailable",
            ),
        }
    }
}
fn validate_request(value: &Value) -> bool {
    static PIN: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    PIN.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/review-evidence-http-v0.1.schema.json"
            ))
            .expect("review request schema"),
        )
        .expect("closed review request schema")
    })
    .is_valid(value)
}
fn failure(status: StatusCode, id: &str, code: &str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"profile":PROFILE,"operation":"failure","request_id":id,"code":code})),
    )
        .into_response()
}
async fn handle(
    State(service): State<Arc<ReviewService>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    if let Some(status) = service
        .endpoint
        .rejection_status(request.headers(), request.uri())
    {
        return failure(status, "unavailable", "invalid_record");
    }
    if request.method() != Method::POST {
        return failure(
            StatusCode::METHOD_NOT_ALLOWED,
            "unavailable",
            "invalid_record",
        );
    }
    if request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        != Some("application/json")
    {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unavailable",
            "invalid_record",
        );
    }
    if request.headers().contains_key("mcp-kedgeflow-grant")
        || request.headers().contains_key("mcp-kedgeflow-grant-ref")
    {
        return failure(StatusCode::BAD_REQUEST, "unavailable", "invalid_record");
    }
    let headers = request.headers().clone();
    let raw = match tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(request.into_body(), 1 << 20),
    )
    .await
    {
        Ok(Ok(raw)) => raw,
        _ => return failure(StatusCode::BAD_REQUEST, "unavailable", "invalid_record"),
    };
    let permit = match service.slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "authority_unavailable",
            );
        }
    };
    match tokio::spawn(async move {
        let _permit = permit;
        service.execute(&headers, &workload, &raw).await
    })
    .await
    {
        Ok(response) => response,
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "authority_unavailable",
        ),
    }
}
