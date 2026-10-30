//! Negative transport fixture: lose one actual signed controller HTTP reply.
//! It has transport credentials and public pins, never native/signing authority.
use super::*;
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use kedgeflow::{
    auth::WorkloadIdentity,
    endpoint::EndpointPolicy,
    error::{Error, Result},
    managed_drain_evidence::{Acceptance, ControlKind, Header},
    managed_drain_store::Context,
};

pub(super) struct Relay {
    context: Arc<Context>,
    upstream: String,
    origin: String,
    accept: reqwest::Client,
    query: reqwest::Client,
    pub accepts: AtomicUsize,
    pub discarded: AtomicUsize,
    discard: bool,
    response: std::sync::Mutex<Option<Acceptance>>,
}
pub(super) struct RunningRelay {
    pub relay: Arc<Relay>,
    _server: crate::live_agent::Running,
}
impl Relay {
    pub fn acceptance(&self) -> Acceptance {
        self.response
            .lock()
            .unwrap()
            .clone()
            .expect("actual signed original target reply")
    }
    fn verify(&self, a: &Acceptance, request: &Value) -> Result<()> {
        let (grant, _) = self.context.validate_origin(&a.origin)?;
        a.controller
            .verify("controller_state", &self.context.physical.controller)?;
        a.controller
            .body
            .validate(&self.context.physical.contract, &grant)?;
        a.proof
            .verify("controller_cas", &self.context.physical.controller)?;
        let signed = URL_SAFE_NO_PAD
            .decode(request["signed_grant"].as_str().unwrap_or_default())
            .map_err(|_| Error::Refused("relay original grant encoding".into()))?;
        if a.profile != kedgeflow::managed_drain::PROFILE
            || a.enrollment_digest != self.context.enrollment.digest()?
            || a.origin.signed_grant.as_bytes() != signed.as_slice()
            || request["attempt_id"] != a.origin.original.attempt_id
            || request["profile"] != kedgeflow::managed_drain::PROFILE
            || request["operation"] != "accept"
            || a.controller.body.accepted.attempt_id != a.origin.original.attempt_id
            || a.controller.body.accepted.grant_digest != a.origin.original.grant_digest
            || !a.controller.body.steps.is_empty() || a.controller.body.closed.is_some()
            || a.proof.body.kind != ControlKind::Accepted
            || a.proof.body.origin_digest != a.origin.digest()?
            || a.proof.body.enrollment_digest != a.enrollment_digest
            || a.proof.body.policy_digest != self.context.enrollment.policy.digest()?
            || a.proof.body.mechanical_digest != a.controller.digest()?
            || json!(a.proof.body.mechanical_header) != json!(Header::state(&a.controller))
            || a.proof.body.checked_at != a.controller.body.accepted.accepted_at
            || !a.events.last().is_some_and(|event| {
                event.at == a.proof.body.checked_at
                    && matches!(&event.change, kedgeflow::managed_drain_journal::Change::ControllerAccepted {proof_digest}
                        if a.proof.digest().is_ok_and(|digest| &digest == proof_digest))
            })
        {
            return Err(Error::Refused("relay signed original acceptance correlation".into()));
        }
        Ok(())
    }
}
pub(super) fn start(
    listener: tokio::net::TcpListener,
    upstream: String,
    context: Arc<Context>,
    identity: &[support::Pki],
    discard: bool,
) -> RunningRelay {
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let client = |i: usize| {
        kedgeflow::tls::pinned_http_client_pem(
            identity[i].ca.as_bytes(),
            identity[i].client.as_bytes(),
            identity[i].client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    };
    let relay = Arc::new(Relay {
        context,
        upstream,
        origin,
        accept: client(6),
        query: client(7),
        accepts: AtomicUsize::new(0),
        discarded: AtomicUsize::new(0),
        discard,
        response: std::sync::Mutex::new(None),
    });
    let tls = kedgeflow::tls::server_config_pem(
        identity[10].client.as_bytes(),
        identity[10].client_key.as_bytes(),
        identity[10].ca.as_bytes(),
    )
    .unwrap();
    let router = Router::new().fallback(handle).with_state(relay.clone());
    let server = crate::live_agent::Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, tls, router)
            .await
            .unwrap();
    }));
    RunningRelay {
        relay,
        _server: server,
    }
}
async fn handle(
    State(r): State<Arc<Relay>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    let path = request.uri().path().to_owned();
    let accept = match (path.as_str(), workload.as_str()) {
        ("/accept", "spiffe://test/gateway") => true,
        ("/query", "spiffe://test/outcome") => false,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if request.method() != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let endpoint = EndpointPolicy::new(&format!("{}{path}", r.origin)).unwrap();
    if let Some(status) = endpoint.rejection_status(request.headers(), request.uri()) {
        return status.into_response();
    }
    let authorization = request.headers().get(header::AUTHORIZATION).cloned();
    let Ok(body) = to_bytes(request.into_body(), 2 << 20).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    if accept {
        r.accepts.fetch_add(1, Ordering::SeqCst);
    }
    let client = if accept { &r.accept } else { &r.query };
    let mut forwarded = client
        .post(format!("{}{path}", r.upstream))
        .header(header::HOST, r.origin.strip_prefix("https://").unwrap())
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.clone());
    if let Some(value) = authorization {
        forwarded = forwarded.header(header::AUTHORIZATION, value);
    }
    let Ok(response) = forwarded.send().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status = response.status();
    let Ok(bytes) = bounded_reply(response).await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if accept && status == StatusCode::OK {
        let actual = kedgeflow::contracts::strict_value(&bytes)
            .and_then(|value| serde_json::from_value::<Acceptance>(value).map_err(Error::from));
        let original = kedgeflow::contracts::strict_value(&body);
        let Ok((actual, original)) =
            actual.and_then(|actual| original.map(|original| (actual, original)))
        else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        if r.verify(&actual, &original).is_err() {
            return StatusCode::BAD_GATEWAY.into_response();
        }
        *r.response.lock().unwrap() = Some(actual);
        if r.discard
            && r.discarded
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            // A real accepted reply was observed, then lost. No positive reply
            // or native state is synthesized, and the original request is not repeated.
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .unwrap()
}
async fn bounded_reply(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let limit = 2 << 20;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::Unavailable(
            "relay reply exceeds original acceptance bound".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit - bytes.len() {
            return Err(Error::Unavailable(
                "relay reply exceeds original acceptance bound".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
