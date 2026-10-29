//! Bounded draft admission/issuer endpoints and optional read-only status.
//! Administrative ledger methods are never HTTP routes.
use crate::{
    admission::{AdmissionPacket, AdmissionTrust, StoredAdmissionPacket},
    auth::{DualAuthenticator, Identity, WorkloadIdentity},
    clock::Clock,
    contracts::{Subject, canonical, record_digest, strict_value},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    issuance::GrantAuthority,
    ledger::EtcdLedger,
    policy::AdmissionController,
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::{sync::Arc, time::Duration};

pub const PROFILE: &str = "KF-LEAF-CONTROL-0.1-draft";

#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum ControlRequest {
    #[serde(rename = "admit")]
    Admit {
        profile: String,
        request_id: String,
        proposal: String,
        descriptor: String,
        manifest: String,
        witnesses: Vec<String>,
    },
    #[serde(rename = "issue")]
    Issue {
        profile: String,
        request_id: String,
        proposal: String,
        certificate: String,
    },
}

pub struct ControlPermissions {
    pub subjects: Vec<Subject>,
    pub admission_scope: String,
    pub issuance_scope: String,
}

pub struct ControlService {
    trust: Arc<AdmissionTrust>,
    controller: AdmissionController,
    issuer: GrantAuthority,
    ledger: EtcdLedger,
    clock: Arc<dyn Clock>,
    admit_auth: DualAuthenticator,
    issue_auth: DualAuthenticator,
    permissions: ControlPermissions,
    admit_endpoint: EndpointPolicy,
    issue_endpoint: EndpointPolicy,
    operations: Arc<tokio::sync::Semaphore>,
    status: Option<(DualAuthenticator, EndpointPolicy, String)>,
    leases: Option<(DualAuthenticator, EndpointPolicy, String)>,
    a2a_root: Option<Arc<crate::a2a_root_service::RootResolutionService>>,
}

impl ControlService {
    /// Read-only startup preparation; check-only configuration never calls this.
    pub async fn prepare_native_history(&self) -> Result<()> {
        self.ledger.prepare_selected_family_history().await
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust: Arc<AdmissionTrust>,
        controller: AdmissionController,
        issuer: GrantAuthority,
        ledger: EtcdLedger,
        clock: Arc<dyn Clock>,
        admit_auth: DualAuthenticator,
        issue_auth: DualAuthenticator,
        permissions: ControlPermissions,
    ) -> Result<Self> {
        let admit_endpoint = EndpointPolicy::new(admit_auth.external_url())?;
        let issue_endpoint = EndpointPolicy::new(issue_auth.external_url())?;
        trust.validate_configuration()?;
        if admit_auth.issuer() != issue_auth.issuer()
            || admit_auth.audience() != issue_auth.audience()
            || admit_endpoint.authority() != issue_endpoint.authority()
            || admit_endpoint.path() == issue_endpoint.path()
            || permissions.admission_scope.is_empty()
            || permissions.issuance_scope.is_empty()
            || permissions.admission_scope == permissions.issuance_scope
            || permissions.admission_scope == trust.required_scope
            || permissions.issuance_scope == trust.required_scope
            || permissions.subjects.is_empty()
            || permissions
                .subjects
                .iter()
                .any(|s| s.iss != admit_auth.issuer() || s.sub.is_empty())
            || !controller.configured_for(&trust)
            || !issuer.configured_for(&trust, &controller)
            || !issuer.reservation_configured(&ledger, &trust)
            || trust.registered_obligations_digest()? != trust.obligation_manifest_digest
        {
            return Err(Error::Invalid(
                "inconsistent control roles, endpoints or installed pins".into(),
            ));
        }
        Ok(Self {
            trust,
            controller,
            issuer,
            ledger,
            clock,
            admit_auth,
            issue_auth,
            permissions,
            admit_endpoint,
            issue_endpoint,
            operations: Arc::new(tokio::sync::Semaphore::new(64)),
            status: None,
            leases: None,
            a2a_root: None,
        })
    }

    /// Explicit opt-in; disclosure never shares an execution/control scope.
    pub fn with_status(mut self, auth: DualAuthenticator, scope: String) -> Result<Self> {
        let endpoint = EndpointPolicy::new(auth.external_url())?;
        if auth.issuer() != self.admit_auth.issuer()
            || auth.audience() != self.admit_auth.audience()
            || endpoint.authority() != self.admit_endpoint.authority()
            || endpoint.path() == self.admit_endpoint.path()
            || endpoint.path() == self.issue_endpoint.path()
            || self
                .leases
                .as_ref()
                .is_some_and(|(_, ep, s)| ep.path() == endpoint.path() || *s == scope)
            || scope.is_empty()
            || [
                &self.permissions.admission_scope,
                &self.permissions.issuance_scope,
                &self.trust.required_scope,
            ]
            .contains(&&scope)
        {
            return Err(Error::Invalid(
                "inconsistent status endpoint or disclosure scope".into(),
            ));
        }
        self.status = Some((auth, endpoint, scope));
        Ok(self)
    }

    /// Opt-in non-authorizing static prevalidation and leased final admission.
    pub fn with_leases(mut self, auth: DualAuthenticator, scope: String) -> Result<Self> {
        let endpoint = EndpointPolicy::new(auth.external_url())?;
        let (id, key) = self.controller.signing_role();
        if auth.issuer() != self.admit_auth.issuer()
            || auth.audience() != self.admit_auth.audience()
            || endpoint.authority() != self.admit_endpoint.authority()
            || endpoint.path() != "/leases"
            || [self.admit_endpoint.path(), self.issue_endpoint.path()].contains(&endpoint.path())
            || scope.is_empty()
            || [
                &self.permissions.admission_scope,
                &self.permissions.issuance_scope,
                &self.trust.required_scope,
            ]
            .contains(&&scope)
            || self.permissions.subjects.len() > 64
            || self
                .status
                .as_ref()
                .is_some_and(|(_, e, s)| e.path() == endpoint.path() || *s == scope)
            || self
                .trust
                .leases
                .as_ref()
                .is_none_or(|r| r.keys.get(id) != Some(&key))
        {
            return Err(Error::Invalid(
                "inconsistent lease endpoint, scope or admission-role key".into(),
            ));
        }
        self.leases = Some((auth, endpoint, scope));
        Ok(self)
    }

    async fn execute_lease(&self, identity: &Identity, raw: &[u8]) -> Result<serde_json::Value> {
        if !crate::lease_http::validate(raw) {
            return Err(Error::Invalid("invalid static lease request".into()));
        }
        let body: crate::lease_http::Request = serde_json::from_value(strict_value(raw)?)?;
        let (id, packet, prevalidate) = body.packet();
        if prevalidate {
            let evidence: Vec<_> = packet
                .witnesses
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();
            let lease = self
                .ledger
                .prevalidate_lease(
                    &self.trust,
                    &self.controller,
                    identity,
                    AdmissionPacket {
                        lease: None,
                        proposal: packet.proposal.as_bytes(),
                        descriptor: packet.descriptor.as_bytes(),
                        manifest: packet.manifest.as_bytes(),
                        evidence: &evidence,
                    },
                    self.clock.as_ref(),
                )
                .await?;
            Ok(
                json!({"profile":crate::leases::PROFILE,"operation":"prevalidated","request_id":id,"lease":lease}),
            )
        } else {
            let certificate = self.admit(identity, packet).await?;
            Ok(
                json!({"profile":crate::leases::PROFILE,"operation":"admitted","request_id":id,"certificate":certificate}),
            )
        }
    }

    async fn operation_status(&self, identity: &Identity, raw: &[u8]) -> Result<serde_json::Value> {
        use crate::ledger::AuthorityLedger;
        crate::operation_status::validate(raw)?;
        let request: crate::operation_status::Lookup =
            serde_json::from_value(strict_value(raw)?)
                .map_err(|_| Error::Invalid("invalid operation lookup".into()))?;
        let key = self
            .trust
            .historical_operation_key(identity, request.proposal.as_bytes())?;
        let proposal = crate::schema::verify_record(
            request.proposal.as_bytes(),
            "proposal",
            &self.trust.proposal_keys,
        )?;
        let Some((issued, bundle)) = self.ledger.retained_operation(&key).await? else {
            return Ok(
                json!({"profile":crate::operation_status::PROFILE,"operation":"status_result","request_id":request.request_id,"state":"unissued","attempt_id":null,"grant_digest":null}),
            );
        };
        let original = crate::schema::verify_record(
            bundle.packet.proposal.as_bytes(),
            "proposal",
            &self.trust.proposal_keys,
        )
        .map_err(|_| Error::Unavailable("invalid historical proposal".into()))?;
        if record_digest(&original)? != record_digest(&proposal)? {
            return Err(Error::Refused(
                "operation proposal differs from retained admission".into(),
            ));
        }
        let verified = self
            .issuer
            .verify_retained(issued.signed_grant.as_bytes())
            .map_err(|_| Error::Unavailable("invalid historical grant".into()))?;
        let g = &verified.grant;
        if verified.digest != issued.grant_digest
            || g.proposal_digest != record_digest(&proposal)?
            || g.certificate_digest != bundle.record.certificate_digest
            || g.subject != identity.subject
            || g.workload_id != identity.workload_id
            || g.dpop_jkt != identity.dpop_jkt
        {
            return Err(Error::Unavailable(
                "historical grant correlation mismatch".into(),
            ));
        }
        let status = self
            .ledger
            .execution_status(g, &verified.digest)
            .await
            .map_err(|_| Error::Unavailable("historical execution state unavailable".into()))?;
        let value = json!({"profile":crate::operation_status::PROFILE,"operation":"status_result","request_id":request.request_id,"state":status.state,"attempt_id":status.attempt_id,"grant_digest":status.grant_digest});
        crate::operation_status::validate(&canonical(&value)?)?;
        Ok(value)
    }

    fn authorize(&self, identity: &Identity, admit: bool) -> Result<()> {
        let scope = if admit {
            &self.permissions.admission_scope
        } else {
            &self.permissions.issuance_scope
        };
        if !identity.scopes.contains(scope)
            || identity.workload_id != self.trust.proposal_workload_id
            || !self.permissions.subjects.contains(&identity.subject)
        {
            return Err(Error::Refused(
                "caller lacks control operation permission".into(),
            ));
        }
        Ok(())
    }

    async fn admit(&self, identity: &Identity, packet: StoredAdmissionPacket) -> Result<String> {
        let evidence: Vec<Vec<u8>> = packet
            .witnesses
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        let inputs = self.trust.verify_inputs(
            identity,
            AdmissionPacket {
                lease: packet.lease.as_deref().map(str::as_bytes),
                proposal: packet.proposal.as_bytes(),
                descriptor: packet.descriptor.as_bytes(),
                manifest: packet.manifest.as_bytes(),
                evidence: &evidence,
            },
            self.clock.as_ref(),
        )?;
        let prepared = self.controller.prepare(&inputs, self.clock.as_ref())?;
        let admitted = self.ledger.admit(&prepared, self.clock.as_ref()).await?;
        Ok(admitted.record.signed_certificate)
    }

    async fn issue(
        &self,
        identity: &Identity,
        proposal: &str,
        certificate: &str,
    ) -> Result<crate::ledger::IssuanceResult> {
        let key = self.trust.operation_key(identity, proposal.as_bytes())?;
        let retained = self
            .ledger
            .admission_bundle(&key, self.clock.as_ref())
            .await?;
        // Accept harmless JSON whitespace differences only after strict parsing.
        // A different signature, ID, time, constraint or certificate conflicts.
        if canonical(&strict_value(certificate.as_bytes())?)?
            != retained.record.signed_certificate.as_bytes()
        {
            return Err(Error::Refused(
                "certificate differs from retained admission".into(),
            ));
        }
        let request_proposal = crate::schema::verify_record(
            proposal.as_bytes(),
            "proposal",
            &self.trust.proposal_keys,
        )?;
        let old_proposal = crate::schema::verify_record(
            retained.packet.proposal.as_bytes(),
            "proposal",
            &self.trust.proposal_keys,
        )?;
        if record_digest(&request_proposal)? != record_digest(&old_proposal)? {
            return Err(Error::Refused(
                "proposal differs from retained admission".into(),
            ));
        }
        let evidence: Vec<Vec<u8>> = retained
            .packet
            .witnesses
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        let inputs = self.trust.verify_inputs(
            identity,
            AdmissionPacket {
                lease: retained.packet.lease.as_deref().map(str::as_bytes),
                proposal: retained.packet.proposal.as_bytes(),
                descriptor: retained.packet.descriptor.as_bytes(),
                manifest: retained.packet.manifest.as_bytes(),
                evidence: &evidence,
            },
            self.clock.as_ref(),
        )?;
        self.issuer
            .issue(
                &self.ledger,
                &inputs,
                retained.record.signed_certificate.as_bytes(),
                self.clock.as_ref(),
            )
            .await
    }

    pub fn with_a2a_root(
        mut self,
        service: Arc<crate::a2a_root_service::RootResolutionService>,
    ) -> Self {
        self.a2a_root = Some(service);
        self
    }
    pub fn router(self: Arc<Self>) -> Router {
        let extension = self.a2a_root.clone();
        let router = Router::new().fallback(handle).with_state(self);
        match extension {
            Some(service) => router.merge(service.router()),
            None => router,
        }
    }
}

fn failure_in(profile: &str, status: StatusCode, request_id: &str, code: &str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"profile":profile,"operation":"failure","request_id":request_id,"code":code})),
    )
        .into_response()
}

async fn handle(
    State(service): State<Arc<ControlService>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    let admit = request.uri().path() == service.admit_endpoint.path();
    let status = service
        .status
        .as_ref()
        .is_some_and(|(_, ep, _)| request.uri().path() == ep.path());
    let leases = service
        .leases
        .as_ref()
        .is_some_and(|(_, ep, _)| request.uri().path() == ep.path());
    let response_profile = if leases {
        crate::leases::PROFILE
    } else if status {
        crate::operation_status::PROFILE
    } else {
        PROFILE
    };
    let failure = |code, id: &str, reason: &str| failure_in(response_profile, code, id, reason);
    let endpoint = if leases {
        &service
            .leases
            .as_ref()
            .expect("configured lease endpoint")
            .1
    } else if status {
        &service.status.as_ref().expect("configured status").1
    } else if admit {
        &service.admit_endpoint
    } else if request.uri().path() == service.issue_endpoint.path() {
        &service.issue_endpoint
    } else {
        return failure(StatusCode::NOT_FOUND, "unavailable", "unsupported_profile");
    };
    if let Some(status) = endpoint.rejection_status(request.headers(), request.uri()) {
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
    if leases
        && (request.headers().contains_key("mcp-kedgeflow-grant")
            || request.headers().contains_key("mcp-kedgeflow-grant-ref"))
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
    // A lost HTTP reply must not cancel a commit already in progress. A retry
    // with a fresh proof resolves the durable certificate/issuance records.
    // Bound these owned tasks separately from connections: disconnecting must
    // not free their capacity while a ledger operation is still running.
    let permit = match service.operations.clone().try_acquire_owned() {
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
        execute(service, &headers, &workload, &raw, admit, status, leases).await
    })
    .await
    {
        Ok(response) => response,
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unavailable",
            "authority_unavailable",
        ),
    }
}

async fn execute(
    service: Arc<ControlService>,
    headers: &HeaderMap,
    workload: &WorkloadIdentity,
    raw: &[u8],
    admit: bool,
    status: bool,
    leases: bool,
) -> Response {
    let profile = if leases {
        crate::leases::PROFILE
    } else if status {
        crate::operation_status::PROFILE
    } else {
        PROFILE
    };
    let failure = |code, id: &str, reason: &str| failure_in(profile, code, id, reason);
    let auth = if leases {
        &service.leases.as_ref().expect("configured leases").0
    } else if status {
        &service.status.as_ref().expect("configured status").0
    } else if admit {
        &service.admit_auth
    } else {
        &service.issue_auth
    };
    let identity = match auth
        .authenticate_shared_at(headers, workload, service.clock.now_ms() / 1000)
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
    let authorized = if leases {
        identity
            .scopes
            .contains(&service.leases.as_ref().expect("configured leases").2)
            && identity.workload_id == service.trust.proposal_workload_id
            && service.permissions.subjects.contains(&identity.subject)
    } else if status {
        let scope = &service.status.as_ref().expect("configured status").2;
        identity.scopes.contains(scope)
            && identity.workload_id == service.trust.proposal_workload_id
            && service.permissions.subjects.contains(&identity.subject)
    } else {
        service.authorize(&identity, admit).is_ok()
    };
    if !authorized {
        return failure(StatusCode::FORBIDDEN, "unavailable", "forbidden");
    }
    if leases {
        let id = strict_value(raw)
            .ok()
            .and_then(|v| {
                v["request_id"]
                    .as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 1024)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unavailable".into());
        return match service.execute_lease(&identity, raw).await {
            Ok(value) => ([("cache-control", "no-store")], Json(value)).into_response(),
            Err(Error::Invalid(_)) => failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
            Err(Error::Refused(_)) => failure(StatusCode::FORBIDDEN, &id, "admission_denied"),
            _ => failure(
                StatusCode::SERVICE_UNAVAILABLE,
                &id,
                "authority_unavailable",
            ),
        };
    }
    let value = match strict_value(raw) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "unavailable", "invalid_record"),
    };
    let id = value["request_id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 1024)
        .unwrap_or("unavailable")
        .to_owned();
    if value["profile"] != profile {
        return failure(StatusCode::BAD_REQUEST, &id, "unsupported_profile");
    }
    if status {
        if headers.contains_key("mcp-kedgeflow-grant")
            || headers.contains_key("mcp-kedgeflow-grant-ref")
        {
            return failure(StatusCode::BAD_REQUEST, &id, "invalid_record");
        }
        return match tokio::time::timeout(
            Duration::from_secs(5),
            service.operation_status(&identity, raw),
        )
        .await
        {
            Ok(Ok(value)) => ([("cache-control", "no-store")], Json(value)).into_response(),
            Ok(Err(Error::Invalid(_))) => failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
            Ok(Err(Error::Refused(_))) => failure(StatusCode::FORBIDDEN, &id, "forbidden"),
            _ => failure(
                StatusCode::SERVICE_UNAVAILABLE,
                &id,
                "authority_unavailable",
            ),
        };
    }
    let parsed: ControlRequest = match serde_json::from_value(value) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
    };
    let result = match parsed {
        ControlRequest::Admit {
            profile,
            request_id,
            proposal,
            descriptor,
            manifest,
            witnesses,
        } if admit
            && profile == PROFILE
            && valid_id(&request_id)
            && witnesses.len() <= 64
            && [&proposal, &descriptor, &manifest]
                .iter()
                .all(|s| valid_record(s))
            && witnesses.iter().all(|s| valid_record(s)) =>
        {
            service
                .admit(
                    &identity,
                    StoredAdmissionPacket {
                        lease: None,
                        proposal,
                        descriptor,
                        manifest,
                        witnesses,
                    },
                )
                .await
                .map(|certificate| {
                    json!({
                        "profile": PROFILE, "operation": "admitted",
                        "request_id": request_id, "certificate": certificate
                    })
                })
        }
        ControlRequest::Issue {
            profile,
            request_id,
            proposal,
            certificate,
        } if !admit
            && profile == PROFILE
            && valid_id(&request_id)
            && valid_record(&proposal)
            && valid_record(&certificate) =>
        {
            service
                .issue(&identity, &proposal, &certificate)
                .await
                .map(|issued| {
                    json!({
                        "profile": PROFILE, "operation": "issued", "request_id": request_id,
                        "issuance_key": issued.record.issuance_key, "reused": issued.reused,
                        "grant": issued.record.signed_grant
                    })
                })
        }
        _ => return failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
    };
    match result {
        Ok(value) => ([("cache-control", "no-store")], Json(value)).into_response(),
        Err(Error::Unavailable(_)) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            &id,
            "authority_unavailable",
        ),
        Err(Error::Invalid(_)) => failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
        Err(_) => failure(
            StatusCode::FORBIDDEN,
            &id,
            if admit {
                "admission_denied"
            } else {
                "issuance_conflict"
            },
        ),
    }
}
fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024
}
fn valid_record(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1 << 20
}
