//! Fixed-scope administrative endpoints, independent from agent permissions.
use crate::{
    admission::AdmissionTrust,
    auth::{DualAuthenticator, Identity, WorkloadIdentity},
    clock::Clock,
    contracts::{Subject, record_digest, strict_value},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    governance::*,
    ledger::EtcdLedger,
    policy::{CedarAdmissionPolicy, CedarPolicyDefinition},
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub struct AdministrativeRole {
    pub subject: Subject,
    pub workload_id: String,
    pub scope: String,
    pub keys: BTreeMap<String, VerifyingKey>,
}
pub struct GovernanceTrust {
    pub registration: ControlRegistration,
    pub admission: AdmissionTrust,
    pub definition: CedarPolicyDefinition,
    pub admission_keys: BTreeMap<String, VerifyingKey>,
    pub issuer_keys: BTreeMap<String, VerifyingKey>,
    pub roles: BTreeMap<String, AdministrativeRole>,
}
impl GovernanceTrust {
    pub fn validate(&self) -> Result<()> {
        self.admission.validate_configuration()?;
        let r = &self.registration;
        let s = &r.scope;
        let a = &r.acknowledger;
        let ack_key = acknowledgement_keys(a)?;
        let mut previous = self
            .admission_keys
            .values()
            .chain(self.issuer_keys.values())
            .copied()
            .collect::<Vec<_>>();
        if self.admission_keys.is_empty()
            || self.issuer_keys.is_empty()
            || self
                .admission_keys
                .values()
                .any(|a| self.issuer_keys.values().any(|i| i == a))
            || r.issuer_keys
                != self
                    .issuer_keys
                    .iter()
                    .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                    .collect::<BTreeMap<_, _>>()
            || r.trust_digest
                != trust_digest(&self.admission, &self.admission_keys, &self.issuer_keys)?
        {
            return Err(Error::Invalid(
                "invalid admission/issuer trust registration".into(),
            ));
        }
        for key in ack_key.values().chain(previous.iter()) {
            if [
                &self.admission.proposal_keys,
                &self.admission.registry_keys,
                &self.admission.manifest_keys,
            ]
            .iter()
            .any(|m| m.values().any(|v| v == key))
                || self
                    .admission
                    .evidence
                    .values()
                    .any(|e| e.keys.values().any(|v| v == key))
            {
                return Err(Error::Invalid(
                    "control signer overlaps an input role".into(),
                ));
            }
        }
        if ack_key.values().any(|a| previous.contains(a)) {
            return Err(Error::Invalid(
                "acknowledger overlaps authority signer".into(),
            ));
        }

        let mut scopes = std::collections::BTreeSet::new();
        for kind in [
            "publish_policy",
            "register_descriptor",
            "install",
            "revoke",
            "query",
        ] {
            let role = self
                .roles
                .get(kind)
                .ok_or_else(|| Error::Invalid("missing administrative role".into()))?;
            if role.subject.sub.is_empty()
                || role.workload_id.is_empty()
                || role.workload_id == self.admission.proposal_workload_id
                || role.scope.is_empty()
                || role.scope == self.admission.required_scope
                || !scopes.insert(&role.scope)
                || (kind != "query" && role.keys.is_empty())
            {
                return Err(Error::Invalid(
                    "invalid independent administrator assignment".into(),
                ));
            }
            for k in role.keys.values() {
                if previous.contains(k)
                    || ack_key.values().any(|v| v == k)
                    || [
                        &self.admission.proposal_keys,
                        &self.admission.registry_keys,
                        &self.admission.manifest_keys,
                    ]
                    .iter()
                    .any(|m| m.values().any(|v| v == k))
                    || self
                        .admission
                        .evidence
                        .values()
                        .any(|e| e.keys.values().any(|v| v == k))
                {
                    return Err(Error::Invalid("administrative signer role overlap".into()));
                }
                previous.push(*k);
            }
        }
        if self.roles.len() != 5
            || r.tenant != self.admission.tenant
            || r.policy != self.admission.policy
            || r.ownership_epoch != self.admission.ownership_epoch
            || r.obligation_manifest_digest != self.admission.obligation_manifest_digest
            || s.action.digest != self.admission.descriptor_digest
            || !crate::grant_reference::valid_reference(&r.trust_digest)
            || s.conflict_domain.is_empty()
            || s.resource.id.is_empty()
            || s.resource.incarnation.is_empty()
            || s.action.id.is_empty()
            || s.action.version.is_empty()
            || a.component_id.is_empty()
            || a.workload_id.is_empty()
            || a.workload_id == self.admission.proposal_workload_id
            || a.key_id.is_empty()
            || a.max_lifetime_ms <= 0
            || a.max_lifetime_ms > 60000
            || self.definition.reference(r.policy.epoch)? != r.policy
        {
            return Err(Error::Invalid(
                "inconsistent approved control registration".into(),
            ));
        }
        crate::grant_reference::fixed_https(&s.audience)?;
        crate::contracts::validate_adapter_contract(&s.adapter_contract, &s.resource, None)?;
        let clauses = s.predicate_descriptor["clauses"]
            .as_array()
            .ok_or_else(|| Error::Invalid("registered predicate clauses".into()))?;
        if clauses.len() != 1
            || clauses[0]["kind"] != "version_eq"
            || serde_json::from_value::<crate::contracts::Resource>(clauses[0]["resource"].clone())?
                != s.resource
        {
            return Err(Error::Invalid("unsupported installed predicate".into()));
        }
        CedarAdmissionPolicy::new(self.definition.clone(), r.policy.clone())?;
        Ok(())
    }
    fn role_authorized(
        &self,
        kind: &str,
        identity: &Identity,
        workload: &WorkloadIdentity,
    ) -> Result<()> {
        let role = self
            .roles
            .get(kind)
            .ok_or_else(|| Error::Refused("unknown administrator role".into()))?;
        if identity.subject != role.subject
            || identity.workload_id != role.workload_id
            || workload.as_str() != role.workload_id
            || !identity.scopes.contains(&role.scope)
        {
            return Err(Error::Refused(
                "caller lacks scoped administrative role".into(),
            ));
        }
        Ok(())
    }
    fn verify(&self, raw: &str, kind: &str) -> Result<StoredControl> {
        let keys = if kind == "acknowledge" {
            acknowledgement_keys(&self.registration.acknowledger)?
        } else {
            self.roles
                .get(kind)
                .ok_or_else(|| Error::Invalid("unsupported administrative operation".into()))?
                .keys
                .clone()
        };
        match kind {
            "publish_policy" => {
                let (p, s): (PolicyPublication, _) = verify_control(raw, kind, &keys)?;
                if p.registration != self.registration
                    || crate::contracts::canonical(&serde_json::to_value(&p.definition)?)?
                        != crate::contracts::canonical(&serde_json::to_value(&self.definition)?)?
                {
                    return Err(Error::Refused(
                        "policy differs from approved registration".into(),
                    ));
                }
                Ok(s)
            }
            "register_descriptor" => {
                let (p, s): (DescriptorPublication, _) = verify_control(raw, kind, &keys)?;
                let d = crate::schema::verify_record(
                    p.descriptor.as_bytes(),
                    "ctd",
                    &self.admission.registry_keys,
                )?;
                let r = &self.registration;
                let scope = &r.scope;
                if p.registration != *r
                    || record_digest(&d)? != scope.action.digest
                    || d.payload["tenant"] != r.tenant
                    || d.payload["action"] != scope.action.id
                    || d.payload["version"] != scope.action.version
                    || d.payload["ownership_epoch"] != r.ownership_epoch
                    || d.payload["gateway_audience"] != scope.audience
                    || d.payload["concurrency"]["conflict_domain"] != scope.conflict_domain
                    || d.payload["adapter_contract"] != scope.adapter_contract
                    || d.payload["concurrency"]["predicate_descriptor"]
                        != scope.predicate_descriptor
                {
                    return Err(Error::Refused(
                        "descriptor registration scope mismatch".into(),
                    ));
                }
                Ok(s)
            }
            "install" => {
                let (i, s): (Installation, _) = verify_control(raw, kind, &keys)?;
                if i.registration != self.registration
                    || i.revision == 0
                    || i.revision > crate::contracts::MAX_SAFE_INTEGER
                    || i.expected_revision.checked_add(1) != Some(i.revision)
                    || !crate::grant_reference::valid_reference(&i.policy_publication_digest)
                    || !crate::grant_reference::valid_reference(&i.descriptor_publication_digest)
                {
                    return Err(Error::Refused(
                        "invalid installation revision or scope".into(),
                    ));
                }
                Ok(s)
            }
            "acknowledge" => {
                let (_, s): (Acknowledgement, _) = verify_control(raw, kind, &keys)?;
                Ok(s)
            }
            "revoke" => {
                let (r, s): (Revocation, _) = verify_control(raw, kind, &keys)?;
                if r.tenant != self.registration.tenant
                    || r.conflict_domain != self.registration.scope.conflict_domain
                    || r.revision != 1
                    || !crate::grant_reference::valid_reference(&r.reason_digest)
                    || match &r.target {
                        RevocationTarget::Domain => false,
                        RevocationTarget::Root { id } | RevocationTarget::Grant { id } => {
                            id.is_empty() || id.len() > 1024
                        }
                    }
                {
                    return Err(Error::Refused(
                        "revocation scope or revision mismatch".into(),
                    ));
                }
                Ok(s)
            }
            _ => Err(Error::Invalid("unsupported control kind".into())),
        }
    }
}
pub struct GovernanceService {
    trust: GovernanceTrust,
    ledger: EtcdLedger,
    auth: DualAuthenticator,
    endpoint: EndpointPolicy,
    clock: Arc<dyn Clock>,
    slots: Arc<tokio::sync::Semaphore>,
}
#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Command {
    #[serde(rename = "apply")]
    Apply {
        profile: String,
        request_id: String,
        record: String,
    },
    #[serde(rename = "query")]
    Query { profile: String, request_id: String },
}
impl GovernanceService {
    pub fn new(
        trust: GovernanceTrust,
        ledger: EtcdLedger,
        auth: DualAuthenticator,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        trust.validate()?;
        if trust.roles.values().any(|r| r.subject.iss != auth.issuer()) {
            return Err(Error::Invalid(
                "administrative subject issuer mismatch".into(),
            ));
        }
        let endpoint = EndpointPolicy::new(auth.external_url())?;
        Ok(Self {
            trust,
            ledger: ledger.with_clock(clock.clone()),
            auth,
            endpoint,
            clock,
            slots: Arc::new(tokio::sync::Semaphore::new(64)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn apply(&self, raw: &str, kind: &str) -> Result<StoredControl> {
        let verified = self.trust.verify(raw, kind)?;
        match kind {
            "publish_policy" | "register_descriptor" => {
                self.ledger.publish_control(&verified, kind).await
            }
            "install" => self.ledger.install_control(&verified).await,
            "acknowledge" => {
                let a = verified.payload("acknowledge")?;
                self.ledger
                    .acknowledge_in_domain(
                        &verified,
                        &a,
                        &self.trust.registration.scope.conflict_domain,
                    )
                    .await
            }
            "revoke" => self.ledger.revoke_control(&verified).await,
            _ => Err(Error::Invalid(
                "unsupported administrative operation".into(),
            )),
        }
    }
}
fn reply(status: StatusCode, value: Value) -> Response {
    (status, [("cache-control", "no-store")], Json(value)).into_response()
}
fn failure(status: StatusCode, id: &str, code: &str) -> Response {
    reply(
        status,
        json!({"profile":PROFILE,"operation":"failure","request_id":id,"code":code}),
    )
}
async fn handle(
    State(service): State<Arc<GovernanceService>>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    if let Some(status) = service
        .endpoint
        .rejection_status(request.headers(), request.uri())
    {
        return failure(status, "unavailable", "invalid_record");
    }
    if request.uri().path() != service.endpoint.path() {
        return failure(StatusCode::NOT_FOUND, "unavailable", "unsupported_profile");
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
    let headers = request.headers().clone();
    let raw = match tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(request.into_body(), 1 << 20),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
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
    // Keep the bounded mutation task alive after a lost HTTP reply.
    match tokio::spawn(async move {
        let _permit = permit;
        execute(service, workload, headers, &raw).await
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
    service: Arc<GovernanceService>,
    workload: WorkloadIdentity,
    headers: http::HeaderMap,
    raw: &[u8],
) -> Response {
    let value = match strict_value(raw) {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "unavailable", "invalid_record"),
    };
    let id = value["request_id"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 1024)
        .unwrap_or("unavailable")
        .to_owned();
    if value["profile"] != PROFILE {
        return failure(StatusCode::BAD_REQUEST, &id, "unsupported_profile");
    }
    if validate_control(&value).is_err() {
        return failure(StatusCode::BAD_REQUEST, &id, "invalid_record");
    }
    let command: Command = match serde_json::from_value(value) {
        Ok(command) => command,
        Err(_) => return failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
    };
    let (profile, request_id, kind, record) = match command {
        Command::Query {
            profile,
            request_id,
        } => (profile, request_id, "query".into(), None),
        Command::Apply {
            profile,
            request_id,
            record,
        } => {
            if record.is_empty() || record.len() > 1 << 20 {
                return failure(StatusCode::BAD_REQUEST, &id, "invalid_record");
            }
            let kind = match control_kind(&record) {
                Ok(kind) => kind,
                Err(_) => return failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
            };
            (profile, request_id, kind, Some(record))
        }
    };
    if profile != PROFILE {
        return failure(StatusCode::BAD_REQUEST, &id, "unsupported_profile");
    }
    if request_id.is_empty() || request_id.len() > 1024 {
        return failure(StatusCode::BAD_REQUEST, &id, "invalid_record");
    }
    if kind == "acknowledge" {
        if workload.as_str() != service.trust.registration.acknowledger.workload_id {
            return failure(StatusCode::FORBIDDEN, &id, "forbidden");
        }
    } else {
        let identity = match service
            .auth
            .authenticate_shared_at(&headers, &workload, service.clock.now_ms() / 1000)
            .await
        {
            Ok(identity) => identity,
            Err(Error::Unavailable(_)) => {
                return failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &id,
                    "authority_unavailable",
                );
            }
            Err(_) => return failure(StatusCode::UNAUTHORIZED, &id, "unauthenticated"),
        };
        if service
            .trust
            .role_authorized(&kind, &identity, &workload)
            .is_err()
        {
            return failure(StatusCode::FORBIDDEN, &id, "forbidden");
        }
    }
    let result = if let Some(raw) = record {
        service.apply(&raw, &kind).await.map(|stored| {
            json!({
                "profile": PROFILE, "operation": "applied", "request_id": request_id,
                "kind": kind, "digest": stored.digest, "record": stored.record
            })
        })
    } else {
        service
            .ledger
            .control_snapshot(&service.trust.registration.scope.conflict_domain)
            .await
            .map(|(installation, acknowledgement)| {
                json!({
                    "profile": PROFILE, "operation": "snapshot", "request_id": request_id,
                    "installation": installation, "acknowledgement": acknowledgement
                })
            })
    };
    match result {
        Ok(value) => reply(StatusCode::OK, value),
        Err(Error::Unavailable(_)) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            &id,
            "authority_unavailable",
        ),
        Err(Error::Invalid(_)) => failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
        Err(_) => failure(StatusCode::FORBIDDEN, &id, "control_refused"),
    }
}
