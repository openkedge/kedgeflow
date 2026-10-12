//! Separate current reporter authentication; durable historical receipt delivery only.
use crate::{
    auth::{DualAuthenticator, WorkloadIdentity},
    clock::Clock,
    contracts::{Envelope, GrantVerifier, Subject, canonical, strict_value},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    ledger::EtcdLedger,
    outcome_report::{Acknowledgement, PROFILE, sign_ack, validate},
    outcome_report_ledger::PreparedReport,
    recovery::Candidate,
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct ReporterTrust {
    pub tenant: String,
    pub conflict_domain: String,
    pub source_id: String,
    pub subject: Subject,
    pub required_scope: String,
    pub grants: GrantVerifier,
    pub outcome_keys: BTreeMap<String, VerifyingKey>,
}
impl ReporterTrust {
    pub fn validate(&self) -> Result<()> {
        for s in [
            &self.tenant,
            &self.conflict_domain,
            &self.source_id,
            &self.subject.iss,
            &self.subject.sub,
            &self.required_scope,
        ] {
            if s.is_empty() || s.len() > 1024 {
                return Err(Error::Invalid(
                    "incomplete outcome reporter registration".into(),
                ));
            }
        }
        if self.required_scope.split_whitespace().count() != 1
            || self.grants.keys.is_empty()
            || self.outcome_keys.is_empty()
            || self
                .outcome_keys
                .values()
                .any(|k| self.grants.keys.values().any(|g| k == g))
        {
            return Err(Error::Invalid(
                "invalid or overlapping outcome role registration".into(),
            ));
        }
        EndpointPolicy::new(&self.grants.audience)?;
        Ok(())
    }
    pub(crate) fn receipt(&self, signed_grant: &str, raw: &str) -> Result<(Candidate, Envelope)> {
        let grant = self.grants.verify_retained(signed_grant.as_bytes())?;
        if grant.grant.conflict_domain != self.conflict_domain
            || grant.grant.workload_id == self.source_id
        {
            return Err(Error::Refused("report outside registered domain".into()));
        }
        let e = crate::schema::verify_record(raw.as_bytes(), "receipt", &self.outcome_keys)?;
        let id = e.payload["attempt_id"]
            .as_str()
            .ok_or_else(|| Error::Invalid("receipt attempt required".into()))?;
        crate::recovery::verify_receipt_binding(
            &e,
            &grant.grant,
            &grant.digest,
            id,
            &self.source_id,
        )?;
        let status = e.payload["status"].as_str().unwrap_or_default();
        if !["committed", "unknown", "not_dispatched", "failed"].contains(&status)
            || e.payload["resolution_evidence"]
                .as_array()
                .is_none_or(|a| a.len() != 1)
            || e.payload["resolution_evidence"][0]["schema"] != crate::recovery::EVIDENCE_SCHEMA
        {
            return Err(Error::Invalid(
                "unsupported retained outcome receipt".into(),
            ));
        }
        Ok((
            Candidate {
                grant: grant.grant,
                attempt_id: id.into(),
            },
            e,
        ))
    }
}
pub struct OutcomeReportService {
    trust: ReporterTrust,
    ledger: EtcdLedger,
    auth: DualAuthenticator,
    endpoint: EndpointPolicy,
    collector_id: String,
    key_id: String,
    signer: SigningKey,
    clock: Arc<dyn Clock>,
    slots: Arc<tokio::sync::Semaphore>,
}
impl OutcomeReportService {
    pub fn new(
        trust: ReporterTrust,
        ledger: EtcdLedger,
        auth: DualAuthenticator,
        collector_id: String,
        key_id: String,
        signer: SigningKey,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        trust.validate()?;
        if collector_id.is_empty()
            || collector_id.len() > 1024
            || key_id.is_empty()
            || key_id.len() > 1024
            || trust.subject.iss != auth.issuer()
            || auth.external_url().len() > 1024
            || trust
                .outcome_keys
                .values()
                .chain(trust.grants.keys.values())
                .any(|k| k == &signer.verifying_key())
        {
            return Err(Error::Invalid(
                "invalid independent outcome collector".into(),
            ));
        }
        let endpoint = EndpointPolicy::new(auth.external_url())?;
        Ok(Self {
            trust,
            ledger,
            auth,
            endpoint,
            collector_id,
            key_id,
            signer,
            clock,
            slots: Arc::new(tokio::sync::Semaphore::new(64)),
        })
    }
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self)
    }
    async fn prepare(
        &self,
        signed_grant: &str,
        receipt: &str,
        evidence: Value,
    ) -> Result<PreparedReport> {
        let (candidate, e) = self.trust.receipt(signed_grant, receipt)?;
        let expected = Acknowledgement::expected(
            &e,
            &self.collector_id,
            self.auth.external_url(),
            &self.trust.tenant,
        )?;
        if e.payload["resolution_evidence"]
            != json!([{"id":expected.evidence_digest,"schema":crate::recovery::EVIDENCE_SCHEMA,"digest":expected.evidence_digest}])
        {
            return Err(Error::Invalid("receipt evidence reference mismatch".into()));
        }
        let previous = if let Some(rd) = &expected.previous_receipt_digest {
            let raw = self
                .ledger
                .retained_receipt(&candidate.grant, &candidate.attempt_id, rd)
                .await?;
            let (_, prev) = self.trust.receipt(signed_grant, &raw)?;
            let pa = Acknowledgement::expected(
                &prev,
                &self.collector_id,
                self.auth.external_url(),
                &self.trust.tenant,
            )?;
            if pa.receipt_digest != *rd || pa.attempt_id != expected.attempt_id {
                return Err(Error::Unknown("not_retained".into()));
            }
            Some((raw, pa))
        } else {
            None
        };
        Ok(PreparedReport {
            candidate,
            receipt: String::from_utf8(canonical(&serde_json::to_value(e)?)?)
                .map_err(|_| Error::Invalid("receipt encoding".into()))?,
            evidence,
            expected,
            previous,
        })
    }
    async fn execute(&self, command: Command) -> Result<Value> {
        let (id, report, write) = match command {
            Command::Report {
                request_id,
                signed_grant,
                signed_receipt,
                evidence,
                ..
            } => (
                request_id,
                self.prepare(&signed_grant, &signed_receipt, evidence)
                    .await?,
                true,
            ),
            Command::Query {
                request_id,
                signed_grant,
                attempt_id,
                receipt_digest,
                ..
            } => {
                let verified = self.trust.grants.verify_retained(signed_grant.as_bytes())?;
                if verified.grant.conflict_domain != self.trust.conflict_domain {
                    return Err(Error::Refused("query outside registered domain".into()));
                }
                let raw = self
                    .ledger
                    .retained_receipt(&verified.grant, &attempt_id, &receipt_digest)
                    .await?;
                let (_, e) = self.trust.receipt(&signed_grant, &raw)?;
                let a = Acknowledgement::expected(
                    &e,
                    &self.collector_id,
                    self.auth.external_url(),
                    &self.trust.tenant,
                )?;
                if a.attempt_id != attempt_id || a.receipt_digest != receipt_digest {
                    return Err(Error::Unknown("not_retained".into()));
                }
                let evidence = self
                    .ledger
                    .retained_report_evidence(&verified.grant, &a)
                    .await?;
                (
                    request_id,
                    self.prepare(&signed_grant, &raw, evidence).await?,
                    false,
                )
            }
        };
        let proposed = if write {
            let mut a = report.expected.clone();
            a.accepted_at = self.clock.now_ms();
            Some(sign_ack(a, &self.key_id, &self.signer)?)
        } else {
            None
        };
        let keys = BTreeMap::from([(self.key_id.clone(), self.signer.verifying_key())]);
        match self
            .ledger
            .acknowledge_report(&report, &keys, proposed.as_deref())
            .await?
        {
            Some(ack) => Ok(
                json!({"profile":PROFILE,"operation":"acknowledgement","request_id":id,"acknowledgement":ack}),
            ),
            None => Ok(
                json!({"profile":PROFILE,"operation":"missing","request_id":id,"receipt_digest":report.expected.receipt_digest}),
            ),
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Command {
    #[serde(rename = "report")]
    Report {
        #[serde(rename = "profile")]
        _profile: String,
        request_id: String,
        signed_grant: String,
        signed_receipt: String,
        evidence: Value,
    },
    #[serde(rename = "query")]
    Query {
        #[serde(rename = "profile")]
        _profile: String,
        request_id: String,
        signed_grant: String,
        attempt_id: String,
        receipt_digest: String,
    },
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
    State(s): State<Arc<OutcomeReportService>>,
    Extension(w): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    if let Some(status) = s
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
    let headers = request.headers().clone();
    let raw = match tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(request.into_body(), 2 << 20),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return failure(StatusCode::BAD_REQUEST, "unavailable", "invalid_record"),
    };
    let permit = match s.slots.clone().try_acquire_owned() {
        Ok(p) => p,
        _ => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "authority_unavailable",
            );
        }
    };
    match tokio::spawn(async move {
        let _permit = permit;
        let value = match strict_value(&raw) {
            Ok(v) => v,
            _ => return failure(StatusCode::BAD_REQUEST, "unavailable", "invalid_record"),
        };
        let id = value["request_id"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 1024)
            .unwrap_or("unavailable")
            .to_owned();
        if value["profile"] != PROFILE {
            return failure(StatusCode::BAD_REQUEST, &id, "unsupported_profile");
        }
        if validate(&value).is_err() {
            return failure(StatusCode::BAD_REQUEST, &id, "invalid_record");
        }
        let command = match serde_json::from_value::<Command>(value) {
            Ok(v) => v,
            _ => return failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
        };
        let identity = match s
            .auth
            .authenticate_at(&headers, &w, s.clock.now_ms() / 1000)
        {
            Ok(i) => i,
            Err(Error::Unavailable(_)) => {
                return failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &id,
                    "authority_unavailable",
                );
            }
            _ => return failure(StatusCode::UNAUTHORIZED, &id, "unauthenticated"),
        };
        if identity.subject != s.trust.subject
            || identity.workload_id != s.trust.source_id
            || !identity.scopes.contains(&s.trust.required_scope)
        {
            return failure(StatusCode::FORBIDDEN, &id, "forbidden");
        }
        match tokio::time::timeout(Duration::from_secs(5), s.execute(command)).await {
            Ok(Ok(v)) => reply(StatusCode::OK, v),
            Ok(Err(Error::Unknown(code)))
                if ["not_retained", "predecessor_required"].contains(&code.as_str()) =>
            {
                failure(StatusCode::CONFLICT, &id, &code)
            }
            Ok(Err(Error::Refused(_))) => failure(StatusCode::FORBIDDEN, &id, "forbidden"),
            Ok(Err(Error::Invalid(_))) => failure(StatusCode::BAD_REQUEST, &id, "invalid_record"),
            _ => failure(
                StatusCode::SERVICE_UNAVAILABLE,
                &id,
                "authority_unavailable",
            ),
        }
    })
    .await
    {
        Ok(r) => r,
        _ => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unavailable",
            "authority_unavailable",
        ),
    }
}
