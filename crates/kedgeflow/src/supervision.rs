//! Bounded owned incidents and ordered delivery; no execution capability.
use crate::{
    clock::Clock,
    contracts::{Envelope, digest, strict_value},
    error::{Error, Result},
    outcome_report::Acknowledgement,
    outcome_report_client::{DeliveryReceipt, OutcomeReportClient},
    recovery::{Candidate, RecoveryWorker},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
pub const PROFILE: &str = "KF-OUTCOME-SUPERVISION-0.1-draft";
pub fn validate(v: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let s = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/outcome-supervision-v0.1.schema.json"
            ))
            .expect("embedded supervision schema"),
        )
        .expect("valid supervision schema")
    });
    if !s.is_valid(v) {
        return Err(Error::Invalid("closed supervision record mismatch".into()));
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentPolicy {
    pub owner_id: String,
    pub unknown_after_ms: i64,
}
impl IncidentPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.owner_id.trim().is_empty()
            || self.owner_id.len() > 1024
            || !(1..=604800000).contains(&self.unknown_after_ms)
        {
            return Err(Error::Invalid(
                "invalid incident owner/deadline policy".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn digest(&self, tenant: &str) -> Result<String> {
        self.validate()?;
        digest("incident-policy", &json!({"tenant":tenant,"policy":self}))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub profile: String,
    pub incident_id: String,
    pub tenant: String,
    pub grant_digest: String,
    pub root_id: String,
    pub attempt_id: String,
    pub owner_id: String,
    pub policy_digest: String,
    pub unknown_since: i64,
    pub deadline: i64,
    pub revision: u64,
    pub state: String,
    pub updated_at: i64,
    pub receipt_digest: String,
    pub previous_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProgress {
    pub profile: String,
    pub collector_digest: String,
    pub receipt_digest: String,
    pub acknowledgement: String,
    pub recorded_at: i64,
}
pub(crate) fn collector_key(a: &Acknowledgement) -> Result<String> {
    digest(
        "outcome-collector",
        &json!({"id":a.collector_id,"url":a.collector_url}),
    )
}
#[derive(Debug, Serialize)]
pub struct SupervisionSweep {
    pub examined: usize,
    pub recovered: usize,
    pub deferred: usize,
    pub unavailable: usize,
    pub incidents_opened: usize,
    pub incidents_escalated: usize,
    pub incidents_resolved: usize,
    pub delivered: usize,
    pub delivery_deferred: usize,
    pub next_cursor: Option<String>,
}
/// Read-only bounded observation of retained state. Counts are sampled, not an
/// atomic global snapshot. Truncation must never be interpreted as an empty queue.
#[derive(Debug, Serialize)]
pub struct BacklogObservation {
    pub profile: &'static str,
    pub scope: &'static str,
    pub checked_at: i64,
    pub elapsed_ms: u64,
    pub complete: bool,
    pub examined: usize,
    pub claimed_not_dispatched: usize,
    pub unresolved_dispatches: usize,
    pub unknown: usize,
    pub unknown_oldest_age_ms: i64,
    pub unknown_owner_deadline_exceeded: usize,
    pub incidents_open: usize,
    pub receipts_pending: usize,
    pub production_qualified: bool,
    pub execution_authority: bool,
}
pub struct OutcomeSupervisor {
    worker: RecoveryWorker,
    client: OutcomeReportClient,
    policy: IncidentPolicy,
    receipt_budget: usize,
    clock: Arc<dyn Clock>,
}
#[async_trait::async_trait]
impl crate::operations::Probe for OutcomeSupervisor {
    async fn check(&self) -> Vec<crate::operations::Check> {
        let (mut checks, material) = tokio::join!(
            crate::operations::Probe::check(&self.worker),
            self.client.readiness_material()
        );
        checks.push(crate::operations::Check::result(
            crate::operations::Dependency::DeliveryMaterial,
            material,
        ));
        checks
    }
}
impl OutcomeSupervisor {
    /// Performs guarded reads and local signature checks only. Never queries a
    /// target/collector, updates incidents, signs, acknowledges, mints or sends.
    pub async fn observe(&self, limit: usize) -> Result<BacklogObservation> {
        let checked_at = self.clock.now_ms();
        let start = std::time::Instant::now();
        let (entries, cursor) = self.worker.ledger.recovery_page(None, limit).await?;
        let mut report = BacklogObservation {
            profile: "KF-SUPERVISION-BACKLOG-0.1-draft",
            scope: "bounded_retained_observation",
            checked_at,
            elapsed_ms: 0,
            complete: cursor.is_none(),
            examined: entries.len(),
            claimed_not_dispatched: 0,
            unresolved_dispatches: 0,
            unknown: 0,
            unknown_oldest_age_ms: 0,
            unknown_owner_deadline_exceeded: 0,
            incidents_open: 0,
            receipts_pending: 0,
            production_qualified: false,
            execution_authority: false,
        };
        for candidate in entries {
            if !self.client.allows_candidate(&candidate) {
                return Err(Error::Refused(
                    "backlog candidate outside reporter scope".into(),
                ));
            }
            let snapshot = self.worker.ledger.recovery_snapshot(&candidate).await?;
            let verified = self
                .worker
                .verifier
                .verify_retained(snapshot.context.signed_grant.as_bytes())?;
            if verified.grant != candidate.grant || verified.digest != snapshot.attempt.grant_digest
            {
                return Err(Error::Refused("backlog grant binding mismatch".into()));
            }
            snapshot
                .context
                .validate(&verified.grant, &verified.digest)?;
            match snapshot.outbox.as_str() {
                "claimed_not_dispatched" => report.claimed_not_dispatched += 1,
                "dispatch_authorized" => report.unresolved_dispatches += 1,
                _ => (),
            }
            if snapshot.head.is_some() {
                if snapshot
                    .head
                    .as_ref()
                    .is_some_and(|head| head.state != snapshot.attempt.status)
                {
                    return Err(Error::Unavailable(
                        "backlog attempt and receipt head differ".into(),
                    ));
                }
                let bundle = self.worker.ledger.export_outcomes(&candidate).await?;
                self.client.verify_bundle(&bundle)?;
                if bundle.receipts.last() != snapshot.head.as_ref().map(|head| &head.signed_receipt)
                {
                    return Err(Error::Unavailable("backlog receipt head changed".into()));
                }
                if snapshot.attempt.status == "unknown" {
                    let since = bundle
                        .journal
                        .iter()
                        .find(|event| event["phase"] == "unknown")
                        .and_then(|event| event["event_time"].as_i64())
                        .filter(|since| *since >= 0 && *since <= checked_at)
                        .ok_or_else(|| {
                            Error::Refused("missing or future unknown journal".into())
                        })?;
                    report.unknown += 1;
                    report.unknown_oldest_age_ms =
                        report.unknown_oldest_age_ms.max(checked_at - since);
                    let deadline = since
                        .checked_add(self.policy.unknown_after_ms)
                        .ok_or_else(|| Error::Refused("unknown deadline overflow".into()))?;
                    report.unknown_owner_deadline_exceeded += usize::from(checked_at >= deadline);
                }
                for raw in &bundle.receipts {
                    let envelope: Envelope = serde_json::from_value(strict_value(raw.as_bytes())?)?;
                    let evidence_id = envelope.payload["resolution_evidence"][0]["digest"]
                        .as_str()
                        .ok_or_else(|| Error::Refused("missing backlog evidence".into()))?;
                    let receipt = DeliveryReceipt {
                        signed_grant: bundle.execution.signed_grant.clone(),
                        signed_receipt: raw.clone(),
                        evidence: bundle
                            .evidence
                            .get(evidence_id)
                            .cloned()
                            .ok_or_else(|| Error::Refused("missing backlog evidence".into()))?,
                    };
                    let expected = self.client.expected(&receipt)?;
                    match self
                        .worker
                        .ledger
                        .delivery_progress(&candidate, &expected)
                        .await?
                    {
                        Some(progress) => {
                            self.client
                                .verify_progress(&progress.acknowledgement, &expected)?;
                            if progress.recorded_at > checked_at {
                                return Err(Error::Refused("backlog clock regressed".into()));
                            }
                        }
                        None => report.receipts_pending += 1,
                    }
                }
            } else if snapshot.attempt.status != "claimed" {
                return Err(Error::Unavailable(
                    "terminal backlog attempt lacks receipt".into(),
                ));
            }
            if let Some(incident) = self.worker.ledger.supervision_incident(&candidate).await? {
                if incident.owner_id != self.policy.owner_id
                    || incident.policy_digest != self.policy.digest(self.client.tenant())?
                    || incident.grant_digest != verified.digest
                    || incident.tenant != self.client.tenant()
                    || incident.updated_at > checked_at
                {
                    return Err(Error::Refused(
                        "backlog incident enrollment or time mismatch".into(),
                    ));
                }
                report.incidents_open += usize::from(incident.state != "resolved");
            }
        }
        report.elapsed_ms = start.elapsed().as_millis() as u64;
        Ok(report)
    }
    pub fn new(
        worker: RecoveryWorker,
        client: OutcomeReportClient,
        policy: IncidentPolicy,
        receipt_budget: usize,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        policy.validate()?;
        client.validate_worker(&worker)?;
        if !(1..=64).contains(&receipt_budget) {
            return Err(Error::Invalid("invalid supervised receipt budget".into()));
        }
        Ok(Self {
            worker,
            client,
            policy,
            receipt_budget,
            clock,
        })
    }
    pub async fn sweep(&self, cursor: Option<&str>, limit: usize) -> Result<SupervisionSweep> {
        let (entries, next_cursor) = self.worker.ledger.recovery_page(cursor, limit).await?;
        let mut s = SupervisionSweep {
            examined: entries.len(),
            recovered: 0,
            deferred: 0,
            unavailable: 0,
            incidents_opened: 0,
            incidents_escalated: 0,
            incidents_resolved: 0,
            delivered: 0,
            delivery_deferred: 0,
            next_cursor,
        };
        for c in entries {
            if !self.client.allows_candidate(&c) {
                s.unavailable += 1;
                continue;
            }
            match self.worker.recover(&c).await {
                Ok(head) => {
                    s.recovered += 1;
                    // Incident deadlines depend on the verified current head.
                    // Complete export limits only delivery, not escalation.
                    let preparation = async {
                        let snapshot = self.worker.ledger.recovery_snapshot(&c).await?;
                        let expected = self.client.expected(&DeliveryReceipt {
                            signed_grant: snapshot.context.signed_grant,
                            signed_receipt: head.signed_receipt.clone(),
                            evidence: snapshot.evidence.ok_or_else(|| {
                                Error::Unavailable("missing supervision evidence".into())
                            })?,
                        })?;
                        if expected.receipt_digest != head.receipt_digest
                            || expected.evidence_digest != head.evidence_digest
                            || expected.grant_digest != snapshot.attempt.grant_digest
                            || expected.attempt_id != c.attempt_id
                        {
                            return Err(Error::Refused("supervision head binding changed".into()));
                        }
                        self.worker
                            .ledger
                            .update_incident(
                                &c,
                                &head,
                                &self.policy,
                                self.client.tenant(),
                                self.clock.now_ms(),
                            )
                            .await
                    }
                    .await;
                    let transitions = match preparation {
                        Ok(v) => v,
                        Err(_) => {
                            s.unavailable += 1;
                            continue;
                        }
                    };
                    for phase in transitions {
                        match phase.as_str() {
                            "open" => s.incidents_opened += 1,
                            "escalated" => s.incidents_escalated += 1,
                            "resolved" => s.incidents_resolved += 1,
                            _ => (),
                        }
                    }
                    let export = async {
                        let bundle = self.worker.ledger.export_outcomes(&c).await?;
                        self.client.verify_bundle(&bundle)?;
                        if bundle.receipts.last() != Some(&head.signed_receipt) {
                            return Err(Error::Refused("supervision receipt head changed".into()));
                        }
                        Ok(bundle)
                    }
                    .await;
                    let bundle = match export {
                        Ok(v) => v,
                        Err(_) => {
                            s.unavailable += 1;
                            continue;
                        }
                    };
                    match self.deliver(&c, &bundle, &mut s).await {
                        Ok(pending) => {
                            s.delivery_deferred += usize::from(pending);
                        }
                        Err(_) => s.unavailable += 1,
                    }
                }
                Err(Error::Refused(_)) => s.deferred += 1,
                Err(_) => s.unavailable += 1,
            }
        }
        Ok(s)
    }
    async fn deliver(
        &self,
        c: &Candidate,
        b: &crate::recovery::OutcomeBundle,
        sweep: &mut SupervisionSweep,
    ) -> Result<bool> {
        let mut completed = 0;
        let mut previous: Option<DeliveryProgress> = None;
        for raw in &b.receipts {
            let envelope: Envelope = serde_json::from_value(strict_value(raw.as_bytes())?)?;
            let ed = envelope.payload["resolution_evidence"][0]["digest"]
                .as_str()
                .ok_or_else(|| Error::Invalid("missing delivery evidence".into()))?;
            let receipt = DeliveryReceipt {
                signed_grant: b.execution.signed_grant.clone(),
                signed_receipt: raw.clone(),
                evidence: b
                    .evidence
                    .get(ed)
                    .cloned()
                    .ok_or_else(|| Error::Invalid("missing retained evidence".into()))?,
            };
            let expected = self.client.expected(&receipt)?;
            if let Some(progress) = self.worker.ledger.delivery_progress(c, &expected).await? {
                self.client
                    .verify_progress(&progress.acknowledgement, &expected)?;
                if progress.recorded_at > self.clock.now_ms() {
                    return Err(Error::Refused("supervision clock regressed".into()));
                }
                previous = Some(progress);
                continue;
            }
            if completed >= self.receipt_budget {
                return Ok(true);
            }
            let request_id = format!("supervise-{}", expected.report_id);
            let ack = match self.client.lookup(&request_id, &receipt).await? {
                Some(ack) => ack,
                None => self.client.deliver(&request_id, &receipt).await?,
            };
            self.client.verify_progress(&ack, &expected)?;
            let progress = DeliveryProgress {
                profile: PROFILE.into(),
                collector_digest: collector_key(&expected)?,
                receipt_digest: expected.receipt_digest.clone(),
                acknowledgement: ack,
                recorded_at: self.clock.now_ms(),
            };
            let persisted = self
                .worker
                .ledger
                .record_delivery(c, &receipt, &expected, &progress, previous.as_ref())
                .await?;
            self.client
                .verify_progress(&persisted.acknowledgement, &expected)?;
            previous = Some(persisted);
            completed += 1;
            sweep.delivered += 1;
        }
        Ok(false)
    }
}
