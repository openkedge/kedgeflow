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
pub struct OutcomeSupervisor {
    worker: RecoveryWorker,
    client: OutcomeReportClient,
    policy: IncidentPolicy,
    receipt_budget: usize,
    clock: Arc<dyn Clock>,
}
impl OutcomeSupervisor {
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
