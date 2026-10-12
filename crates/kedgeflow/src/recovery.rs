//! Query-only recovery and OutcomeService receipts for the bounded leaf profile.
use crate::{
    clock::Clock,
    contracts::{
        Envelope, Grant, GrantVerifier, canonical, digest, record_digest, signature_input,
        strict_value,
    },
    error::{Error, Result},
    ledger::{Attempt, EtcdLedger, OutcomeQuerier, record},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub const PROFILE: &str = "KF-OUTCOME-RECOVERY-0.1-draft";
pub const EVIDENCE_SCHEMA: &str = "urn:kedgeflow:draft:recovery:evidence:0.1";

pub fn validate(value: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let schema = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/outcome-recovery-v0.1.schema.json"
            ))
            .expect("embedded recovery schema"),
        )
        .expect("valid recovery schema")
    });
    if !schema.is_valid(value) {
        return Err(Error::Invalid("closed recovery supplement mismatch".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub signed_grant: String,
    pub tool: String,
    pub parameters: Value,
}
impl ExecutionRecord {
    pub(crate) fn validate(&self, g: &Grant, expected_digest: &str) -> Result<()> {
        validate(&serde_json::to_value(self)?)?;
        let e: Envelope = serde_json::from_value(strict_value(self.signed_grant.as_bytes())?)?;
        if self.signed_grant.len() > 1 << 20
            || self.tool.is_empty()
            || self.tool.len() > 1024
            || e.kind != "grant"
            || serde_json::from_value::<Grant>(e.payload.clone())? != *g
            || record_digest(&e)? != expected_digest
            || digest("parameters", &self.parameters)? != g.parameters_digest
        {
            return Err(Error::Invalid("execution record binding mismatch".into()));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub grant: Grant,
    pub attempt_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptHead {
    pub signed_receipt: String,
    pub receipt_digest: String,
    pub state: String,
    pub evidence_digest: String,
}
#[derive(Debug, Serialize)]
pub struct Sweep {
    pub examined: usize,
    pub reported: usize,
    pub deferred: usize,
    pub unavailable: usize,
    pub next_cursor: Option<String>,
}

pub(crate) fn context_key(l: &EtcdLedger, g: &Grant, id: &str) -> String {
    format!("{}/execution", l.attempt(g, id))
}
pub(crate) fn evidence_key(l: &EtcdLedger, g: &Grant, id: &str) -> String {
    format!("{}/outcome-evidence", l.attempt(g, id))
}
pub(crate) fn journal_key(l: &EtcdLedger, g: &Grant, id: &str, phase: &str) -> String {
    format!("{}/journal/{phase}", l.attempt(g, id))
}
pub(crate) fn index_key(l: &EtcdLedger, gd: &str, id: &str) -> Result<String> {
    Ok(format!(
        "{}/recovery/index/{}",
        l.namespace(),
        digest("recovery-key", &json!({"grant_digest":gd,"attempt_id":id}))?
    ))
}
pub(crate) fn transition(g: &Grant, a: &Attempt, phase: &str, now: i64) -> Result<String> {
    let value = json!({"profile":PROFILE,"attempt_id":a.id,"root_id":g.root_id,"grant_digest":a.grant_digest,"phase":phase,"event_time":now});
    validate(&value)?;
    record(&value)
}

pub struct RecoveryWorker {
    pub(crate) ledger: EtcdLedger,
    pub(crate) verifier: GrantVerifier,
    query: Arc<dyn OutcomeQuerier>,
    key_id: String,
    signing_key: SigningKey,
    source_id: String,
    clock: Arc<dyn Clock>,
}
impl RecoveryWorker {
    pub fn new(
        ledger: EtcdLedger,
        verifier: GrantVerifier,
        query: Arc<dyn OutcomeQuerier>,
        key_id: String,
        signing_key: SigningKey,
        source_id: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        if key_id.is_empty()
            || source_id.is_empty()
            || source_id.len() > 1024
            || verifier.keys.is_empty()
            || verifier
                .keys
                .values()
                .any(|k| k == &signing_key.verifying_key())
        {
            return Err(Error::Invalid(
                "invalid or overlapping OutcomeService role".into(),
            ));
        }
        Ok(Self {
            ledger,
            verifier,
            query,
            key_id,
            signing_key,
            source_id,
            clock,
        })
    }
    pub async fn sweep(&self, cursor: Option<&str>, limit: usize) -> Result<Sweep> {
        let (candidates, next_cursor) = self.ledger.recovery_page(cursor, limit).await?;
        let mut result = Sweep {
            examined: candidates.len(),
            reported: 0,
            deferred: 0,
            unavailable: 0,
            next_cursor,
        };
        for c in candidates {
            match self.recover(&c).await {
                Ok(_) => result.reported += 1,
                Err(Error::Refused(_)) => result.deferred += 1,
                Err(_) => result.unavailable += 1,
            }
        }
        Ok(result)
    }
    pub async fn recover(&self, candidate: &Candidate) -> Result<ReceiptHead> {
        let snapshot = self.ledger.recovery_snapshot(candidate).await?;
        let verified = self
            .verifier
            .verify_retained(snapshot.context.signed_grant.as_bytes())?;
        if verified.grant != candidate.grant || verified.digest != snapshot.attempt.grant_digest {
            return Err(Error::Unavailable("recovery grant mismatch".into()));
        }
        snapshot
            .context
            .validate(&verified.grant, &verified.digest)?;
        let g = &verified.grant;
        if snapshot.attempt.status == "claimed" && self.clock.now_ms() < g.expires_at {
            return Err(Error::Refused(
                "execution budget still active; defer takeover".into(),
            ));
        }
        let mut state = snapshot.attempt.status.clone();
        let mut evidence = snapshot.evidence.clone().unwrap_or_else(
            || json!({"kind":"ledger_status","state":state,"target_evidence":"missing"}),
        );
        if state == "claimed" && snapshot.outbox == "claimed_not_dispatched" {
            state = "not_dispatched".into();
            evidence = json!({"kind":"pre_dispatch_seal","attempt_id":snapshot.attempt.id,"grant_digest":verified.digest});
        } else if ["claimed", "unknown"].contains(&state.as_str()) {
            state = "unknown".into();
            evidence = json!({"kind":"query_unavailable"});
            if let Ok(Ok(observation)) = tokio::time::timeout(
                Duration::from_secs(5),
                self.query.query(&snapshot.attempt.id),
            )
            .await
            {
                let valid = observation.attempt_id == snapshot.attempt.id
                    && observation.root_id == g.root_id
                    && observation.grant_digest == verified.digest
                    && !observation.target_reference.is_empty()
                    && observation.target_reference.len() <= 1024
                    && [
                        "committed",
                        "pending",
                        "unknown",
                        "not_found",
                        "not_dispatched",
                        "fenced_no_effect",
                    ]
                    .contains(&observation.status.as_str());
                let bytes = record(&observation)?;
                if bytes.len() > 65536 {
                    return Err(Error::Unavailable("observation exceeds bound".into()));
                }
                evidence = json!({"kind":if valid {"authoritative_query"} else {"uncorrelated_query"},"observation":observation});
                if valid && observation.status == "committed" {
                    state = "committed".into();
                }
            }
        }
        let ed = digest("outcome-evidence", &evidence)?;
        let previous = if let Some(head) = &snapshot.head {
            let envelope = crate::schema::verify_record(
                head.signed_receipt.as_bytes(),
                "receipt",
                &BTreeMap::from([(self.key_id.clone(), self.signing_key.verifying_key())]),
            )?;
            verify_receipt_binding(
                &envelope,
                g,
                &verified.digest,
                &snapshot.attempt.id,
                &self.source_id,
            )?;
            let receipt_state = if head.state == "state_guard_violation" {
                "failed"
            } else {
                &head.state
            };
            if envelope.payload["status"] != receipt_state
                || record_digest(&envelope)? != head.receipt_digest
                || envelope.payload["resolution_evidence"]
                    != json!([{"id":head.evidence_digest,"schema":EVIDENCE_SCHEMA,"digest":head.evidence_digest}])
            {
                return Err(Error::Unavailable("receipt head mismatch".into()));
            }
            if head.state == state && head.evidence_digest == ed {
                return Ok(head.clone());
            }
            Some(head.receipt_digest.clone())
        } else {
            None
        };
        let rid = digest(
            "outcome-report",
            &json!({"attempt_id":snapshot.attempt.id,"grant_digest":verified.digest,"state":state,"evidence_digest":ed,"previous":previous}),
        )?;
        let receipt_status = if state == "state_guard_violation" {
            "failed"
        } else {
            &state
        };
        let mut envelope = Envelope {
            profile: crate::contracts::PROFILE.into(),
            kind: "receipt".into(),
            schema: "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Receipt".into(),
            key_id: self.key_id.clone(),
            signature: String::new(),
            payload: json!({
                "rid":rid,"proposal_digest":g.proposal_digest,"certificate_digest":g.certificate_digest,"grant_digest":verified.digest,"root_id":g.root_id,"root_generation":g.root_generation,"attempt_id":snapshot.attempt.id,"source_id":self.source_id,"source_role":"OutcomeService","event_time":self.clock.now_ms(),"status":receipt_status,
                "resource_operation_id":if evidence["kind"]=="authoritative_query" {evidence["observation"]["TargetReference"].as_str()} else {None},"observed_version":null,"effect_digest":g.parameters_digest,"error_code":match state.as_str() {"unknown"=>Some("OUTCOME_UNKNOWN"),"not_dispatched"=>Some("RESOURCE_ERROR"),"state_guard_violation"=>Some("STATE_GUARD_VIOLATION"),_=>None},"previous_receipt_digest":previous,
                "resolution_evidence":[{"id":ed,"schema":EVIDENCE_SCHEMA,"digest":ed}],"fence":g.fence,"saga_budget":null
            }),
        };
        envelope.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(&signature_input(&envelope)?)
                .to_bytes(),
        );
        let signed = canonical(&serde_json::to_value(&envelope)?)?;
        crate::schema::verify_record(
            &signed,
            "receipt",
            &BTreeMap::from([(self.key_id.clone(), self.signing_key.verifying_key())]),
        )?;
        let head = ReceiptHead {
            signed_receipt: String::from_utf8(signed)
                .map_err(|_| Error::Invalid("receipt encoding".into()))?,
            receipt_digest: record_digest(&envelope)?,
            state: state.clone(),
            evidence_digest: ed,
        };
        self.ledger
            .apply_recovery(
                candidate,
                &snapshot,
                &state,
                &evidence,
                &head,
                self.clock.now_ms(),
            )
            .await?;
        Ok(head)
    }
}
pub(crate) fn verify_receipt_binding(
    e: &Envelope,
    g: &Grant,
    gd: &str,
    id: &str,
    source: &str,
) -> Result<()> {
    let p = &e.payload;
    if p["grant_digest"] != gd
        || p["proposal_digest"] != g.proposal_digest
        || p["certificate_digest"] != g.certificate_digest
        || p["root_id"] != g.root_id
        || p["root_generation"] != g.root_generation
        || p["attempt_id"] != id
        || p["fence"] != g.fence
        || p["source_id"] != source
        || p["source_role"] != "OutcomeService"
        || p["effect_digest"] != g.parameters_digest
    {
        return Err(Error::Invalid("receipt lineage mismatch".into()));
    }
    Ok(())
}

/// Offline receipt-chain evidence. Trust keys are supplied separately by the
/// verifier, never selected by this bundle. Missing authorization links are explicit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeBundle {
    pub profile: String,
    pub execution: ExecutionRecord,
    pub attempt_id: String,
    pub receipts: Vec<String>,
    pub evidence: BTreeMap<String, Value>,
    pub journal: Vec<Value>,
}
#[derive(Debug, Serialize)]
pub struct TraceVerification {
    pub receipts_verified: usize,
    pub grant_digest: String,
    pub attempt_id: String,
    pub reported_status: String,
    pub missing_links: Vec<String>,
}
pub fn verify_outcomes(
    bundle: &OutcomeBundle,
    grants: &GrantVerifier,
    outcome_keys: &BTreeMap<String, ed25519_dalek::VerifyingKey>,
    source_id: &str,
) -> Result<TraceVerification> {
    if bundle.profile != PROFILE
        || bundle.receipts.is_empty()
        || bundle.receipts.len() > 64
        || outcome_keys.is_empty()
        || outcome_keys
            .values()
            .any(|k| grants.keys.values().any(|g| g == k))
    {
        return Err(Error::Invalid(
            "invalid outcome bundle or role overlap".into(),
        ));
    }
    let verified = grants.verify_retained(bundle.execution.signed_grant.as_bytes())?;
    bundle
        .execution
        .validate(&verified.grant, &verified.digest)?;
    let mut previous: Option<String> = None;
    let mut status = String::new();
    for raw in &bundle.receipts {
        let e = crate::schema::verify_record(raw.as_bytes(), "receipt", outcome_keys)?;
        verify_receipt_binding(
            &e,
            &verified.grant,
            &verified.digest,
            &bundle.attempt_id,
            source_id,
        )?;
        let p = &e.payload;
        if p["previous_receipt_digest"] != json!(previous) {
            return Err(Error::Invalid(
                "missing or reordered receipt predecessor".into(),
            ));
        }
        let next = p["status"]
            .as_str()
            .ok_or_else(|| Error::Invalid("invalid receipt status".into()))?;
        if !["unknown", "committed", "not_dispatched", "failed"].contains(&next)
            || (!status.is_empty()
                && (status != "unknown" || !["unknown", "committed"].contains(&next)))
        {
            return Err(Error::Invalid("contradictory outcome transition".into()));
        }
        let ed = p["resolution_evidence"][0]["digest"]
            .as_str()
            .ok_or_else(|| Error::Invalid("missing evidence digest".into()))?;
        let evidence = bundle
            .evidence
            .get(ed)
            .ok_or_else(|| Error::Invalid("missing outcome evidence".into()))?;
        if digest("outcome-evidence", evidence)? != ed
            || p["resolution_evidence"] != json!([{"id":ed,"schema":EVIDENCE_SCHEMA,"digest":ed}])
        {
            return Err(Error::Invalid("outcome evidence binding mismatch".into()));
        }
        if evidence["kind"] == "authoritative_query" {
            let o: crate::ledger::AuthoritativeObservation =
                serde_json::from_value(evidence["observation"].clone())?;
            if o.attempt_id != bundle.attempt_id
                || o.root_id != verified.grant.root_id
                || o.grant_digest != verified.digest
                || (next == "committed" && o.status != "committed")
            {
                return Err(Error::Invalid(
                    "query observation differs from receipt".into(),
                ));
            }
        }
        previous = Some(record_digest(&e)?);
        status = next.into();
    }
    Ok(TraceVerification {
        receipts_verified: bundle.receipts.len(),
        grant_digest: verified.digest,
        attempt_id: bundle.attempt_id.clone(),
        reported_status: status,
        missing_links: vec![
            "signed proposal".into(),
            "signed manifest and witnesses".into(),
            "signed admission certificate".into(),
            "installed control/key history".into(),
            "independently authenticated authority journal".into(),
            "target-signed commit/no-effect proof".into(),
        ],
    })
}
