//! Delivery transactions write acknowledgements only, never execution state.
use crate::{
    contracts::{Grant, digest, strict_value},
    error::{Error, Result},
    ledger::{
        Attempt, EtcdLedger, expected_root, get, put, range_kv, record, value_eq, version_zero,
    },
    outcome_report::{Acknowledgement, verify_ack},
    recovery::{Candidate, ExecutionRecord, context_key, index_key},
};
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(crate) struct PreparedReport {
    pub candidate: Candidate,
    pub receipt: String,
    pub evidence: Value,
    pub expected: Acknowledgement,
    pub previous: Option<(String, Acknowledgement)>,
}
fn ack_key(l: &EtcdLedger, g: &Grant, a: &Acknowledgement, rd: &str) -> Result<String> {
    Ok(format!(
        "{}/deliveries/{}/{}",
        l.attempt(g, &a.attempt_id),
        digest(
            "outcome-collector",
            &json!({"id":a.collector_id,"url":a.collector_url})
        )?,
        rd
    ))
}
fn unavailable() -> Error {
    Error::Unavailable("inconsistent outcome delivery state".into())
}
impl EtcdLedger {
    pub(crate) async fn retained_receipt(&self, g: &Grant, id: &str, rd: &str) -> Result<String> {
        let raw = self
            .read_key(&format!("{}/receipts/{rd}", self.attempt(g, id)))
            .await?
            .ok_or_else(|| Error::Unknown("not_retained".into()))?;
        String::from_utf8(raw).map_err(|_| unavailable())
    }
    pub(crate) async fn retained_report_evidence(
        &self,
        g: &Grant,
        a: &Acknowledgement,
    ) -> Result<Value> {
        let raw = self
            .read_key(&format!(
                "{}/reports/evidence/{}",
                self.attempt(g, &a.attempt_id),
                a.evidence_digest
            ))
            .await?
            .ok_or_else(|| Error::Unknown("not_retained".into()))?;
        strict_value(&raw)
    }
    pub(crate) async fn acknowledge_report(
        &self,
        report: &PreparedReport,
        keys: &BTreeMap<String, VerifyingKey>,
        proposed: Option<&str>,
    ) -> Result<Option<String>> {
        let c = &report.candidate;
        let g = &c.grant;
        let a = &report.expected;
        let base = self.attempt(g, &c.attempt_id);
        let receipt_key = format!("{base}/receipts/{}", a.receipt_digest);
        let evidence_key = format!("{base}/reports/evidence/{}", a.evidence_digest);
        let current = ack_key(self, g, a, &a.receipt_digest)?;
        let previous = a
            .previous_receipt_digest
            .as_ref()
            .map(|rd| ack_key(self, g, a, rd))
            .transpose()?;
        // A concurrent submission may win first; reread its exact stored acknowledgement.
        for _ in 0..2 {
            let mut reads = vec![
                get(&self.root(g)),
                get(&self.grant_key(g)),
                get(&self.nonce(g)),
                get(&context_key(self, g, &c.attempt_id)),
                get(&index_key(self, &a.grant_digest, &c.attempt_id)?),
                get(&receipt_key),
                get(&evidence_key),
                get(&current),
                get(&base),
            ];
            if let Some(key) = &previous {
                reads.push(get(key));
                reads.push(get(&format!(
                    "{base}/receipts/{}",
                    a.previous_receipt_digest.as_ref().ok_or_else(unavailable)?
                )));
            }
            let read = self.txn(vec![], reads, vec![]).await?;
            if !read.succeeded || read.responses.len() != 9 + 2 * usize::from(previous.is_some()) {
                return Err(unavailable());
            }
            let required = |i: usize| -> Result<String> {
                let kv = range_kv(&read.responses[i])?
                    .ok_or_else(|| Error::Unknown("not_retained".into()))?;
                String::from_utf8(kv.value).map_err(|_| unavailable())
            };
            let mut root = expected_root(g);
            root.status = "claimed".into();
            let context_raw = required(3)?;
            let context: ExecutionRecord =
                serde_json::from_value(strict_value(context_raw.as_bytes())?)?;
            context.validate(g, &a.grant_digest)?;
            let attempt: Attempt = serde_json::from_value(strict_value(required(8)?.as_bytes())?)?;
            if required(0)? != record(&root)?
                || required(1)? != a.grant_digest
                || required(2)? != c.attempt_id
                || required(4)? != record(c)?
                || required(5)? != report.receipt
                || required(6)? != record(&report.evidence)?
                || digest("outcome-evidence", &report.evidence)? != a.evidence_digest
                || attempt.id != c.attempt_id
                || attempt.root_id != g.root_id
                || attempt.grant_digest != a.grant_digest
            {
                return Err(Error::Unknown("not_retained".into()));
            }
            if let Some(kv) = range_kv(&read.responses[7])? {
                let raw = String::from_utf8(kv.value).map_err(|_| unavailable())?;
                verify_ack(&raw, keys, a).map_err(|_| unavailable())?;
                return Ok(Some(raw));
            }
            let Some(proposed) = proposed else {
                return Ok(None);
            };
            verify_ack(proposed, keys, a)?;
            let mut compare = vec![
                value_eq(&self.root(g), &record(&root)?),
                value_eq(&self.grant_key(g), &a.grant_digest),
                value_eq(&self.nonce(g), &c.attempt_id),
                value_eq(&context_key(self, g, &c.attempt_id), &context_raw),
                value_eq(
                    &index_key(self, &a.grant_digest, &c.attempt_id)?,
                    &record(c)?,
                ),
                value_eq(&receipt_key, &report.receipt),
                value_eq(&evidence_key, &record(&report.evidence)?),
                version_zero(&current),
            ];
            if let Some(key) = &previous {
                let raw = range_kv(&read.responses[9])?
                    .ok_or_else(|| Error::Unknown("predecessor_required".into()))?;
                let raw = String::from_utf8(raw.value).map_err(|_| unavailable())?;
                let (receipt, expected) = report.previous.as_ref().ok_or_else(unavailable)?;
                verify_ack(&raw, keys, expected).map_err(|_| unavailable())?;
                if required(10)? != *receipt {
                    return Err(unavailable());
                }
                compare.push(value_eq(key, &raw));
                compare.push(value_eq(
                    &format!("{base}/receipts/{}", expected.receipt_digest),
                    receipt,
                ));
            }
            if self
                .txn(compare, vec![put(&current, proposed)], vec![])
                .await?
                .succeeded
            {
                return Ok(Some(proposed.into()));
            }
        }
        Err(Error::Unavailable(
            "delivery snapshot changed; query or retry exact report".into(),
        ))
    }
}
