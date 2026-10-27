//! Explicit original-dispatch lineage with no retained outcome receipt. This
//! supplement can only report pending. The reserved/control observer checkpoint
//! attests the native journal and exact receipt-head absence; no receipt is made.
use crate::{
    contracts::GrantVerifier,
    error::{Error, Result},
    recovery::{OutcomeBundle, TraceVerification},
};
use std::collections::BTreeMap;
pub const OUTCOME_PROFILE: &str = "KF-MANAGED-PENDING-OUTCOMES-0.1-draft";
pub const LINEAGE_PROFILE: &str = "KF-MANAGED-PENDING-LINEAGE-0.1-draft";
pub const RESERVED_PROFILE: &str = "KF-MANAGED-PENDING-RESERVED-0.1-draft";
pub const CONTROL_PROFILE: &str = "KF-MANAGED-PENDING-CONTROL-0.1-draft";
fn refuse() -> Error {
    Error::Refused("managed pending original/no-receipt proof refused".into())
}
pub(crate) fn verify_outcomes(
    b: &OutcomeBundle,
    grants: &GrantVerifier,
    outcomes: &BTreeMap<String, ed25519_dalek::VerifyingKey>,
) -> Result<TraceVerification> {
    if b.profile != OUTCOME_PROFILE
        || !b.receipts.is_empty()
        || !b.evidence.is_empty()
        || b.journal.len() < 2
        || b.journal.len() > 6
        || b.attempt_id.is_empty()
        || b.attempt_id.len() > 1024
        || outcomes.is_empty()
        || outcomes
            .values()
            .any(|k| grants.keys.values().any(|g| g == k))
    {
        return Err(refuse());
    }
    let v = grants.verify_retained(b.execution.signed_grant.as_bytes())?;
    b.execution.validate(&v.grant, &v.digest)?;
    if v.grant.action.id != crate::managed_drain::ACTION
        || v.grant.action.version != crate::managed_drain::VERSION
        || v.grant.adapter_contract != crate::managed_drain::adapter_contract()
    {
        return Err(refuse());
    }
    let mut phases = std::collections::BTreeSet::new();
    let mut previous = v.grant.valid_from;
    for e in &b.journal {
        crate::recovery::validate(e)?;
        let phase = e["phase"].as_str().ok_or_else(refuse)?;
        let at = e["event_time"].as_i64().ok_or_else(refuse)?;
        if e["attempt_id"] != b.attempt_id
            || e["root_id"] != v.grant.root_id
            || e["grant_digest"] != v.digest
            || !phases.insert(phase)
            || at < previous
            || matches!(phase, "claimed" | "dispatch_authorized") && at >= v.grant.expires_at
            || ![
                "claimed",
                "dispatch_authorized",
                "unknown",
                "committed",
                "state_guard_violation",
            ]
            .contains(&phase)
        {
            return Err(refuse());
        }
        previous = at;
    }
    if b.journal[0]["phase"] != "claimed" || b.journal[1]["phase"] != "dispatch_authorized" {
        return Err(refuse());
    }
    Ok(TraceVerification{receipts_verified:0,grant_digest:v.digest,attempt_id:b.attempt_id.clone(),reported_status:"pending".into(),missing_links:vec!["No outcome receipt is retained; this journal requires its separately pinned native observer checkpoint and cannot establish no effect or completion".into()]})
}
impl crate::ledger::EtcdLedger {
    async fn managed_pending_snapshot(
        &self,
        c: &crate::recovery::Candidate,
    ) -> Result<Option<(OutcomeBundle, Vec<serde_json::Value>)>> {
        use crate::ledger::{record, value_eq, version_zero};
        use crate::recovery::{context_key, journal_key};
        if c.grant.action.id != crate::managed_drain::ACTION {
            return Ok(None);
        }
        let context = crate::managed_drain_store::Context::from_ledger(self)?;
        let s = self.recovery_snapshot(c).await?;
        if s.head.is_some() {
            return Ok(None);
        }
        let gd = &s.attempt.grant_digest;
        s.context.validate(&c.grant, gd)?;
        let retained = self
            .export_authorization(&context.enrollment.operation_key)
            .await?
            .issuance;
        if !["dispatch_authorized", "unknown", "committed"].contains(&s.outbox.as_str())
            || context.enrollment.operation_key != retained.issuance_key
            || retained.grant_digest != *gd
            || crate::contracts::canonical(&crate::contracts::strict_value(
                retained.signed_grant.as_bytes(),
            )?)? != crate::contracts::canonical(&crate::contracts::strict_value(
                s.context.signed_grant.as_bytes(),
            )?)?
        {
            return Err(refuse());
        }
        let base = self.attempt(&c.grant, &c.attempt_id);
        let mut compare = vec![
            version_zero(&format!("{base}/receipt-head")),
            value_eq(&context_key(self, &c.grant, &c.attempt_id), &s.context_raw),
            value_eq(&self.attempt(&c.grant, &c.attempt_id), &record(&s.attempt)?),
            value_eq(&self.outbox(&c.grant, &c.attempt_id), &s.outbox),
            value_eq(&self.nonce(&c.grant), &c.attempt_id),
        ];
        let mut journal = vec![];
        for phase in [
            "claimed",
            "dispatch_authorized",
            "unknown",
            "committed",
            "state_guard_violation",
        ] {
            let key = journal_key(self, &c.grant, &c.attempt_id, phase);
            match self.read_key(&key).await? {
                Some(raw) => {
                    journal.push(crate::contracts::strict_value(&raw)?);
                    compare.push(value_eq(
                        &key,
                        std::str::from_utf8(&raw).map_err(|_| refuse())?,
                    ));
                }
                None => compare.push(version_zero(&key)),
            }
        }
        let bundle = OutcomeBundle {
            profile: OUTCOME_PROFILE.into(),
            execution: s.context,
            attempt_id: c.attempt_id.clone(),
            receipts: vec![],
            evidence: BTreeMap::new(),
            journal,
        };
        Ok(Some((bundle, compare)))
    }
    pub(crate) async fn export_managed_pending_outcomes(
        &self,
        c: &crate::recovery::Candidate,
    ) -> Result<Option<OutcomeBundle>> {
        let Some((bundle, compare)) = self.managed_pending_snapshot(c).await? else {
            return Ok(None);
        };
        if !self.txn(compare, vec![], vec![]).await?.succeeded {
            return Err(refuse());
        }
        Ok(Some(bundle))
    }
    /// Recompare the exact disclosed pending journal and receipt absence at the
    /// enclosing checkpoint, rather than merely at the inner export's read.
    pub(crate) async fn managed_pending_compare(
        &self,
        c: &crate::recovery::Candidate,
        lineage: &crate::lineage::LineageBundle,
    ) -> Result<Vec<serde_json::Value>> {
        if lineage.profile != LINEAGE_PROFILE {
            return Ok(vec![]);
        }
        let (current, compare) = self.managed_pending_snapshot(c).await?.ok_or_else(refuse)?;
        if crate::contracts::canonical(&serde_json::json!(current))?
            != crate::contracts::canonical(&serde_json::json!(lineage.outcomes))?
        {
            return Err(refuse());
        }
        Ok(compare)
    }
}
