//! Incident CAS/events and immutable local collector-acceptance progress.
use crate::{
    contracts::{digest, strict_value},
    error::{Error, Result},
    ledger::{EtcdLedger, expected_root, get, put, range_kv, record, value_eq, version_zero},
    outcome_report::Acknowledgement,
    outcome_report_client::DeliveryReceipt,
    recovery::{Candidate, ReceiptHead, context_key, index_key, journal_key},
    supervision::{DeliveryProgress, Incident, IncidentPolicy, PROFILE, collector_key, validate},
};
use serde_json::json;
fn refused() -> Error {
    Error::Refused("inconsistent or conflicting supervision state".into())
}
fn incident_key(l: &EtcdLedger, c: &Candidate) -> String {
    format!("{}/incident", l.attempt(&c.grant, &c.attempt_id))
}
fn progress_key(l: &EtcdLedger, c: &Candidate, collector: &str, rd: &str) -> String {
    format!(
        "{}/delivery-progress/{collector}/{rd}",
        l.attempt(&c.grant, &c.attempt_id)
    )
}
fn incident_digest(i: &Incident) -> Result<String> {
    digest("outcome-incident", &serde_json::to_value(i)?)
}
fn parse<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    let v = strict_value(raw)?;
    validate(&v)?;
    Ok(serde_json::from_value(v)?)
}
impl EtcdLedger {
    /// Protected operator state; does not disclose execution authority.
    pub async fn supervision_incident(&self, c: &Candidate) -> Result<Option<Incident>> {
        let key = incident_key(self, c);
        let read = self
            .txn(
                vec![],
                vec![
                    get(&key),
                    get(&format!("{key}/events/1")),
                    get(&format!("{key}/events/2")),
                    get(&format!("{key}/events/3")),
                ],
                vec![],
            )
            .await?;
        if !read.succeeded || read.responses.len() != 4 {
            return Err(refused());
        }
        let events = (1..=3)
            .map(|i| {
                range_kv(&read.responses[i])?
                    .map(|kv| parse::<Incident>(&kv.value))
                    .transpose()
            })
            .collect::<Result<Vec<_>>>()?;
        let head = range_kv(&read.responses[0])?
            .map(|kv| parse::<Incident>(&kv.value))
            .transpose()?;
        let Some(head) = head else {
            if events.iter().any(Option::is_some) {
                return Err(refused());
            }
            return Ok(None);
        };
        let mut previous: Option<Incident> = None;
        for (index, event) in events.into_iter().enumerate() {
            if index >= head.revision as usize {
                if event.is_some() {
                    return Err(refused());
                }
                continue;
            }
            let event = event.ok_or_else(refused)?;
            if event.revision != index as u64 + 1
                || event.attempt_id != c.attempt_id
                || event.root_id != c.grant.root_id
                || event.incident_id
                    != digest(
                        "unknown-incident",
                        &json!({"namespace":self.prefix,"tenant":event.tenant,"grant_digest":event.grant_digest,"attempt_id":c.attempt_id}),
                    )?
                || event.deadline <= event.unknown_since
                || event.updated_at < event.unknown_since
            {
                return Err(refused());
            }
            if let Some(p) = &previous {
                if event.previous_digest != Some(incident_digest(p)?)
                    || event.incident_id != p.incident_id
                    || event.owner_id != p.owner_id
                    || event.tenant != p.tenant
                    || event.grant_digest != p.grant_digest
                    || event.policy_digest != p.policy_digest
                    || event.unknown_since != p.unknown_since
                    || event.deadline != p.deadline
                    || event.updated_at < p.updated_at
                    || !matches!(
                        (p.state.as_str(), event.state.as_str()),
                        ("open", "escalated" | "resolved") | ("escalated", "resolved")
                    )
                {
                    return Err(refused());
                }
            } else if event.state != "open" || event.previous_digest.is_some() {
                return Err(refused());
            }
            previous = Some(event);
        }
        if previous.as_ref() != Some(&head) {
            return Err(refused());
        }
        Ok(Some(head))
    }
    pub(crate) async fn update_incident(
        &self,
        c: &Candidate,
        head: &ReceiptHead,
        policy: &IncidentPolicy,
        tenant: &str,
        now: i64,
    ) -> Result<Vec<String>> {
        let mut transitions = Vec::new();
        for _ in 0..3 {
            let s = self.recovery_snapshot(c).await?;
            if s.head.as_ref().is_none_or(|h| {
                h.receipt_digest != head.receipt_digest
                    || h.signed_receipt != head.signed_receipt
                    || h.state != head.state
                    || h.evidence_digest != head.evidence_digest
            }) || s.attempt.status != head.state
            {
                return Err(refused());
            }
            let old = self.supervision_incident(c).await?;
            let unknown_key = journal_key(self, &c.grant, &c.attempt_id, "unknown");
            let unknown = self.read_key(&unknown_key).await?;
            let Some(raw) = unknown else {
                if old.is_some() || head.state == "unknown" {
                    return Err(refused());
                }
                return Ok(transitions);
            };
            let unknown = strict_value(&raw)?;
            crate::recovery::validate(&unknown)?;
            if unknown["phase"] != "unknown"
                || unknown["attempt_id"] != c.attempt_id
                || unknown["root_id"] != c.grant.root_id
                || unknown["grant_digest"] != s.attempt.grant_digest
            {
                return Err(refused());
            }
            let since = unknown["event_time"].as_i64().ok_or_else(refused)?;
            let deadline = since
                .checked_add(policy.unknown_after_ms)
                .filter(|v| *v <= crate::contracts::MAX_SAFE_INTEGER as i64)
                .ok_or_else(refused)?;
            let pin = policy.digest(tenant)?;
            if now < since || now > crate::contracts::MAX_SAFE_INTEGER as i64 {
                return Err(refused());
            }
            let mut next = match &old {
                None => Incident {
                    profile: PROFILE.into(),
                    incident_id: digest(
                        "unknown-incident",
                        &json!({"namespace":self.prefix,"tenant":tenant,"grant_digest":s.attempt.grant_digest,"attempt_id":c.attempt_id}),
                    )?,
                    tenant: tenant.into(),
                    grant_digest: s.attempt.grant_digest.clone(),
                    root_id: c.grant.root_id.clone(),
                    attempt_id: c.attempt_id.clone(),
                    owner_id: policy.owner_id.clone(),
                    policy_digest: pin.clone(),
                    unknown_since: since,
                    deadline,
                    revision: 1,
                    state: "open".into(),
                    updated_at: now,
                    receipt_digest: head.receipt_digest.clone(),
                    previous_digest: None,
                },
                Some(old) => {
                    if old.owner_id != policy.owner_id
                        || old.policy_digest != pin
                        || old.tenant != tenant
                        || old.grant_digest != s.attempt.grant_digest
                        || old.unknown_since != since
                        || old.deadline != deadline
                        || now < old.updated_at
                    {
                        return Err(refused());
                    }
                    let phase = if old.state != "resolved" && head.state == "committed" {
                        "resolved"
                    } else if old.state == "open" && head.state == "unknown" && now >= old.deadline
                    {
                        "escalated"
                    } else {
                        return Ok(transitions);
                    };
                    let mut n = old.clone();
                    n.revision += 1;
                    n.state = phase.into();
                    n.updated_at = now;
                    n.receipt_digest = head.receipt_digest.clone();
                    n.previous_digest = Some(incident_digest(old)?);
                    n
                }
            };
            // A new head is always created as open, then resolved/escalated by
            // the next bounded iteration against freshly read authority state.
            next.updated_at = now;
            validate(&serde_json::to_value(&next)?)?;
            let key = incident_key(self, c);
            let event = format!("{key}/events/{}", next.revision);
            let mut root = expected_root(&c.grant);
            root.status = "claimed".into();
            let mut compare = vec![
                value_eq(&self.root(&c.grant), &record(&root)?),
                value_eq(&self.grant_key(&c.grant), &s.attempt.grant_digest),
                value_eq(&self.nonce(&c.grant), &c.attempt_id),
                value_eq(&self.attempt(&c.grant, &c.attempt_id), &record(&s.attempt)?),
                value_eq(&context_key(self, &c.grant, &c.attempt_id), &s.context_raw),
                value_eq(
                    &index_key(self, &s.attempt.grant_digest, &c.attempt_id)?,
                    &record(c)?,
                ),
                value_eq(
                    &format!("{}/receipt-head", self.attempt(&c.grant, &c.attempt_id)),
                    s.head_raw.as_deref().ok_or_else(refused)?,
                ),
                value_eq(
                    &unknown_key,
                    std::str::from_utf8(&raw).map_err(|_| refused())?,
                ),
                version_zero(&event),
            ];
            match &old {
                Some(old) => {
                    compare.push(value_eq(&key, &record(old)?));
                    compare.push(value_eq(
                        &format!("{key}/events/{}", old.revision),
                        &record(old)?,
                    ));
                }
                None => compare.push(version_zero(&key)),
            }
            if self
                .txn(
                    compare,
                    vec![put(&key, &record(&next)?), put(&event, &record(&next)?)],
                    vec![],
                )
                .await?
                .succeeded
            {
                transitions.push(next.state);
            }
        }
        // A contention that exhausted the bound is unavailable, not an owned
        // incident success. Already committed events remain retained.
        Err(Error::Unavailable(
            "incident changed during bounded update; rescan".into(),
        ))
    }
    pub(crate) async fn delivery_progress(
        &self,
        c: &Candidate,
        a: &Acknowledgement,
    ) -> Result<Option<DeliveryProgress>> {
        let collector = collector_key(a)?;
        let raw = self
            .read_key(&progress_key(self, c, &collector, &a.receipt_digest))
            .await?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let p: DeliveryProgress = parse(&raw)?;
        if p.collector_digest != collector || p.receipt_digest != a.receipt_digest {
            return Err(refused());
        }
        Ok(Some(p))
    }
    pub(crate) async fn record_delivery(
        &self,
        c: &Candidate,
        r: &DeliveryReceipt,
        a: &Acknowledgement,
        p: &DeliveryProgress,
        previous: Option<&DeliveryProgress>,
    ) -> Result<DeliveryProgress> {
        validate(&serde_json::to_value(p)?)?;
        let s = self.recovery_snapshot(c).await?;
        let base = self.attempt(&c.grant, &c.attempt_id);
        let key = progress_key(self, c, &p.collector_digest, &p.receipt_digest);
        if s.context.signed_grant != r.signed_grant
            || s.attempt.grant_digest != a.grant_digest
            || a.attempt_id != c.attempt_id
            || p.receipt_digest != a.receipt_digest
            || p.collector_digest != collector_key(a)?
            || digest("outcome-evidence", &r.evidence)? != a.evidence_digest
        {
            return Err(refused());
        }
        let mut root = expected_root(&c.grant);
        root.status = "claimed".into();
        let mut compare = vec![
            value_eq(&self.root(&c.grant), &record(&root)?),
            value_eq(&self.grant_key(&c.grant), &a.grant_digest),
            value_eq(&self.nonce(&c.grant), &c.attempt_id),
            value_eq(&context_key(self, &c.grant, &c.attempt_id), &s.context_raw),
            value_eq(
                &index_key(self, &a.grant_digest, &c.attempt_id)?,
                &record(c)?,
            ),
            value_eq(
                &format!("{base}/receipts/{}", a.receipt_digest),
                &r.signed_receipt,
            ),
            value_eq(
                &format!("{base}/reports/evidence/{}", a.evidence_digest),
                &record(&r.evidence)?,
            ),
            version_zero(&key),
        ];
        match (&a.previous_receipt_digest, previous) {
            (None, None) => (),
            (Some(rd), Some(prev))
                if prev.receipt_digest == *rd && prev.collector_digest == p.collector_digest =>
            {
                compare.push(value_eq(
                    &progress_key(self, c, &p.collector_digest, rd),
                    &record(prev)?,
                ))
            }
            _ => return Err(refused()),
        }
        if self
            .txn(compare, vec![put(&key, &record(p)?)], vec![])
            .await?
            .succeeded
        {
            return Ok(p.clone());
        }
        let old = self.delivery_progress(c, a).await?.ok_or_else(refused)?;
        if old.acknowledgement != p.acknowledgement {
            return Err(refused());
        }
        Ok(old)
    }
}
