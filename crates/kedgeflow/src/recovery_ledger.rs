//! All recovery state changes compare the snapshot; workers never dispatch.
use crate::{
    contracts::strict_value,
    error::{Error, Result},
    ledger::{
        Attempt, EtcdLedger, expected_root, get, put, range_kv, record, value_eq, version_zero,
    },
    recovery::{
        Candidate, ExecutionRecord, ReceiptHead, context_key, evidence_key, index_key, journal_key,
        transition,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub(crate) struct Snapshot {
    pub attempt: Attempt,
    pub outbox: String,
    pub context: ExecutionRecord,
    pub evidence: Option<Value>,
    pub head: Option<ReceiptHead>,
    pub head_raw: Option<String>,
    pub context_raw: String,
}
fn unavailable() -> Error {
    Error::Unavailable("inconsistent recovery snapshot".into())
}
impl EtcdLedger {
    pub(crate) async fn recovery_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Candidate>, Option<String>)> {
        if !(1..=64).contains(&limit)
            || cursor.is_some_and(|c| !crate::grant_reference::valid_reference(c))
        {
            return Err(Error::Invalid("invalid recovery page".into()));
        }
        let prefix = format!("{}/recovery/index/", self.namespace());
        let start = cursor
            .map(|c| format!("{prefix}{c}\0"))
            .unwrap_or_else(|| prefix.clone());
        let end = format!("{}/recovery/index0", self.namespace());
        let read = self.txn(vec![], vec![json!({"request_range":{"key":STANDARD.encode(start),"range_end":STANDARD.encode(end),"limit":limit.to_string()}})], vec![]).await?;
        if !read.succeeded || read.responses.len() != 1 {
            return Err(unavailable());
        }
        let range = read.responses[0]
            .get("response_range")
            .and_then(Value::as_object)
            .ok_or_else(unavailable)?;
        let entries = match range.get("kvs") {
            None => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            _ => return Err(unavailable()),
        };
        if entries.len() > limit {
            return Err(unavailable());
        }
        let mut candidates = Vec::new();
        let mut last = None;
        for kv in entries {
            let key = STANDARD
                .decode(kv["key"].as_str().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            let key = String::from_utf8(key).map_err(|_| unavailable())?;
            let raw = STANDARD
                .decode(kv["value"].as_str().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            let c: Candidate =
                serde_json::from_value(strict_value(&raw)?).map_err(|_| unavailable())?;
            let suffix = key
                .strip_prefix(&prefix)
                .filter(|s| crate::grant_reference::valid_reference(s))
                .ok_or_else(unavailable)?;
            if c.attempt_id.is_empty() || c.attempt_id.len() > 1024 {
                return Err(unavailable());
            }
            last = Some(suffix.to_owned());
            candidates.push(c);
        }
        Ok((
            candidates,
            if range.get("more").and_then(Value::as_bool) == Some(true) {
                last
            } else {
                None
            },
        ))
    }
    pub(crate) async fn recovery_snapshot(&self, c: &Candidate) -> Result<Snapshot> {
        let g = &c.grant;
        let id = &c.attempt_id;
        let read = self
            .txn(
                vec![],
                vec![
                    get(&self.root(g)),
                    get(&self.grant_key(g)),
                    get(&self.nonce(g)),
                    get(&self.attempt(g, id)),
                    get(&self.outbox(g, id)),
                    get(&context_key(self, g, id)),
                    get(&evidence_key(self, g, id)),
                    get(&format!("{}/receipt-head", self.attempt(g, id))),
                    get(&journal_key(self, g, id, "claimed")),
                    get(&journal_key(self, g, id, "dispatch_authorized")),
                ],
                vec![],
            )
            .await?;
        if !read.succeeded || read.responses.len() != 10 {
            return Err(unavailable());
        }
        let required = |i: usize| -> Result<String> {
            String::from_utf8(range_kv(&read.responses[i])?.ok_or_else(unavailable)?.value)
                .map_err(|_| unavailable())
        };
        let attempt: Attempt = serde_json::from_value(strict_value(required(3)?.as_bytes())?)
            .map_err(|_| unavailable())?;
        let outbox = required(4)?;
        let context_raw = required(5)?;
        let context: ExecutionRecord =
            serde_json::from_value(strict_value(context_raw.as_bytes())?)
                .map_err(|_| unavailable())?;
        let mut root = expected_root(g);
        root.status = "claimed".into();
        if required(0)? != record(&root)?
            || required(1)? != attempt.grant_digest
            || required(2)? != *id
            || attempt.id != *id
            || attempt.root_id != g.root_id
        {
            return Err(unavailable());
        }
        let claimed: Value = strict_value(required(8)?.as_bytes())?;
        crate::recovery::validate(&claimed)?;
        if claimed["phase"] != "claimed"
            || claimed["attempt_id"] != *id
            || claimed["grant_digest"] != attempt.grant_digest
            || claimed["root_id"] != g.root_id
        {
            return Err(unavailable());
        }
        let valid = match attempt.status.as_str() {
            "claimed" => {
                ["claimed_not_dispatched", "dispatch_authorized"].contains(&outbox.as_str())
            }
            "unknown" | "committed" | "not_dispatched" | "state_guard_violation" => {
                outbox == attempt.status
            }
            _ => false,
        };
        if !valid {
            return Err(unavailable());
        }
        if outbox == "dispatch_authorized"
            || ["unknown", "committed", "state_guard_violation"].contains(&attempt.status.as_str())
        {
            let dispatched: Value = strict_value(required(9)?.as_bytes())?;
            crate::recovery::validate(&dispatched)?;
            if dispatched["phase"] != "dispatch_authorized"
                || dispatched["attempt_id"] != *id
                || dispatched["grant_digest"] != attempt.grant_digest
                || dispatched["root_id"] != g.root_id
            {
                return Err(unavailable());
            }
        }
        let evidence = range_kv(&read.responses[6])?
            .map(|v| strict_value(&v.value))
            .transpose()?;
        let head_raw = range_kv(&read.responses[7])?
            .map(|v| String::from_utf8(v.value).map_err(|_| unavailable()))
            .transpose()?;
        let head = head_raw
            .as_ref()
            .map(|v| {
                serde_json::from_value::<ReceiptHead>(strict_value(v.as_bytes())?)
                    .map_err(|_| unavailable())
            })
            .transpose()?;
        Ok(Snapshot {
            attempt,
            outbox,
            context,
            evidence,
            head,
            head_raw,
            context_raw,
        })
    }
    pub(crate) async fn apply_recovery(
        &self,
        c: &Candidate,
        s: &Snapshot,
        state: &str,
        evidence: &Value,
        head: &ReceiptHead,
        now: i64,
    ) -> Result<()> {
        let g = &c.grant;
        let id = &c.attempt_id;
        let attempt_key = self.attempt(g, id);
        let head_key = format!("{attempt_key}/receipt-head");
        let mut root = expected_root(g);
        root.status = "claimed".into();
        let mut compare = vec![
            value_eq(&self.root(g), &record(&root)?),
            value_eq(&self.grant_key(g), &s.attempt.grant_digest),
            value_eq(&self.nonce(g), id),
            value_eq(&attempt_key, &record(&s.attempt)?),
            value_eq(&self.outbox(g, id), &s.outbox),
            value_eq(&context_key(self, g, id), &s.context_raw),
            value_eq(&index_key(self, &s.attempt.grant_digest, id)?, &record(c)?),
        ];
        compare.push(match &s.head_raw {
            Some(v) => value_eq(&head_key, v),
            None => version_zero(&head_key),
        });
        let receipt_key = format!("{attempt_key}/receipts/{}", head.receipt_digest);
        compare.push(version_zero(&receipt_key));
        let mut after = s.attempt.clone();
        after.status = state.into();
        let mut writes = vec![
            put(&attempt_key, &record(&after)?),
            put(&self.outbox(g, id), state),
            put(&head_key, &record(head)?),
            put(&receipt_key, &head.signed_receipt),
            put(&evidence_key(self, g, id), &record(evidence)?),
            put(
                &format!("{attempt_key}/reports/evidence/{}", head.evidence_digest),
                &record(evidence)?,
            ),
        ];
        if state != s.attempt.status {
            let event = journal_key(self, g, id, state);
            compare.push(version_zero(&event));
            writes.push(put(&event, &transition(g, &after, state, now)?));
        }
        let reservation = self
            .reservation_refine(g, &s.attempt.grant_digest, id, head, evidence)
            .await?;
        compare.extend(reservation.compare);
        writes.extend(reservation.writes);
        if !self.txn(compare, writes, vec![]).await?.succeeded {
            return Err(Error::Refused(
                "recovery snapshot changed; query again".into(),
            ));
        }
        Ok(())
    }
}

impl EtcdLedger {
    /// Protected operator-side export, not an agent disclosure endpoint.
    pub async fn export_outcomes(&self, c: &Candidate) -> Result<crate::recovery::OutcomeBundle> {
        let s = self.recovery_snapshot(c).await?;
        let mut head = s
            .head
            .ok_or_else(|| Error::Unknown("no retained outcome receipt".into()))?;
        let mut receipts = Vec::new();
        let mut evidence = std::collections::BTreeMap::new();
        let base = self.attempt(&c.grant, &c.attempt_id);
        loop {
            if receipts.len() >= 64 {
                return Err(Error::Unavailable(
                    "receipt chain exceeds export bound".into(),
                ));
            }
            let raw = self
                .read_key(&format!("{base}/receipts/{}", head.receipt_digest))
                .await?
                .ok_or_else(unavailable)?;
            let raw = String::from_utf8(raw).map_err(|_| unavailable())?;
            if raw != head.signed_receipt {
                return Err(unavailable());
            }
            let e: crate::contracts::Envelope =
                serde_json::from_value(strict_value(raw.as_bytes())?)?;
            if crate::contracts::record_digest(&e)? != head.receipt_digest {
                return Err(unavailable());
            }
            let ed = e.payload["resolution_evidence"][0]["digest"]
                .as_str()
                .ok_or_else(unavailable)?;
            let body = self
                .read_key(&format!("{base}/reports/evidence/{ed}"))
                .await?
                .ok_or_else(unavailable)?;
            evidence.insert(ed.into(), strict_value(&body)?);
            receipts.push(raw);
            let previous = e.payload["previous_receipt_digest"].as_str();
            let Some(previous) = previous else {
                break;
            };
            let raw = self
                .read_key(&format!("{base}/receipts/{previous}"))
                .await?
                .ok_or_else(unavailable)?;
            head.receipt_digest = previous.into();
            head.signed_receipt = String::from_utf8(raw).map_err(|_| unavailable())?;
        }
        receipts.reverse();
        let mut journal = Vec::new();
        for phase in [
            "claimed",
            "dispatch_authorized",
            "not_dispatched",
            "unknown",
            "committed",
            "state_guard_violation",
        ] {
            if let Some(raw) = self
                .read_key(&journal_key(self, &c.grant, &c.attempt_id, phase))
                .await?
            {
                journal.push(strict_value(&raw)?);
            }
        }
        Ok(crate::recovery::OutcomeBundle {
            profile: crate::recovery::PROFILE.into(),
            execution: s.context,
            attempt_id: c.attempt_id.clone(),
            receipts,
            evidence,
            journal,
        })
    }
}
