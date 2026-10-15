//! Immutable governance event append participates in each live mutation's CAS.
use crate::{
    contracts::{MAX_SAFE_INTEGER, strict_value},
    control_history::{HistoryEvent, HistoryHead, MAX_EVENTS},
    error::{Error, Result},
    governance::StoredControl,
    ledger::{EtcdLedger, get, mod_revision, put, range_kv, record, version_zero},
};
use serde_json::Value;
impl EtcdLedger {
    fn history_base(&self, domain: &str) -> String {
        format!("{}/control/history", self.domain_base(domain))
    }
    pub(crate) async fn history_append(
        &self,
        domain: &str,
        control: &StoredControl,
        kind: &str,
    ) -> Result<(Vec<Value>, Vec<Value>)> {
        self.action_domain_scope(domain)?;
        let base = self.history_base(domain);
        let hk = format!("{base}/head");
        let t = self.txn(vec![], vec![get(&hk)], vec![]).await?;
        if !t.succeeded || t.responses.len() != 1 {
            return Err(Error::Unavailable("invalid history head read".into()));
        }
        let kv = range_kv(&t.responses[0])?;
        let now = self.authority_clock.now_ms();
        if !(0..=MAX_SAFE_INTEGER as i64).contains(&now) {
            return Err(Error::Refused(
                "history accepted clock outside profile".into(),
            ));
        }
        let (sequence, previous_digest, mut compare) = if let Some(kv) = kv {
            let head: HistoryHead = serde_json::from_value(strict_value(&kv.value)?)?;
            if head.sequence == 0
                || head.sequence >= MAX_SAFE_INTEGER
                || now < head.accepted_at
                || !crate::grant_reference::valid_reference(&head.digest)
            {
                return Err(Error::Refused(
                    "invalid/exhausted history or backward accepted clock".into(),
                ));
            }
            let previous_key = format!("{base}/events/{:020}", head.sequence);
            let previous = self
                .read_key(&previous_key)
                .await?
                .ok_or_else(|| Error::Unavailable("history head event missing".into()))?;
            let event: HistoryEvent = serde_json::from_value(strict_value(&previous)?)?;
            if event.sequence != head.sequence
                || event.digest()? != head.digest
                || event.accepted_at != head.accepted_at
            {
                return Err(Error::Unavailable(
                    "history head event correlation mismatch".into(),
                ));
            }
            (
                head.sequence + 1,
                Some(head.digest),
                vec![
                    mod_revision(&hk, &kv.mod_revision),
                    crate::ledger::value_eq(&previous_key, &record(&event)?),
                ],
            )
        } else {
            let domain_base = self.domain_base(domain);
            // No fabricated prefix for pre-existing managed state. The same
            // transaction guards genesis against a competing first mutation.
            let genesis = [
                "control/publish_policy",
                "control/register_descriptor",
                "control/installation",
                "control/ack",
                "control-required",
                "revocations/domain",
            ];
            let keys: Vec<_> = genesis
                .iter()
                .map(|s| format!("{domain_base}/{s}"))
                .collect();
            let t = self
                .txn(vec![], keys.iter().map(|k| get(k)).collect(), vec![])
                .await?;
            if !t.succeeded
                || t.responses.len() != keys.len()
                || t.responses
                    .iter()
                    .map(range_kv)
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .any(Option::is_some)
            {
                return Err(Error::Refused(
                    "legacy managed state has no history genesis".into(),
                ));
            }
            let mut compares = keys.iter().map(|k| version_zero(k)).collect::<Vec<_>>();
            compares.push(version_zero(&hk));
            (1, None, compares)
        };
        let event = HistoryEvent {
            sequence,
            previous_digest,
            kind: kind.into(),
            accepted_at: now,
            control: control.clone(),
        };
        let head = HistoryHead {
            sequence,
            digest: event.digest()?,
            accepted_at: now,
        };
        let ek = format!("{base}/events/{sequence:020}");
        compare.push(version_zero(&ek));
        Ok((
            compare,
            vec![put(&ek, &record(&event)?), put(&hk, &record(&head)?)],
        ))
    }
    pub(crate) async fn retained_control_history(
        &self,
        domain: &str,
    ) -> Result<(HistoryHead, Vec<HistoryEvent>)> {
        self.action_domain_scope(domain)?;
        let base = self.history_base(domain);
        let t = self
            .txn(vec![], vec![get(&format!("{base}/head"))], vec![])
            .await?;
        if !t.succeeded || t.responses.len() != 1 {
            return Err(Error::Unavailable("invalid history head read".into()));
        }
        let kv = range_kv(&t.responses[0])?
            .ok_or_else(|| Error::Refused("retained control history absent".into()))?;
        let head: HistoryHead = serde_json::from_value(strict_value(&kv.value)?)?;
        if head.sequence == 0 || head.sequence > MAX_EVENTS {
            return Err(Error::Refused(
                "history export count unsupported; no prefix truncation".into(),
            ));
        }
        let reads = (1..=head.sequence)
            .map(|s| get(&format!("{base}/events/{s:020}")))
            .collect();
        let t = self.txn(vec![], reads, vec![]).await?;
        if !t.succeeded || t.responses.len() != head.sequence as usize {
            return Err(Error::Unavailable("invalid retained history read".into()));
        }
        let mut events = Vec::new();
        let mut previous = None;
        let mut time = 0;
        for (n, r) in t.responses.iter().enumerate() {
            let kv = range_kv(r)?
                .ok_or_else(|| Error::Unavailable("missing retained history event".into()))?;
            let event: HistoryEvent = serde_json::from_value(strict_value(&kv.value)?)?;
            if event.sequence != n as u64 + 1
                || event.previous_digest != previous
                || event.accepted_at < time
            {
                return Err(Error::Unavailable(
                    "retained control history correlation mismatch".into(),
                ));
            }
            previous = Some(event.digest()?);
            time = event.accepted_at;
            events.push(event);
        }
        if previous.as_deref() != Some(&head.digest) || time != head.accepted_at {
            return Err(Error::Unavailable("retained history head mismatch".into()));
        }
        Ok((head, events))
    }
}
