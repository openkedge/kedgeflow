//! Opt-in bounded budget history. Observer signatures attest retained data, not consensus.
use crate::{
    contracts::{canonical, digest, strict_value},
    coordination::ReservationSnapshot,
    error::{Error, Result},
    ledger::{EtcdLedger, put, record, value_eq, version_zero},
    recovery::ReceiptHead,
    reserved_leaf::{Change, Registration, ReservationBinding},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const LEAF_PROFILE: &str = "KF-RESERVED-LEAF-0.2-draft";
pub const PROFILE: &str = "KF-RESERVED-LINEAGE-0.1-draft";
pub const MAX_EVENTS: u64 = 256;
pub const MAX_BUNDLE: usize = 64 << 20;
fn refuse() -> Error {
    Error::Refused("reserved history or transition refused".into())
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventData {
    pub phase: String,
    pub operation_key: Option<String>,
    pub grant_digest: Option<String>,
    pub fence: Option<u64>,
    pub attempt_id: Option<String>,
    pub binding: Option<ReservationBinding>,
    pub signed_grant: Option<String>,
    pub outcome: Option<ReceiptHead>,
    pub evidence: Option<Value>,
}
impl EventData {
    pub(crate) fn new(phase: &str, operation: Option<&str>) -> Self {
        Self {
            phase: phase.into(),
            operation_key: operation.map(str::to_owned),
            ..Self::default()
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub profile: String,
    pub registration_digest: String,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub data: EventData,
    pub after: ReservationSnapshot,
}
impl Event {
    pub fn digest(&self) -> Result<String> {
        digest("reservation-history-event", &json!(self))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    sequence: u64,
    digest: String,
    state_digest: String,
}
fn state_digest(s: &ReservationSnapshot) -> Result<String> {
    digest("reservation-history-state", &json!(s))
}
pub(crate) fn base(ledger: &EtcdLedger, r: &Registration) -> Result<String> {
    Ok(format!(
        "{}/reservation-history/{}",
        ledger.namespace(),
        r.digest()?
    ))
}
fn event_key(base: &str, n: u64) -> String {
    format!("{base}/events/{n:06}")
}
impl EtcdLedger {
    async fn history_head(
        &self,
        r: &Registration,
        state: &ReservationSnapshot,
    ) -> Result<(Head, Vec<Value>)> {
        let base = base(self, r)?;
        let key = format!("{base}/head");
        let raw = self.read_key(&key).await?.ok_or_else(refuse)?;
        if raw.len() > 1024 {
            return Err(refuse());
        }
        let head: Head = serde_json::from_value(strict_value(&raw)?)?;
        if head.sequence == 0
            || head.sequence > MAX_EVENTS
            || head.state_digest != state_digest(state)?
        {
            return Err(refuse());
        }
        let last_key = event_key(&base, head.sequence);
        let last = self.read_key(&last_key).await?.ok_or_else(refuse)?;
        if last.len() > 256 << 10 {
            return Err(refuse());
        }
        let e: Event = serde_json::from_value(strict_value(&last)?)?;
        if e.digest()? != head.digest
            || e.sequence != head.sequence
            || e.registration_digest != r.digest()?
            || e.profile != PROFILE
            || e.after != *state
        {
            return Err(refuse());
        }
        Ok((
            head,
            vec![
                value_eq(&key, std::str::from_utf8(&raw).map_err(|_| refuse())?),
                value_eq(&last_key, std::str::from_utf8(&last).map_err(|_| refuse())?),
            ],
        ))
    }
    pub(crate) async fn history_guard(
        &self,
        r: &Registration,
        state: &ReservationSnapshot,
    ) -> Result<Vec<Value>> {
        if r.profile != LEAF_PROFILE {
            return Ok(Vec::new());
        }
        Ok(self.history_head(r, state).await?.1)
    }
    pub(crate) async fn history_change(
        &self,
        r: &Registration,
        before: Option<&ReservationSnapshot>,
        after: &ReservationSnapshot,
        data: EventData,
    ) -> Result<Change> {
        if r.profile != LEAF_PROFILE {
            return Ok(Change {
                compare: Vec::new(),
                writes: Vec::new(),
                newly_allocated: false,
            });
        }
        let base = base(self, r)?;
        let head_key = format!("{base}/head");
        let (sequence, previous_digest, mut compare) = if let Some(before) = before {
            let (head, compare) = self.history_head(r, before).await?;
            if head.sequence >= MAX_EVENTS
                || head.sequence == MAX_EVENTS - 1 && data.phase != "stop"
            {
                return Err(refuse());
            }
            (head.sequence + 1, Some(head.digest), compare)
        } else {
            (1, None, vec![version_zero(&head_key)])
        };
        after.validate()?;
        if canonical(&json!(after))?.len() > 128 << 10 {
            return Err(refuse());
        }
        let event = Event {
            profile: PROFILE.into(),
            registration_digest: r.digest()?,
            sequence,
            previous_digest,
            data,
            after: after.clone(),
        };
        let raw = record(&event)?;
        if raw.len() > 256 << 10 {
            return Err(refuse());
        }
        let key = event_key(&base, sequence);
        compare.push(version_zero(&key));
        let head = Head {
            sequence,
            digest: event.digest()?,
            state_digest: state_digest(after)?,
        };
        Ok(Change {
            compare,
            writes: vec![put(&key, &raw), put(&head_key, &record(&head)?)],
            newly_allocated: false,
        })
    }
    pub(crate) async fn read_reservation_history(
        &self,
        r: &Registration,
        state: &ReservationSnapshot,
    ) -> Result<(Vec<Event>, Vec<Value>)> {
        let (head, compare) = self.history_head(r, state).await?;
        let base = base(self, r)?;
        let mut events = Vec::new();
        for n in 1..=head.sequence {
            let raw = self
                .read_key(&event_key(&base, n))
                .await?
                .ok_or_else(refuse)?;
            if raw.len() > 256 << 10 {
                return Err(refuse());
            }
            events.push(serde_json::from_value(strict_value(&raw)?)?);
        }
        Ok((events, compare))
    }
}

impl EtcdLedger {
    /// Called only with the native worker's signed receipt in its outcome CAS.
    pub(crate) async fn reservation_refine(
        &self,
        g: &crate::contracts::Grant,
        gd: &str,
        attempt: &str,
        head: &ReceiptHead,
        evidence: &Value,
    ) -> Result<Change> {
        let required = crate::reserved_leaf::required_key(self, &g.conflict_domain);
        let raw = self.read_key(&required).await?;
        let audited = raw
            .as_ref()
            .map(|v| strict_value(v))
            .transpose()?
            .is_some_and(|v| v["profile"] == LEAF_PROFILE);
        if !audited {
            if self
                .reservation
                .as_ref()
                .is_some_and(|r| r.profile == LEAF_PROFILE)
            {
                return Err(refuse());
            }
            let compare = match raw {
                None => version_zero(&required),
                Some(v) => value_eq(&required, std::str::from_utf8(&v).map_err(|_| refuse())?),
            };
            return Ok(Change {
                compare: vec![compare],
                writes: Vec::new(),
                newly_allocated: false,
            });
        }
        if self
            .reservation
            .as_ref()
            .is_none_or(|r| r.profile != LEAF_PROFILE)
        {
            return Err(Error::Unavailable(
                "approved v0.2 reservation configuration required for recovery".into(),
            ));
        }
        let (mut gate, b) = self
            .reservation_bound(g, gd, false)
            .await?
            .ok_or_else(refuse)?;
        if gate.r.profile != LEAF_PROFILE {
            return Err(refuse());
        }
        let before = gate.state.clone();
        let a = gate
            .state
            .allocations
            .get_mut(&b.payload.operation_key)
            .ok_or_else(refuse)?;
        if a.attempt_id.as_deref() != Some(attempt) {
            return Err(refuse());
        }
        use crate::coordination::ReservationState as S;
        let target = if head.state == "committed" {
            Some(S::Committed)
        } else if head.state == "not_dispatched" {
            let journal = crate::recovery::journal_key(self, g, attempt, "dispatch_authorized");
            if self.read_key(&journal).await?.is_none() {
                gate.compare.push(version_zero(&journal));
                Some(S::ProvenNoEffect)
            } else {
                None
            }
        } else {
            None
        };
        let Some(target) = target else {
            if a.state != S::Unknown {
                return Err(refuse());
            }
            return Ok(Change {
                compare: gate.compare,
                writes: Vec::new(),
                newly_allocated: false,
            });
        };
        if a.state == target {
            return Ok(Change {
                compare: gate.compare,
                writes: Vec::new(),
                newly_allocated: false,
            });
        }
        if a.state != S::Unknown {
            return Err(refuse());
        }
        a.state = target;
        let mut data = EventData::new("refine", Some(&b.payload.operation_key));
        data.grant_digest = Some(gd.into());
        data.attempt_id = Some(attempt.into());
        data.outcome = Some(head.clone());
        data.evidence = Some(evidence.clone());
        let history = self
            .history_change(&gate.r, Some(&before), &gate.state, data)
            .await?;
        gate.compare.extend(history.compare);
        let mut writes = history.writes;
        writes.push(put(&gate.c.key, &record(&gate.state)?));
        Ok(Change {
            compare: gate.compare,
            writes,
            newly_allocated: false,
        })
    }
}
