//! Native-write snapshot consistency for the explicit composition profile.
//! The epoch is initialized only by fresh family namespace enrollment; reads
//! never repair or initialize a missing epoch.
use crate::{
    contracts::{digest, strict_value},
    error::{Error, Result},
    family::{Access, Registration},
    family_saga::PROFILE,
    ledger::{EtcdLedger, get, put, range_kv, record, value_eq},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) fn selected(l: &EtcdLedger) -> bool {
    l.family.as_ref().is_some_and(|a| match a.as_ref() {
        Access::Manager(r) => r.composition.is_some(),
        Access::Child(s) => s.registration.composition.is_some(),
    })
}
fn root_stop(l: &EtcdLedger, r: &Registration, success: &[Value]) -> bool {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if success.len() != 1 {
        return false;
    }
    let op = &success[0]["request_put"];
    let Some(k) = op["key"].as_str() else {
        return false;
    };
    let Some(v) = op["value"].as_str() else {
        return false;
    };
    if STANDARD.decode(k).ok().as_deref()
        != Some(format!("{}/family/state", l.namespace()).as_bytes())
    {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(v) else {
        return false;
    };
    if bytes.len() > crate::family::MAX_BYTES {
        return false;
    }
    let Ok(state) = serde_json::from_slice::<crate::family::State>(&bytes) else {
        return false;
    };
    !state.active && state.verify(r).is_ok() && state.events.last().is_some_and(|e|matches!(&e.command.payload.action,crate::family::Action::Stop {branch_id} if branch_id=="root"))
}

fn refused() -> Error {
    Error::Refused("native family saga write epoch is missing or inconsistent".into())
}
fn key(l: &EtcdLedger) -> String {
    format!("{}/family/saga/epoch", l.namespace())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    profile: String,
    registration_digest: String,
    sequence: u64,
    nonce: String,
}
impl Epoch {
    fn fresh(r: &Registration, sequence: u64) -> Result<Self> {
        Ok(Self {
            profile: PROFILE.into(),
            registration_digest: r.digest()?,
            sequence,
            nonce: hex::encode(rand::random::<[u8; 32]>()),
        })
    }
    fn decode(raw: &[u8], r: &Registration) -> Result<Self> {
        if raw.len() > 512 {
            return Err(refused());
        }
        let e: Self = serde_json::from_value(strict_value(raw)?)?;
        if e.profile != PROFILE
            || e.registration_digest != r.digest()?
            || !(1..=crate::contracts::MAX_SAFE_INTEGER).contains(&e.sequence)
            || !crate::grant_reference::valid_reference(&e.nonce)
            || record(&e)?.as_bytes() != raw
        {
            return Err(refused());
        }
        Ok(e)
    }
}
pub(crate) fn initial_writes(l: &EtcdLedger, r: &Registration) -> Result<Vec<Value>> {
    if r.composition.is_none() {
        return Ok(vec![]);
    }
    if l.namespace() != r.namespace {
        return Err(refused());
    }
    Ok(vec![put(&key(l), &record(&Epoch::fresh(r, 1)?)?)])
}
pub(crate) struct CapturedEpoch {
    pub token: String,
    pub compare: Value,
}
pub(crate) async fn capture(l: &EtcdLedger, r: &Registration) -> Result<CapturedEpoch> {
    let k = key(l);
    let read = l.raw_txn(vec![], vec![get(&k)], vec![]).await?;
    if !read.succeeded || read.responses.len() != 1 {
        return Err(refused());
    }
    let raw = range_kv(&read.responses[0])?.ok_or_else(refused)?;
    let e = Epoch::decode(&raw.value, r)?;
    Ok(CapturedEpoch {
        token: digest("family-saga-write-epoch", &json!(e))?,
        compare: value_eq(&k, &record(&e)?),
    })
}
impl EtcdLedger {
    pub(crate) async fn family_saga_epoch(
        &self,
        success: &mut Vec<Value>,
        failure: &[Value],
    ) -> Result<Vec<Value>> {
        let Some(access) = &self.family else {
            return Ok(vec![]);
        };
        let r = match access.as_ref() {
            Access::Manager(r) => r,
            Access::Child(s) => &s.registration,
        };
        if r.composition.is_none() {
            return Ok(vec![]);
        }
        // This rule applies before restore wrapping too. A failed application
        // comparison must never mutate native state without changing the epoch.
        if failure.iter().any(|op| op.get("request_range").is_none())
            || success.iter().any(|op| {
                op.get("request_range").is_none()
                    && op.get("request_put").is_none()
                    && op.get("request_delete_range").is_none()
            })
        {
            return Err(refused());
        }
        let k = key(self);
        let read = self.raw_txn(vec![], vec![get(&k)], vec![]).await?;
        if !read.succeeded || read.responses.len() != 1 {
            return Err(refused());
        }
        let raw = range_kv(&read.responses[0])?.ok_or_else(refused)?;
        let old = Epoch::decode(&raw.value, r)?;
        if success.iter().any(|op| op.get("request_range").is_none()) {
            if old.sequence >= crate::contracts::MAX_SAFE_INTEGER - 1
                && !root_stop(self, r, success)
            {
                return Err(refused());
            }
            let sequence = old
                .sequence
                .checked_add(1)
                .filter(|n| *n <= crate::contracts::MAX_SAFE_INTEGER)
                .ok_or_else(refused)?;
            // The sequence cannot wrap, so the encoded record cannot return
            // to an earlier value even if a random nonce repeats.
            let next = Epoch::fresh(r, sequence)?;
            success.push(put(&k, &record(&next)?));
        }
        // Keep any caller's different collected-epoch comparison as well. It
        // must cause a failed CAS, never be replaced by this current read.
        Ok(vec![value_eq(&k, &record(&old)?)])
    }
}
