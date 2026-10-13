//! RFC 0023 target-side prerequisite. These records confer no execution authority.
//! The existing gateway still accepts only the mock action; native SQL carriage
//! and independently authenticated target/query integration are separate work.
use crate::{
    contracts::{Resource, strict_value},
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

pub const PROFILE: &str = "KF-POSTGRES-RESERVATION-0.1-draft";
pub const ACTION: &str = "postgres.reservation.set.v1";
pub const MIGRATION: &str = include_str!("../../../migrations/postgres/0001-reservation.sql");
const MAX_RECORD_BYTES: usize = 32 * 1024;

fn record(raw: &[u8]) -> Result<Value> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid("PostgreSQL record exceeds bound".into()));
    }
    let value = strict_value(raw)?;
    validate(&value)?;
    Ok(value)
}

pub fn validate(value: &Value) -> Result<()> {
    static PIN: OnceLock<std::result::Result<jsonschema::Validator, String>> = OnceLock::new();
    let pin = PIN.get_or_init(|| {
        let schema = serde_json::from_str(include_str!(
            "../../../spec/drafts/postgres-reservation-v0.1.schema.json"
        ))
        .map_err(|_| "invalid PostgreSQL action schema".to_owned())?;
        crate::schema::compile(&schema).map_err(|_| "invalid local PostgreSQL schema".to_owned())
    });
    if !pin
        .as_ref()
        .map_err(|m| Error::Unavailable(m.clone()))?
        .is_valid(value)
    {
        return Err(Error::Invalid("invalid PostgreSQL action record".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub resource_id: String,
    pub expected_version: u64,
    pub reservation: String,
}

impl Parameters {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value = record(raw)?;
        Ok(serde_json::from_value(value)?)
    }
}

/// Construct only inside an independently authenticated target service, after
/// checking the signed grant, credential and actual request against fixed pins.
/// Decoding validates shape; it is neither grant verification nor authorization.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchRequest {
    pub profile: String,
    pub action: String,
    pub tenant: String,
    pub conflict_domain: String,
    pub attempt_id: String,
    pub grant_digest: String,
    pub root_id: String,
    pub resource: Resource,
    pub expected_version: u64,
    pub fence: u64,
    pub reservation: String,
    pub gateway_workload: String,
    pub expires_at: u64,
}

impl DispatchRequest {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value = record(raw)?;
        Ok(serde_json::from_value(value)?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Committed,
    GuardRejected,
}

/// This unsigned record is evidence only under authenticated target custody.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub profile: String,
    pub request: DispatchRequest,
    pub status: Status,
    pub post_version: Option<u64>,
}

impl Outcome {
    pub fn verify(raw: &[u8], expected: &DispatchRequest) -> Result<Self> {
        validate(&serde_json::to_value(expected)?)?;
        let value = record(raw)?;
        let outcome: Self = serde_json::from_value(value)?;
        if &outcome.request != expected
            || match outcome.status {
                Status::Committed => {
                    outcome.post_version != expected.expected_version.checked_add(1)
                }
                Status::GuardRejected => outcome.post_version.is_some(),
            }
        {
            return Err(Error::Unknown("uncorrelated PostgreSQL outcome".into()));
        }
        Ok(outcome)
    }
}
