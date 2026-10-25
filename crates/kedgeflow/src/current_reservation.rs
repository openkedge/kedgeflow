//! Fresh read-only SQL reservation evidence; never inverse or dispatch authority.
use crate::{
    contracts::{Resource, canonical, digest},
    error::{Error, Result},
    family_saga::ObserverPin,
    grant_reference::{fixed_https, valid_reference},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
pub const PROFILE: &str = "KF-CURRENT-SQL-RESERVATION-0.2-draft";
fn refuse() -> Error {
    Error::Refused("protected current SQL reservation registration refused".into())
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/@".contains(&b))
}
/// An observed server/database lifetime, not a general rollback detector. A
/// postmaster restart or database recreation requires fresh protected enrollment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageIdentity {
    pub database: String,
    pub database_oid: u64,
    pub postmaster_started_at_us: u64,
}
impl StorageIdentity {
    pub fn validate(&self) -> Result<()> {
        if !id(&self.database)
            || self.database.len() > 63
            || self.database_oid == 0
            || self.database_oid > u32::MAX as u64
            || self.postmaster_started_at_us == 0
            || self.postmaster_started_at_us > crate::contracts::MAX_SAFE_INTEGER
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StorageBoundary {
    pub storage_id: String,
    pub generation: u64,
    pub identity: StorageIdentity,
    pub owner: ObserverPin,
    pub restore_protocol_digest: String,
    pub coordinated_writers: Vec<String>,
    pub external_writers: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub profile: String,
    pub tenant: String,
    pub forward_child_id: String,
    pub forward_operation_key: String,
    pub forward_reservation_root_id: String,
    pub compensation_contract_digest: String,
    pub resource: Resource,
    pub endpoint: String,
    pub evidence_endpoint: String,
    pub provider: ObserverPin,
    pub storage: StorageBoundary,
    pub maximum_age_ms: u64,
    pub request_timeout_ms: u64,
}
impl Registration {
    pub fn validate(&self) -> Result<()> {
        let s = &self.storage;
        s.identity.validate()?;
        if self.profile != PROFILE
            || !id(&self.tenant)
            || !id(&self.forward_child_id)
            || !valid_reference(&self.forward_operation_key)
            || !id(&self.forward_reservation_root_id)
            || !valid_reference(&self.compensation_contract_digest)
            || !id(&self.resource.id)
            || !id(&self.resource.incarnation)
            || !id(&s.storage_id)
            || s.generation == 0
            || s.generation > crate::contracts::MAX_SAFE_INTEGER
            || !valid_reference(&s.restore_protocol_digest)
            || !(1..=5000).contains(&self.maximum_age_ms)
            || !(1..=5000).contains(&self.request_timeout_ms)
            || s.coordinated_writers.is_empty()
            || s.coordinated_writers.len() > 32
            || s.external_writers.len() > 32
            || s.coordinated_writers
                .iter()
                .chain(s.external_writers.iter())
                .any(|s| !id(s))
            || s.coordinated_writers
                .iter()
                .chain(s.external_writers.iter())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != s.coordinated_writers.len() + s.external_writers.len()
            || fixed_https(&self.endpoint)?.as_str() != self.endpoint
            || fixed_https(&self.evidence_endpoint)?.as_str() != self.evidence_endpoint
            || crate::endpoint::EndpointPolicy::new(&self.endpoint)?.authority()
                != crate::endpoint::EndpointPolicy::new(&self.evidence_endpoint)?.authority()
            || self.endpoint == self.evidence_endpoint
            || canonical(&json!(self))?.len() > 32 << 10
        {
            return Err(refuse());
        }
        let mut all = std::collections::BTreeSet::new();
        for pin in [&self.provider, &s.owner] {
            if !id(&pin.id)
                || pin.keys.is_empty()
                || pin.keys.len() > 16
                || pin.keys.keys().any(|s| !id(s))
            {
                return Err(refuse());
            }
            for key in crate::control_config::keys(&pin.keys)?.values() {
                if !all.insert(*key.as_bytes()) {
                    return Err(refuse());
                }
            }
        }
        if self.provider.id == s.owner.id {
            return Err(refuse());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("current-sql-reservation-registration", &json!(self))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageHead {
    pub storage_id: String,
    pub generation: u64,
    pub sequence: u64,
    pub resource: Resource,
    pub boundary_digest: String,
    pub published_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub profile: String,
    pub kind: String,
    pub signer_id: String,
    pub key_id: String,
    pub body: T,
    pub signature: String,
}
impl<T: Serialize> Signed<T> {
    fn message(&self) -> Result<Vec<u8>> {
        let mut b = format!("KedgeFlow:{PROFILE}\0").into_bytes();
        b.extend(canonical(&json!({"profile":self.profile,"kind":self.kind,"signer_id":self.signer_id,"key_id":self.key_id,"body":self.body}))?);
        Ok(b)
    }
    pub fn sign(
        kind: &str,
        body: T,
        pin: &ObserverPin,
        key_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::Signer;
        if crate::control_config::keys(&pin.keys)?.get(key_id) != Some(&key.verifying_key()) {
            return Err(refuse());
        }
        let mut s = Self {
            profile: PROFILE.into(),
            kind: kind.into(),
            signer_id: pin.id.clone(),
            key_id: key_id.into(),
            body,
            signature: String::new(),
        };
        s.signature = URL_SAFE_NO_PAD.encode(key.sign(&s.message()?).to_bytes());
        Ok(s)
    }
    pub fn verify(&self, kind: &str, pin: &ObserverPin) -> Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        if self.profile != PROFILE || self.kind != kind || self.signer_id != pin.id {
            return Err(refuse());
        }
        let keys = crate::control_config::keys(&pin.keys)?;
        let key = keys.get(&self.key_id).ok_or_else(refuse)?;
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| refuse())?;
        if URL_SAFE_NO_PAD.encode(&raw) != self.signature {
            return Err(refuse());
        }
        let sig = ed25519_dalek::Signature::from_slice(&raw).map_err(|_| refuse())?;
        key.verify_strict(&self.message()?, &sig)
            .map_err(|_| refuse())
    }
    pub fn digest(&self) -> Result<String> {
        digest("current-sql-reservation-statement", &json!(self))
    }
}
impl Signed<StorageHead> {
    pub fn validate_head(&self, r: &Registration, at: i64) -> Result<()> {
        self.verify("storage_head", &r.storage.owner)?;
        let b = &self.body;
        if b.storage_id != r.storage.storage_id
            || b.generation != r.storage.generation
            || b.resource != r.resource
            || b.sequence == 0
            || b.sequence > crate::contracts::MAX_SAFE_INTEGER
            || b.boundary_digest != digest("sql-storage-boundary", &json!(r.storage))?
            || b.published_at < (r.storage.identity.postmaster_started_at_us / 1000) as i64
            || b.published_at > at
            || b.expires_at <= at
            || b.expires_at > crate::contracts::MAX_SAFE_INTEGER as i64
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub profile: String,
    pub enrollment_digest: String,
    pub origin: crate::managed_drain_journal::Origin,
    pub reservation_digest: String,
    pub requested_at: i64,
}
impl Query {
    pub fn digest(&self) -> Result<String> {
        digest("current-sql-reservation-query", &json!(self))
    }
}
/// The one-use native source-read reservation precedes any SQL source I/O.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceClaim {
    pub profile: String,
    pub enrollment_digest: String,
    pub origin_digest: String,
    pub reservation_digest: String,
    pub query_digest: String,
    pub requested_at: i64,
    pub operating_head_digest: String,
    pub claimed_at: i64,
    pub expires_at: i64,
}
impl SourceClaim {
    pub fn digest(&self) -> Result<String> {
        digest("current-sql-source-claim", &json!(self))
    }
    pub fn validate(
        &self,
        e: &crate::managed_drain::Enrollment,
        o: &crate::managed_drain_journal::Origin,
    ) -> Result<()> {
        let q = Query {
            profile: PROFILE.into(),
            enrollment_digest: e.digest()?,
            origin: o.clone(),
            reservation_digest: self.reservation_digest.clone(),
            requested_at: self.requested_at,
        };
        if self.profile != PROFILE
            || self.enrollment_digest != e.digest()?
            || self.origin_digest != o.digest()?
            || self.query_digest != q.digest()?
            || !valid_reference(&self.reservation_digest)
            || !valid_reference(&self.operating_head_digest)
            || self.expires_at <= self.claimed_at
            || self.expires_at > crate::contracts::MAX_SAFE_INTEGER as i64
            || self.expires_at.saturating_sub(self.claimed_at) > 5000
            || self.claimed_at < o.original.dispatched_at
            || self.claimed_at > crate::contracts::MAX_SAFE_INTEGER as i64
            || self.requested_at < 0
            || self.requested_at
                < o.original
                    .dispatched_at
                    .saturating_sub(e.clock_uncertainty_ms as i64)
            || self.requested_at
                > self
                    .claimed_at
                    .saturating_add(e.clock_uncertainty_ms as i64)
            || self.claimed_at - self.requested_at > e.current_sql.maximum_age_ms as i64
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub requested_at: i64,
    pub query_digest: String,
    pub enrollment_digest: String,
    pub origin_digest: String,
    pub reservation_digest: String,
    pub source_claim: SourceClaim,
    pub storage_head: Signed<StorageHead>,
    pub sql: crate::postgres_compensation::BarrierObservation,
    pub from: i64,
    pub until: i64,
    pub expires_at: i64,
}
pub type Witness = Signed<Observation>;
impl Witness {
    pub fn validate_current(
        &self,
        e: &crate::managed_drain::Enrollment,
        o: &crate::managed_drain_journal::Origin,
        reservation: &str,
        at: i64,
        sql_grant: &crate::contracts::Grant,
        sql_digest: &str,
    ) -> Result<()> {
        let r = &e.current_sql;
        r.validate()?;
        self.verify("reservation_observation", &r.provider)?;
        let b = &self.body;

        b.source_claim.validate(e, o)?;
        self.body.storage_head.validate_head(r, b.until)?;
        self.body.storage_head.validate_head(r, at)?;
        let expected = Query {
            profile: PROFILE.into(),
            enrollment_digest: e.digest()?,
            origin: o.clone(),
            reservation_digest: reservation.into(),
            requested_at: b.requested_at,
        };
        if b.source_claim.requested_at != b.requested_at
            || b.source_claim.query_digest != b.query_digest
            || b.source_claim.reservation_digest != b.reservation_digest
            || b.from < b.source_claim.claimed_at
            || b.requested_at < 0
            || b.from < b.requested_at.saturating_sub(e.clock_uncertainty_ms as i64)
            || b.query_digest != expected.digest()?
            || b.enrollment_digest != e.digest()?
            || b.origin_digest != o.digest()?
            || b.reservation_digest != reservation
            || !valid_reference(&b.query_digest)
            || b.from < 0
            || b.from > b.until
            || b.until > at
            || b.expires_at <= at
            || b.expires_at > b.source_claim.expires_at
            || b.expires_at - b.from > r.maximum_age_ms as i64
            || b.until - b.from > r.request_timeout_ms as i64
            || b.expires_at > crate::contracts::MAX_SAFE_INTEGER as i64
        {
            return Err(refuse());
        }
        validate_sql(r, sql_grant, sql_digest, &o.forward_attempt_id, &b.sql)
    }
}

pub const OBLIGATION: &str = "managed-current-sql";
pub fn question(r: &Registration) -> Result<crate::admission::RecordReference> {
    Ok(crate::admission::RecordReference {
        id: "kedgeflow:question:current-sql-reservation".into(),
        schema: "urn:kedgeflow:current-sql-reservation:question:2.0".into(),
        digest: r.digest()?,
    })
}
pub fn result_schema() -> serde_json::Value {
    json!({"type":"object","additionalProperties":false,"properties":{
 "current":{"type":"boolean"},"registration_digest":{"type":"string","pattern":"^[a-f0-9]{64}$"},"forward_reservation_root_id":{"type":"string"},"forward_execution_root_id":{"type":"string"},"incarnation":{"type":"string"},"storage_generation":{"type":"string"},
 "forward_grant_digest":{"type":"string","pattern":"^[a-f0-9]{64}$"},"forward_attempt_id":{"type":"string"},"fence":{"type":"integer","minimum":1,"maximum":crate::contracts::MAX_SAFE_INTEGER},"post_version":{"type":"integer","minimum":1,"maximum":crate::contracts::MAX_SAFE_INTEGER},"observation_digest":{"type":"string","pattern":"^[a-f0-9]{64}$"}},
 "required":["current","registration_digest","forward_reservation_root_id","forward_execution_root_id","incarnation","storage_generation","forward_grant_digest","forward_attempt_id","fence","post_version","observation_digest"]})
}
pub fn schema_reference() -> Result<crate::admission::RecordReference> {
    Ok(crate::admission::RecordReference {
        id: "kedgeflow:result:current-sql-reservation".into(),
        schema: "urn:kedgeflow:current-sql-reservation:result:2.0".into(),
        digest: digest("result-schema", &result_schema())?,
    })
}
pub fn predicates(r: &Registration) -> Result<Vec<crate::admission::EvidencePredicate>> {
    use crate::admission::EvidencePredicate as P;
    Ok(vec![
        P::BooleanEquals {
            field: "current".into(),
            expected: true,
        },
        P::StringEquals {
            field: "registration_digest".into(),
            expected: r.digest()?,
        },
        P::StringEquals {
            field: "forward_reservation_root_id".into(),
            expected: r.forward_reservation_root_id.clone(),
        },
        P::StringEquals {
            field: "incarnation".into(),
            expected: r.resource.incarnation.clone(),
        },
        P::StringEquals {
            field: "storage_generation".into(),
            expected: r.storage.generation.to_string(),
        },
    ])
}
pub fn validate_requirement_shape(q: &crate::admission::EvidenceRequirement) -> Result<()> {
    if q.obligation.stage != "jit"
        || !q.obligation.execution_relevant
        || q.question.schema != "urn:kedgeflow:current-sql-reservation:question:2.0"
        || q.result_schema_ref != schema_reference()?
        || q.result_schema != result_schema()
        || q.provider_version != "2.0"
        || q.predicates.len() != 5
        || q.max_age_ms <= 0
        || q.max_age_ms > 5000
        || !matches!(&q.predicates[0],crate::admission::EvidencePredicate::BooleanEquals{field,expected:true} if field=="current")
    {
        return Err(refuse());
    }
    Ok(())
}
pub fn validate_requirement(r: &Registration, t: &crate::admission::AdmissionTrust) -> Result<()> {
    let q = t.evidence.get(OBLIGATION).ok_or_else(refuse)?;
    validate_requirement_shape(q)?;
    if t.tenant != r.tenant
        || q.provider_id != r.provider.id
        || q.keys != crate::control_config::keys(&r.provider.keys)?
        || q.question != question(r)?
        || q.max_age_ms > r.maximum_age_ms as i64
        || json!(q.predicates) != json!(predicates(r)?)
    {
        return Err(refuse());
    }
    Ok(())
}

pub(crate) fn validate_sql(
    r: &Registration,
    sql_grant: &crate::contracts::Grant,
    sql_digest: &str,
    attempt: &str,
    observation: &crate::postgres_compensation::BarrierObservation,
) -> Result<()> {
    let f = &observation.forward_outcome;
    let q = &f.request;
    let parameters = crate::postgres_action::Parameters {
        resource_id: q.resource.id.clone(),
        expected_version: q.expected_version,
        reservation: q.reservation.clone(),
    };
    if observation.contract_digest != r.compensation_contract_digest
        || observation.resource != r.resource
        || observation.observed_version != q.expected_version.checked_add(1).ok_or_else(refuse)?
        || q.resource != r.resource
        || q.tenant != r.tenant
        || q.root_id != sql_grant.root_id
        || sql_grant.action.id != crate::postgres_action::ACTION
        || sql_grant.resources != [r.resource.clone()]
        || q.conflict_domain != sql_grant.conflict_domain
        || !valid_reference(&observation.restore_state_digest)
        || q.grant_digest != sql_digest
        || q.attempt_id != attempt
        || q.fence != sql_grant.fence
        || sql_grant.parameters_digest != digest("parameters", &json!(parameters))?
        || f.status != crate::postgres_action::Status::Committed
        || f.post_version != Some(observation.observed_version)
        || q.expires_at > sql_grant.expires_at as u64
    {
        return Err(refuse());
    }
    crate::postgres_action::Outcome::verify(&serde_json::to_vec(f)?, q)?;
    Ok(())
}
