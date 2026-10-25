//! Separate bounded admission source protocol. A physical grant/origin does not
//! exist yet; admission observations never fabricate a dispatched operation.
use crate::{
    contracts::{Envelope, Grant, Subject, digest, record_digest},
    current_reservation::{PROFILE, Signed, StorageHead},
    error::{Error, Result},
    managed_drain_store::Context,
    postgres_compensation::BarrierObservation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
pub const MAX_OBSERVATIONS: usize = 4;
fn refuse() -> Error {
    Error::Refused("exact managed proposal/current SQL preflight refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub profile: String,
    pub enrollment_digest: String,
    pub signed_proposal: String,
    pub requested_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub signed_grant: String,
    pub grant_digest: String,
    pub attempt_id: String,
}
impl Context {
    pub fn forward_grant(&self, f: &Forward) -> Result<Grant> {
        let r = &self.selection.registration;
        let e = &self.enrollment;
        let n = r
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&e.current_sql.forward_child_id)?;
        let verified = n
            .forward()?
            .lineage
            .grants
            .verify_retained(f.signed_grant.as_bytes())?;
        r.child(&n.child_id)?.reservation.grant(&verified.grant)?;
        if f.grant_digest != verified.digest
            || f.attempt_id.is_empty()
            || f.attempt_id.len() > 256
            || verified.grant.resources != [e.current_sql.resource.clone()]
            || verified.grant.action.id != crate::postgres_action::ACTION
        {
            return Err(refuse());
        }
        Ok(verified.grant)
    }
    pub fn admission_proposal(&self, q: &Request, at: i64) -> Result<(Envelope, String)> {
        let e = &self.enrollment;
        let c = &self.physical.contract;
        let n = self
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&self.selection.child_id)?;
        let native = n.forward()?;
        let t = &native.lineage;
        if q.profile != PROFILE
            || q.enrollment_digest != e.digest()?
            || q.signed_proposal.len() > 1 << 20
            || q.requested_at < 0
            || q.requested_at > at.saturating_add(e.clock_uncertainty_ms as i64)
            || at.saturating_sub(q.requested_at) > e.current_sql.maximum_age_ms as i64
        {
            return Err(refuse());
        }
        let signed = crate::schema::verify_record(
            q.signed_proposal.as_bytes(),
            "proposal",
            &t.admission.proposal_keys,
        )?;
        let p = &signed.payload;
        let subject: Subject = serde_json::from_value(p["subject"].clone())?;
        let created = p["created_at"].as_i64().ok_or_else(refuse)?;
        let expected_version = c.generation.to_string();
        if p["tenant"] != self.selection.registration.tenant
            || !t.subjects.contains(&subject)
            || p["workload_id"] != t.admission.proposal_workload_id
            || p["action"]["id"] != crate::managed_drain::ACTION
            || p["action"]["version"] != crate::managed_drain::VERSION
            || p["action"]["digest"] != t.admission.descriptor_digest
            || p["resources"] != json!([c.resource()?])
            || p["parameters"] != json!({"node":c.node.name,"expected_version":c.generation})
            || p["baseline_state"].as_array().is_none_or(|b| b.len() != 1)
            || p["baseline_state"][0]["state_digest"] != c.digest()?
            || p["baseline_state"][0]["resource"] != json!(c.resource()?)
            || p["baseline_state"][0]["version"].as_str() != Some(expected_version.as_str())
            || p["baseline_state"][0]["observed_at"]
                .as_i64()
                .is_none_or(|v| v < 0 || v > at)
            || p["baseline_state"][0]["expires_at"]
                .as_i64()
                .is_none_or(|v| v <= at)
            || p["requested_completion"] != "dispatch_bound"
            || p["delegation"]["token_audience"] != t.delegation_audience
            || p["delegation"]["authorization_server"] != subject.iss
            || p["delegation"]["scopes"]
                .as_array()
                .is_none_or(|s| !s.contains(&json!(t.admission.required_scope)))
            || p["delegation"]["expires_at"]
                .as_i64()
                .is_none_or(|v| v <= at)
            || created > at
            || at.saturating_sub(created) >= t.admission.max_proposal_age_ms
            || at < self.selection.registration.valid_from
            || at >= self.selection.registration.expires_at
        {
            return Err(refuse());
        }
        let operation = digest(
            "issuance-key",
            &json!({"tenant":p["tenant"],"subject":p["subject"],"workload_id":p["workload_id"],"qid":p["qid"]}),
        )?;
        if operation != e.operation_key {
            return Err(refuse());
        }
        let pd = record_digest(&signed)?;
        Ok((signed, pd))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub profile: String,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub enrollment_digest: String,
    pub registration_digest: String,
    pub proposal_digest: String,
    pub forward: Forward,
    pub requested_at: i64,
    pub claimed_at: i64,
    pub expires_at: i64,
    pub family_head: String,
    pub phase_head: String,
}
impl Claim {
    pub fn digest(&self) -> Result<String> {
        digest("current-sql-admission-claim", &json!(self))
    }
    pub fn validate(&self, c: &Context) -> Result<Grant> {
        let e = &c.enrollment;
        if self.profile != PROFILE
            || !(1..=MAX_OBSERVATIONS as u64).contains(&self.sequence)
            || self.enrollment_digest != e.digest()?
            || self.registration_digest != c.selection.registration.digest()?
            || !crate::grant_reference::valid_reference(&self.proposal_digest)
            || self
                .previous_digest
                .as_ref()
                .is_some_and(|s| !crate::grant_reference::valid_reference(s))
            || (self.sequence == 1) != self.previous_digest.is_none()
            || self.requested_at < 0
            || self.requested_at
                > self
                    .claimed_at
                    .saturating_add(e.clock_uncertainty_ms as i64)
            || self.claimed_at.saturating_sub(self.requested_at)
                > e.current_sql.maximum_age_ms as i64
            || self.claimed_at < c.selection.registration.valid_from
            || self.expires_at > c.selection.registration.expires_at
            || self.expires_at <= self.claimed_at
            || self.expires_at - self.claimed_at > e.current_sql.maximum_age_ms as i64
            || !crate::grant_reference::valid_reference(&self.family_head)
            || !crate::grant_reference::valid_reference(&self.phase_head)
        {
            return Err(refuse());
        }
        c.forward_grant(&self.forward)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub claim: Claim,
    pub storage_head: Signed<StorageHead>,
    pub sql: BarrierObservation,
    pub from: i64,
    pub until: i64,
    pub expires_at: i64,
}
pub type Statement = Signed<Observation>;
impl Statement {
    pub fn validate_admission(&self, c: &Context, at: i64) -> Result<()> {
        let e = &c.enrollment;
        let r = &e.current_sql;
        self.verify("admission_reservation_observation", &r.provider)?;
        let b = &self.body;
        let g = b.claim.validate(c)?;
        b.storage_head.validate_head(r, b.until)?;
        b.storage_head.validate_head(r, at)?;
        if b.from < b.claim.claimed_at
            || b.until < b.from
            || b.until > at
            || b.expires_at <= at
            || b.expires_at > b.claim.expires_at
            || b.expires_at - b.from > r.maximum_age_ms as i64
            || b.until - b.from > r.request_timeout_ms as i64
        {
            return Err(refuse());
        }
        crate::current_reservation::validate_sql(
            r,
            &g,
            &b.claim.forward.grant_digest,
            &b.claim.forward.attempt_id,
            &b.sql,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub profile: String,
    pub statement: Statement,
    pub evidence: Envelope,
}

/// Exact frozen-envelope payload shared by the producer, native anchor and offline audit.
pub fn evidence_payload(
    c: &Context,
    proposal: &Envelope,
    statement: &Statement,
) -> Result<serde_json::Value> {
    let e = &c.enrollment;
    let r = &e.current_sql;
    let b = &statement.body;
    let c = &c.physical.contract;
    if record_digest(proposal)? != b.claim.proposal_digest {
        return Err(refuse());
    }
    let digest = statement.digest()?;
    let domains: std::collections::BTreeSet<_> = [r.resource.id.clone(), c.resource()?.id]
        .into_iter()
        .collect();
    // The standard evidence state fields bind the exact physical proposal's
    // contract baseline. Current SQL facts and their independently retained
    // statement are explicit result fields; this signer makes no Kube inventory claim.
    Ok(
        serde_json::json!({"wid":format!("current-sql:{digest}"),"provider_id":r.provider.id,"provider_version":"2.0","question_ref":crate::current_reservation::question(r)?,"proposal_digest":b.claim.proposal_digest,"state_scope":[c.resource()?],"state_digest":c.digest()?,"result_schema":crate::current_reservation::schema_reference()?,"result":{"current":true,"registration_digest":r.digest()?,"forward_reservation_root_id":r.forward_reservation_root_id,"forward_execution_root_id":b.sql.forward_outcome.request.root_id,"incarnation":r.resource.incarnation,"storage_generation":r.storage.generation.to_string(),"forward_grant_digest":b.claim.forward.grant_digest,"forward_attempt_id":b.claim.forward.attempt_id,"fence":b.sql.forward_outcome.request.fence,"post_version":b.sql.observed_version,"observation_digest":digest},"observed_at":b.until,"expires_at":b.expires_at,"provenance_refs":[],"exposure_domains":domains.into_iter().collect::<Vec<_>>()}),
    )
}
impl Evidence {
    pub fn validate(&self, c: &Context, proposal: &Envelope, at: i64) -> Result<()> {
        self.statement.validate_admission(c, at)?;
        let raw = crate::contracts::canonical(&json!(self.evidence))?;
        crate::schema::verify_record(
            &raw,
            "evidence",
            &crate::control_config::keys(&c.enrollment.current_sql.provider.keys)?,
        )?;
        if self.profile != PROFILE
            || self.evidence.payload != evidence_payload(c, proposal, &self.statement)?
        {
            return Err(refuse());
        }
        Ok(())
    }
}
