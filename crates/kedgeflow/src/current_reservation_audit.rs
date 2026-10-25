//! Independent signed-source correlation replay. This does not attest native CAS
//! history, Kubernetes effects, current live freshness, or storage-owner custody.
use crate::{
    contracts::{Envelope, strict_value},
    current_reservation::{PROFILE, Query, Witness},
    error::{Error, Result},
    family::Selection,
    lineage::AuthorizationBundle,
    managed_drain_preflight::Evidence,
    managed_drain_store::{Context, Store},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const MAX_BYTES: usize = 8 << 20;
fn refuse() -> Error {
    Error::Refused("current SQL source audit refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub profile: String,
    pub selection: Selection,
}
impl Trust {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 2 << 20 {
            return Err(refuse());
        }
        let t: Self = serde_json::from_value(strict_value(raw)?)?;
        t.context()?;
        Ok(t)
    }
    fn context(&self) -> Result<Context> {
        if self.profile != PROFILE {
            return Err(refuse());
        }
        Context::from_selection(self.selection.clone())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub profile: String,
    pub authorization: AuthorizationBundle,
    pub admission: Evidence,
    pub query: Query,
    pub witness: Witness,
}
impl Bundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BYTES {
            return Err(refuse());
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    /// Retains actual source records and original authorization while their native
    /// source slot is still pending. No synthetic authorization or source claim.
    pub async fn collect(
        store: &Store,
        admission: Evidence,
        query: Query,
        witness: Witness,
        at: i64,
    ) -> Result<Self> {
        store
            .current_sql_claim(&query, &witness.body.source_claim, at)
            .await?;
        let authorization = store
            .ledger
            .export_authorization(&store.context.enrollment.operation_key)
            .await?;
        let (g, _) = store.context.validate_origin(&query.origin)?;
        store.admission_dispatch_proof(&g, &query.origin).await?;
        let b = Self {
            profile: PROFILE.into(),
            authorization,
            admission,
            query,
            witness,
        };
        b.verify(&Trust {
            profile: PROFILE.into(),
            selection: store.context.selection.clone(),
        })?;
        Ok(b)
    }
    pub fn verify(&self, trust: &Trust) -> Result<Value> {
        let c = trust.context()?;
        let e = &c.enrollment;
        let n = c
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&c.selection.child_id)?;
        crate::lineage::verify_authorization(&self.authorization, &n.forward()?.lineage)?;
        let (g, sql) = c.validate_origin(&self.query.origin)?;
        let proposal: Envelope =
            serde_json::from_value(strict_value(self.authorization.packet.proposal.as_bytes())?)?;
        let q = crate::managed_drain_preflight::Request {
            profile: PROFILE.into(),
            enrollment_digest: e.digest()?,
            signed_proposal: self.authorization.packet.proposal.clone(),
            requested_at: self.admission.statement.body.claim.requested_at,
        };
        c.admission_proposal(&q, g.issued_at)?;
        self.admission.validate(&c, &proposal, g.issued_at)?;
        let forward = &self.admission.statement.body.claim.forward;
        self.witness.validate_current(
            e,
            &self.query.origin,
            &self.query.reservation_digest,
            self.witness.body.until,
            &sql,
            &forward.grant_digest,
        )?;
        if self.profile != PROFILE
            || self.query.profile != PROFILE
            || self.query.enrollment_digest != e.digest()?
            || self.query.digest()? != self.witness.body.query_digest
            || self.authorization.issuance.signed_grant != self.query.origin.signed_grant
            || self.authorization.issuance.grant_digest != self.query.origin.original.grant_digest
            || forward.signed_grant != self.query.origin.forward_signed_grant
            || forward.attempt_id != self.query.origin.forward_attempt_id
            || !self.authorization.packet.witnesses.iter().any(|raw| {
                strict_value(raw.as_bytes()).ok() == Some(json!(self.admission.evidence))
            })
            || crate::contracts::canonical(&json!(self))?.len() > MAX_BYTES
        {
            return Err(refuse());
        }
        Ok(
            json!({"profile":PROFILE,"verified":"historical_signed_source_correlation",
            "enrollment_digest":e.digest()?,"admission_observation_digest":self.admission.statement.digest()?,
            "query_observation_digest":self.witness.digest()?,"query_digest":self.query.digest()?,
            "forward_reservation_root_id":e.current_sql.forward_reservation_root_id,
            "forward_execution_root_id":sql.root_id,"admission_at":g.issued_at,
            "query_observed_at":self.witness.body.until,"execution_authority":false,
            "native_history_verified":false,"managed_physical_qualification":false}),
        )
    }
}
