//! Independently pinned SQL inverse target checks and real target barrier signing.
use crate::{
    action_domain::{Lane, Selection, Topology},
    compensation::{
        self, Applicability, Barrier, Contract, Forward, Proof, Qualification, Statement,
    },
    compensation_execution::{Binding, Payload},
    contracts::{Grant, GrantVerifier, digest, record_digest, strict_value},
    error::{Error, Result},
    hierarchical_leaf::Principal,
    postgres_action::{self},
    postgres_compensation::{self as sql, BarrierQuery, CompensationStore, DispatchRequest},
    postgres_target::Registration,
    reserved_lineage::{Bundle, Trust},
    target_token::{TargetTokenVerifier, TokenBinding},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
pub const PROFILE: &str = "KF-POSTGRES-COMPENSATION-HTTP-0.1-draft";
fn refused() -> Error {
    Error::Refused("SQL inverse authority or original effect refused".into())
}
pub struct Original {
    pub identity: Forward,
    pub grant: Grant,
    pub parameters: postgres_action::Parameters,
    pub committed_at: i64,
    pub deadline: i64,
}
pub fn original(c: &Contract, t: &Trust, b: &Bundle, at: i64) -> Result<Original> {
    c.validate(t)?;
    let v = crate::reserved_lineage::verify(b, t)?;
    if v.budget_state != crate::coordination::ReservationState::Committed
        || v.lineage.reported_status != "committed"
        || v.lineage.operation_key != c.forward_operation_key
        || v.held_compensation < c.compensation_units
    {
        return Err(refused());
    }
    let receipt = crate::schema::verify_record(
        b.lineage
            .outcomes
            .receipts
            .last()
            .ok_or_else(refused)?
            .as_bytes(),
        "receipt",
        &t.lineage.outcome_keys,
    )?;
    let committed_at = receipt.payload["event_time"].as_i64().ok_or_else(refused)?;
    let deadline = committed_at
        .checked_add(c.deadline_ms)
        .ok_or_else(refused)?
        .min(c.expires_at);
    let grant = t
        .lineage
        .grants
        .verify_retained(b.lineage.issuance.signed_grant.as_bytes())?
        .grant;
    let proposal = crate::schema::verify_record(
        b.lineage.packet.proposal.as_bytes(),
        "proposal",
        &t.lineage.admission.proposal_keys,
    )?;
    let parameters =
        postgres_action::Parameters::decode(&serde_json::to_vec(&proposal.payload["parameters"])?)?;
    let r = &t.registration;
    let baseline = proposal.payload["baseline_state"]
        .as_array()
        .and_then(|all| {
            all.iter()
                .find(|b| b["resource"] == json!(r.scope.resource))
        })
        .ok_or_else(refused)?;
    if r.scope.action.id != postgres_action::ACTION
        || grant.action.id != postgres_action::ACTION
        || grant.action.version != "1.0"
        || grant.parameters_digest != digest("parameters", &json!(parameters))?
        || parameters.resource_id != r.scope.resource.id
        || baseline["state_digest"] != c.restore_state_digest
        || baseline["version"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
            != Some(parameters.expected_version)
        || committed_at > at
        || b.checkpoint.payload.captured_at > at
        || at < c.valid_from
        || at >= deadline
    {
        return Err(refused());
    }
    Ok(Original {
        identity: Forward {
            registration_digest: r.digest()?,
            root_id: r.root_id.clone(),
            saga_id: r.saga.as_ref().ok_or_else(refused)?.saga_id.clone(),
            node_id: c.node_id.clone(),
            operation_key: c.forward_operation_key.clone(),
            grant_digest: v.lineage.grant_digest,
            attempt_id: v.lineage.attempt_id,
            receipt_digest: record_digest(&receipt)?,
            resource: r.scope.resource.clone(),
        },
        grant,
        parameters,
        committed_at,
        deadline,
    })
}
pub struct TargetTrust {
    pub contract: Contract,
    pub forward: Trust,
    pub topology: Topology,
    pub registration: Registration,
    pub forward_gateway_workload: String,
    pub outcome_keys: BTreeMap<String, VerifyingKey>,
    pub outcome_source: String,
}
impl TargetTrust {
    pub fn validate(&self, grants: &GrantVerifier) -> Result<()> {
        self.contract.validate(&self.forward)?;
        self.topology.validate()?;
        self.registration.validate()?;
        let inverse = Selection {
            topology: self.topology.clone(),
            lane: Lane::Inverse,
        };
        let forward = Selection {
            topology: self.topology.clone(),
            lane: Lane::Forward,
        };
        let keys = self
            .topology
            .inverse
            .issuer_keys
            .iter()
            .map(|(id, v)| {
                let b: [u8; 32] = hex::decode(v)
                    .map_err(|_| refused())?
                    .try_into()
                    .map_err(|_| refused())?;
                Ok((
                    id.clone(),
                    VerifyingKey::from_bytes(&b).map_err(|_| refused())?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let barrier_keys = crate::control_config::keys(&self.contract.barrier_keys)?;
        let app_keys = crate::control_config::keys(&self.contract.applicability_keys)?;
        if grants
            .keys
            .values()
            .chain(self.outcome_keys.values())
            .any(|k| {
                barrier_keys
                    .values()
                    .chain(app_keys.values())
                    .any(|b| b == k)
            })
            || self
                .outcome_keys
                .values()
                .any(|k| grants.keys.values().any(|g| g == k))
        {
            return Err(refused());
        }
        let pin = &self.registration;
        if self.forward.registration.scope.action.id != postgres_action::ACTION
            || !forward.accepts_reservation(&self.forward.registration)
            || grants.keys != keys
            || grants.audience != self.contract.inverse_scope.audience
            || inverse.registration().scope != self.contract.inverse_scope
            || inverse.registration().policy != self.contract.inverse_policy
            || pin.tenant != self.forward.registration.enrollment.tenant
            || pin.action != self.contract.inverse_scope.action
            || pin.resource != self.contract.inverse_scope.resource
            || pin.conflict_domain != self.contract.inverse_scope.conflict_domain
            || pin.adapter_contract != self.contract.inverse_scope.adapter_contract
            || pin.predicate_id != self.contract.inverse_scope.predicate_descriptor["id"]
            || pin.predicate_version != self.contract.inverse_scope.predicate_descriptor["version"]
            || !crate::auth::valid_spiffe_id(&self.forward_gateway_workload)
            || !(1..=16).contains(&self.outcome_keys.len())
            || self.outcome_source.is_empty()
            || crate::governance::trust_digest(
                &self.forward.lineage.admission,
                &self.forward.lineage.admission_keys,
                &self.forward.lineage.grants.keys,
            )? != self.topology.forward.trust_digest
        {
            return Err(refused());
        }
        Ok(())
    }
    pub fn bind(
        &self,
        grants: &GrantVerifier,
        tokens: &TargetTokenVerifier,
        request: &Dispatch,
        token: &str,
        now: i64,
    ) -> Result<DispatchRequest> {
        self.validate(grants)?;
        if request.profile != PROFILE || request.operation != "dispatch" {
            return Err(refused());
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&request.signed_grant)
            .map_err(|_| refused())?;
        if raw.len() > 1 << 20 || URL_SAFE_NO_PAD.encode(&raw) != request.signed_grant {
            return Err(refused());
        }
        let verified = grants.verify(&raw, now)?;
        let g = &verified.grant;
        let q = &request.qualification;
        let c = &self.contract;
        let historical =
            compensation::verify(c, &self.forward, &q.proof, q.verification.validated_at)?;
        if q.profile != compensation::PROFILE || q.verification != historical {
            return Err(refused());
        }
        let current = compensation::verify(c, &self.forward, &q.proof, now)?;
        let prior = original(c, &self.forward, &q.proof.forward, now)?;
        request.binding.verify(&grants.keys)?;
        let expected = Payload {
            outcome_trust_digest: digest(
                "compensation-outcome-trust",
                &json!({"source_id":self.outcome_source,"keys":self.outcome_keys.iter().map(|(id,k)|(id.clone(),hex::encode(k.as_bytes()))).collect::<BTreeMap<_,_>>()}),
            )?,
            topology_digest: self.topology.digest()?,
            contract_digest: c.digest()?,
            qualification_digest: q.digest()?,
            forward: current.forward.clone(),
            inverse_operation_key: c.inverse_operation_key.clone(),
            grant_digest: verified.digest.clone(),
            certificate_digest: g.certificate_digest.clone(),
            parameters_digest: g.parameters_digest.clone(),
            compensation_units: c.compensation_units,
            valid_from: g.valid_from,
            expires_at: g.expires_at,
        };
        if request.binding.payload != expected
            || g.parameters_digest != current.parameters_digest
            || g.expires_at > current.valid_until
            || g.policy != c.inverse_policy
            || Principal::from_grant(g) != c.inverse_principal
            || crate::governance::EnforcementScope::grant(g)? != c.inverse_scope
            || g.ownership_epoch != self.forward.registration.ownership_epoch
        {
            return Err(refused());
        }
        let pin = &self.registration;
        let credential = tokens.verify(
            token,
            &TokenBinding {
                grant_digest: verified.digest.clone(),
                root_id: g.root_id.clone(),
                attempt_id: request.attempt_id.clone(),
                gateway_workload: pin.gateway_workload.clone(),
                audience: pin.target_audience.clone(),
                scope: pin.target_scope.clone(),
                max_expires_at: g.expires_at,
            },
            now,
        )?;
        let p = &q.proof.parameters;
        let bound = DispatchRequest {
            profile: sql::PROFILE.into(),
            action: compensation::ACTION.into(),
            tenant: pin.tenant.clone(),
            conflict_domain: pin.conflict_domain.clone(),
            attempt_id: request.attempt_id.clone(),
            grant_digest: verified.digest,
            root_id: g.root_id.clone(),
            resource: pin.resource.clone(),
            expected_version: p.expected_version,
            fence: g.fence,
            gateway_workload: pin.gateway_workload.clone(),
            expires_at: (credential.exp * 1000) as u64,
            contract_digest: c.digest()?,
            forward_root_id: prior.grant.root_id,
            forward_grant_digest: p.forward_grant_digest.clone(),
            forward_attempt_id: p.forward_attempt_id.clone(),
            restore_state_digest: p.restore_state_digest.clone(),
        };
        sql::validate(&json!(bound))?;
        Ok(bound)
    }
    pub async fn barrier(
        &self,
        store: &dyn CompensationStore,
        b: &Bundle,
        now: i64,
        lifetime: i64,
        key_id: &str,
        key: &SigningKey,
    ) -> Result<Statement> {
        let c = &self.contract;
        let prior = original(c, &self.forward, b, now)?;
        let expected = crate::control_config::keys(&c.barrier_keys)?;
        if expected.get(key_id) != Some(&key.verifying_key()) || !(1..=60000).contains(&lifetime) {
            return Err(refused());
        }
        let q = BarrierQuery {
            tenant: self.forward.registration.enrollment.tenant.clone(),
            contract_digest: c.digest()?,
            forward_attempt_id: prior.identity.attempt_id.clone(),
            forward_grant_digest: prior.identity.grant_digest.clone(),
            forward_root_id: prior.grant.root_id.clone(),
        };
        let observed = store.barrier(&q).await?.ok_or_else(refused)?;
        let r = &observed.forward_outcome.request;
        if observed.resource != prior.identity.resource
            || observed.restore_state_digest != c.restore_state_digest
            || observed.observed_version
                != prior
                    .parameters
                    .expected_version
                    .checked_add(1)
                    .ok_or_else(refused)?
            || r.conflict_domain != self.forward.registration.scope.conflict_domain
            || r.fence != prior.grant.fence
            || r.expected_version != prior.parameters.expected_version
            || r.reservation != prior.parameters.reservation
            || r.gateway_workload != self.forward_gateway_workload
            || r.expires_at > prior.grant.expires_at as u64
        {
            return Err(refused());
        }
        let expires_at = now
            .checked_add(lifetime)
            .ok_or_else(refused)?
            .min(prior.deadline);
        let payload = Barrier {
            contract_digest: c.digest()?,
            forward: prior.identity,
            target_id: c.target_id.clone(),
            original_terminal: true,
            no_late_commit: true,
            observed_version: observed.observed_version,
            valid_from: now,
            expires_at,
        };
        sign("barrier", json!(payload), key_id, key)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dispatch {
    pub profile: String,
    pub operation: String,
    pub signed_grant: String,
    pub attempt_id: String,
    pub qualification: Qualification,
    pub binding: Binding,
}
impl Dispatch {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 768 << 10 {
            return Err(refused());
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
}
fn sign(kind: &str, payload: serde_json::Value, id: &str, key: &SigningKey) -> Result<Statement> {
    let mut s = Statement {
        profile: compensation::PROFILE.into(),
        kind: kind.into(),
        key_id: id.into(),
        payload,
        signature: String::new(),
    };
    s.signature = URL_SAFE_NO_PAD.encode(key.sign(&s.message()?).to_bytes());
    Ok(s)
}
/// Separate trusted evaluator role. The signed result is returned only after
/// the complete original proof, barrier and fixed restore semantics verify.
pub fn applicability(
    c: &Contract,
    t: &Trust,
    b: Bundle,
    barrier: Statement,
    now: i64,
    id: &str,
    key: &SigningKey,
) -> Result<Proof> {
    let prior = original(c, t, &b, now)?;
    if crate::control_config::keys(&c.applicability_keys)?.get(id) != Some(&key.verifying_key()) {
        return Err(refused());
    }
    let observed: Barrier = serde_json::from_value(barrier.payload.clone())?;
    let parameters = compensation::Parameters {
        resource_id: prior.identity.resource.id.clone(),
        expected_version: observed.observed_version,
        forward_grant_digest: prior.identity.grant_digest.clone(),
        forward_attempt_id: prior.identity.attempt_id.clone(),
        restore_state_digest: c.restore_state_digest.clone(),
    };
    let app = Applicability {
        contract_digest: c.digest()?,
        forward: prior.identity,
        barrier_digest: barrier.digest()?,
        evaluator_id: c.evaluator_id.clone(),
        inverse_operation_key: c.inverse_operation_key.clone(),
        inverse_principal: c.inverse_principal.clone(),
        parameters_digest: digest("parameters", &json!(parameters))?,
        restore_state_digest: c.restore_state_digest.clone(),
        applicable: true,
        valid_from: now,
        expires_at: observed.expires_at,
    };
    let p = Proof {
        profile: compensation::PROFILE.into(),
        forward: b,
        barrier,
        applicability: sign("applicability", json!(app), id, key)?,
        parameters,
    };
    compensation::verify(c, t, &p, now)?;
    Ok(p)
}
