//! Closed public historical registration; no service secrets or network clients.
use crate::{
    admission::{AdmissionTrust, EvidenceRequirement},
    contracts::{GrantVerifier, Policy, Subject, strict_value},
    control_config::{EvidenceRegistration, PolicyRegistration, keys},
    error::{Error, Result},
    lineage::LineageTrust,
    policy::CedarPolicyDefinition,
    schema::ClosedObjectSchema,
};
use serde::Deserialize;
use std::collections::BTreeMap;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageTrustConfig {
    pub tenant: String,
    pub workload_id: String,
    pub subjects: Vec<Subject>,
    pub delegation_audience: String,
    pub gateway_audience: String,
    pub action_scope: String,
    pub proposal_keys: BTreeMap<String, String>,
    pub registry_keys: BTreeMap<String, String>,
    pub manifest_keys: BTreeMap<String, String>,
    pub admission_keys: BTreeMap<String, String>,
    pub grant_keys: BTreeMap<String, String>,
    pub outcome_keys: BTreeMap<String, String>,
    pub source_id: String,
    pub descriptor_digest: String,
    pub ownership_epoch: u64,
    pub max_proposal_age_ms: i64,
    pub policy: PolicyRegistration,
    pub evidence: BTreeMap<String, EvidenceRegistration>,
}
impl LineageTrustConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("historical trust exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub fn registration(&self) -> Result<LineageTrust> {
        if self.tenant.is_empty()
            || self.workload_id.is_empty()
            || self.action_scope.is_empty()
            || self.ownership_epoch == 0
            || self.evidence.len() > 64
            || !crate::grant_reference::valid_reference(&self.descriptor_digest)
        {
            return Err(Error::Invalid("incomplete historical registration".into()));
        }
        let evidence = self
            .evidence
            .iter()
            .map(|(id, r)| {
                ClosedObjectSchema::new(&r.result_schema)?;
                if r.provider_id.is_empty()
                    || r.provider_version.is_empty()
                    || !matches!(r.obligation.stage.as_str(), "static" | "jit")
                {
                    return Err(Error::Invalid(
                        "invalid historical evidence registration".into(),
                    ));
                }
                Ok((
                    id.clone(),
                    EvidenceRequirement {
                        review: r.review.clone(),
                        obligation: r.obligation.clone(),
                        provider_id: r.provider_id.clone(),
                        provider_version: r.provider_version.clone(),
                        keys: keys(&r.keys)?,
                        question: r.question.clone(),
                        result_schema_ref: r.result_schema_ref.clone(),
                        result_schema: r.result_schema.clone(),
                        max_age_ms: r.max_age_ms,
                        predicates: r.predicates.clone(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut admission = AdmissionTrust {
            tenant: self.tenant.clone(),
            proposal_keys: keys(&self.proposal_keys)?,
            proposal_workload_id: self.workload_id.clone(),
            registry_keys: keys(&self.registry_keys)?,
            manifest_keys: keys(&self.manifest_keys)?,
            descriptor_digest: self.descriptor_digest.clone(),
            ownership_epoch: self.ownership_epoch,
            policy: Policy {
                id: self.policy.id.clone(),
                epoch: self.policy.epoch,
                digest: String::new(),
            },
            obligation_manifest_digest: String::new(),
            required_scope: self.action_scope.clone(),
            max_proposal_age_ms: self.max_proposal_age_ms,
            evidence,
        };
        admission.obligation_manifest_digest = admission.registered_obligations_digest()?;
        let policy = CedarPolicyDefinition {
            tenant: self.tenant.clone(),
            policy_id: self.policy.id.clone(),
            cedar: self.policy.cedar.clone(),
            obligation_manifest_digest: admission.obligation_manifest_digest.clone(),
            max_certificate_lifetime_ms: self.policy.max_certificate_lifetime_ms,
        };
        admission.policy = policy.reference(self.policy.epoch)?;
        let trust = LineageTrust {
            admission,
            policy,
            subjects: self.subjects.clone(),
            delegation_audience: self.delegation_audience.clone(),
            admission_keys: keys(&self.admission_keys)?,
            grants: GrantVerifier {
                keys: keys(&self.grant_keys)?,
                audience: self.gateway_audience.clone(),
            },
            outcome_keys: keys(&self.outcome_keys)?,
            source_id: self.source_id.clone(),
        };
        trust.validate()?;
        Ok(trust)
    }
}
