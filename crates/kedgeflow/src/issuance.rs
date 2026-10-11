//! Certificate-constrained issuance prerequisite, not a public admission service.
//!
//! AdmissionContext is supplied only by a trusted authority caller. Prefer
//! validate_inputs for the independently verified raw-record chain. Policy
//! evaluation/certificate production live in policy.rs. Authenticated live
//! services remain the next increment.
//! A cryptographically valid certificate cannot broaden the pinned context.

use crate::contracts::{
    Action, GrantVerifier, Policy, Resource, Subject, canonical, digest, record_digest,
};
use crate::error::{Error, Result};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize)]
pub struct RequiredObligation {
    pub predicate_digest: String,
    pub stage: String,
    pub execution_relevant: bool,
}

/// Authority-side inputs, never deserialized from an agent request. The caller
/// must establish these from verified proposal, identity and installed control.
#[derive(Clone, Debug, Serialize)]
pub struct AdmissionContext {
    pub tenant: String,
    pub qid: String,
    pub subject: Subject,
    pub workload_id: String,
    pub dpop_jkt: String,
    pub proposal_digest: String,
    pub delegation_digest: String,
    pub descriptor_digest: String,
    pub obligation_manifest_digest: String,
    pub evidence_manifest_digest: String,
    pub policy: Policy,
    pub ownership_epoch: u64,
    pub audience: String,
    pub conflict_domain: String,
    pub obligations: BTreeMap<String, RequiredObligation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRef {
    id: String,
    schema: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Discharge {
    obligation_id: String,
    predicate_digest: String,
    witness_refs: Vec<RecordRef>,
    result: String,
    stage: String,
    execution_relevant: bool,
    observed_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Constraints {
    action: Action,
    resources: Vec<Resource>,
    parameters_digest: String,
    predicate_descriptor: Value,
    adapter_contract: Value,
    audience: String,
    max_attempts: u64,
    expires_at: i64,
    saga_budget: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    cid: String,
    proposal_digest: String,
    delegation_digest: String,
    subject: Subject,
    workload_id: String,
    policy: Policy,
    ownership_epoch: u64,
    descriptor_digest: String,
    obligation_manifest_digest: String,
    evidence_manifest_digest: String,
    discharges: Vec<Discharge>,
    constraints: Constraints,
    constraint_digest: String,
    lease_digest: Value,
    admitted_at: i64,
    expires_at: i64,
}

/// An opaque candidate: only certificate validation can construct this value.
/// Candidate allocation/signing belongs to the trusted issuer, not its caller.
#[derive(Clone, Debug)]
pub struct AdmittedIssuance {
    pub(crate) key: String,
    pub(crate) binding: String,
    pub(crate) grant: crate::contracts::Grant,
    pub(crate) grant_digest: String,
    pub(crate) signed_grant: String,
}

pub struct IssuanceVerifier {
    /// The tenant to which this verifier and its authority keys are assigned.
    pub tenant: String,
    /// Pinned tenant-scoped Admission Controller keys, independent from issuer keys.
    pub admission_keys: BTreeMap<String, VerifyingKey>,
    pub grants: GrantVerifier,
}

fn refuse(message: &str) -> Error {
    Error::Refused(message.into())
}

fn valid_digest(value: &str) -> bool {
    crate::grant_reference::valid_reference(value)
}

impl IssuanceVerifier {
    /// Stronger issuer entry point: bind the certificate to independently
    /// verified proposal/descriptor/manifest/evidence inputs before persistence.
    pub fn validate_inputs(
        &self,
        inputs: &crate::admission::VerifiedAdmissionInputs,
        signed_certificate: &[u8],
        signed_grant: &[u8],
        clock: &dyn crate::clock::Clock,
    ) -> Result<AdmittedIssuance> {
        let now = clock.now_ms();
        if now < inputs.valid_from || now >= inputs.valid_until {
            return Err(refuse("verified admission inputs expired"));
        }
        let admitted = self.validate(&inputs.context, signed_certificate, signed_grant, now)?;
        let envelope = crate::contracts::verify_envelope(signed_certificate, &self.admission_keys)?;
        let certificate: Certificate = serde_json::from_value(envelope.payload)?;
        let scope = &certificate.constraints;
        if scope.action != inputs.action
            || scope.resources != inputs.resources
            || scope.parameters_digest != inputs.parameters_digest
            || scope.predicate_descriptor != inputs.predicate_descriptor
            || scope.adapter_contract != inputs.adapter_contract
            || scope.expires_at > inputs.valid_until
        {
            return Err(refuse("certificate changes verified proposal constraints"));
        }
        for discharge in &certificate.discharges {
            let witness = inputs
                .witnesses
                .get(&discharge.obligation_id)
                .ok_or_else(|| refuse("discharge lacks verified witness"))?;
            if discharge.witness_refs.len() != 1
                || discharge.witness_refs[0].id != witness.reference.id
                || discharge.witness_refs[0].schema != witness.reference.schema
                || discharge.witness_refs[0].digest != witness.reference.digest
                || discharge.observed_at != witness.observed_at
                || discharge.expires_at != witness.expires_at
            {
                return Err(refuse("discharge differs from verified witness"));
            }
        }
        Ok(admitted)
    }

    pub fn validate(
        &self,
        context: &AdmissionContext,
        signed_certificate: &[u8],
        signed_grant: &[u8],
        now_ms: i64,
    ) -> Result<AdmittedIssuance> {
        if self.admission_keys.is_empty()
            || self
                .admission_keys
                .values()
                .any(|admission| self.grants.keys.values().any(|issuer| admission == issuer))
        {
            return Err(refuse("admission and issuer key roles must be distinct"));
        }
        if context.tenant.is_empty()
            || context.tenant != self.tenant
            || context.qid.is_empty()
            || context.subject.iss.is_empty()
            || context.subject.sub.is_empty()
            || context.workload_id.is_empty()
            || context.dpop_jkt.is_empty()
            || context.conflict_domain.is_empty()
            || context.audience != self.grants.audience
        {
            return Err(refuse("invalid trusted admission context"));
        }
        let envelope =
            crate::schema::verify_record(signed_certificate, "certificate", &self.admission_keys)?;
        if envelope.kind != "certificate" {
            return Err(refuse("not an admission certificate"));
        }
        // No Option fields: even nullable fields must be present on the wire.
        let cert: Certificate = serde_json::from_value(envelope.payload.clone())?;
        if cert.cid.is_empty()
            || !cert.lease_digest.is_null()
            || cert.proposal_digest != context.proposal_digest
            || cert.delegation_digest != context.delegation_digest
            || cert.subject != context.subject
            || cert.workload_id != context.workload_id
            || cert.policy != context.policy
            || cert.ownership_epoch != context.ownership_epoch
            || cert.descriptor_digest != context.descriptor_digest
            || cert.obligation_manifest_digest != context.obligation_manifest_digest
            || cert.evidence_manifest_digest != context.evidence_manifest_digest
        {
            return Err(refuse(
                "certificate does not bind trusted admission context",
            ));
        }
        for value in [
            &cert.proposal_digest,
            &cert.delegation_digest,
            &cert.descriptor_digest,
            &cert.obligation_manifest_digest,
            &cert.evidence_manifest_digest,
            &cert.policy.digest,
            &cert.constraint_digest,
        ] {
            if !valid_digest(value) {
                return Err(refuse("invalid certificate digest"));
            }
        }
        let scope = &cert.constraints;
        if cert.admitted_at < 0
            || cert.admitted_at > now_ms
            || cert.expires_at <= now_ms
            || cert.expires_at > scope.expires_at
            || cert.policy.epoch == 0
            || cert.ownership_epoch == 0
            || scope.max_attempts != 1
            || !scope.saga_budget.is_null()
            || scope.action.digest != cert.descriptor_digest
            || scope.audience != context.audience
            || digest("constraints", &serde_json::to_value(scope)?)? != cert.constraint_digest
        {
            return Err(refuse("invalid or stale certificate constraints"));
        }
        let mut seen = BTreeSet::new();
        for discharge in &cert.discharges {
            let expected = context
                .obligations
                .get(&discharge.obligation_id)
                .ok_or_else(|| refuse("unexpected obligation discharge"))?;
            if !seen.insert(&discharge.obligation_id)
                || !valid_digest(&discharge.predicate_digest)
                || discharge.predicate_digest != expected.predicate_digest
                || discharge.stage != expected.stage
                || !matches!(discharge.stage.as_str(), "static" | "jit")
                || discharge.execution_relevant != expected.execution_relevant
                || discharge.result != "satisfied"
                || discharge.observed_at < 0
                || discharge.observed_at > cert.admitted_at
                || discharge.expires_at < cert.expires_at
                || discharge.witness_refs.is_empty()
            {
                return Err(refuse("incomplete or stale obligation discharge"));
            }
            let mut witnesses = BTreeSet::new();
            for witness in &discharge.witness_refs {
                if witness.id.is_empty()
                    || url::Url::parse(&witness.schema).is_err()
                    || !valid_digest(&witness.digest)
                    || !witnesses.insert(&witness.id)
                {
                    return Err(refuse("invalid witness reference"));
                }
            }
        }
        if seen.len() != context.obligations.len() {
            return Err(refuse("missing required obligation discharge"));
        }
        crate::schema::verify_record(signed_grant, "grant", &self.grants.keys)?;
        let verified = self.grants.verify(signed_grant, now_ms)?;
        let grant = &verified.grant;
        let certificate_digest = record_digest(&envelope)?;
        if grant.certificate_digest != certificate_digest
            || grant.proposal_digest != cert.proposal_digest
            || grant.delegation_digest != cert.delegation_digest
            || grant.subject != cert.subject
            || grant.workload_id != cert.workload_id
            || grant.dpop_jkt != context.dpop_jkt
            || grant.policy != cert.policy
            || grant.ownership_epoch != cert.ownership_epoch
            || grant.evidence_manifest_digest != cert.evidence_manifest_digest
            || grant.constraint_digest != cert.constraint_digest
            || grant.action != scope.action
            || grant.resources != scope.resources
            || grant.parameters_digest != scope.parameters_digest
            || grant.predicate_descriptor != scope.predicate_descriptor
            || grant.adapter_contract != scope.adapter_contract
            || grant.audience != scope.audience
            || grant.conflict_domain != context.conflict_domain
            || grant.root_generation != 1
            || grant.issued_at < cert.admitted_at
            || grant.expires_at > cert.expires_at
        {
            return Err(refuse("grant broadens or changes admitted constraints"));
        }
        let key = digest(
            "issuance-key",
            &json!({"tenant": context.tenant, "subject": context.subject,
                "workload_id": context.workload_id, "qid": context.qid}),
        )?;
        let binding = digest(
            "issuance-binding",
            &json!({"context": context, "certificate_digest": certificate_digest}),
        )?;
        // Canonicalize the authenticated envelope, never a caller's unsigned copy.
        let raw = canonical(&crate::contracts::strict_value(&verified.raw)?)?;
        let signed_grant = String::from_utf8(raw)
            .map_err(|_| Error::Invalid("invalid signed grant UTF-8".into()))?;
        Ok(AdmittedIssuance {
            key,
            binding,
            grant: verified.grant,
            grant_digest: verified.digest,
            signed_grant,
        })
    }
}
