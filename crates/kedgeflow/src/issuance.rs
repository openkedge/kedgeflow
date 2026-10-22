//! Certificate-constrained verification and authority-owned grant production.
//!
//! AdmissionContext is supplied only by a trusted authority caller. Prefer
//! validate_inputs for the independently verified raw-record chain. Policy
//! evaluation/certificate production live in policy.rs. The bounded authenticated
//! service composes these checks in control.rs.
//! A cryptographically valid certificate cannot broaden the pinned context.

use crate::contracts::{
    Action, GrantVerifier, Policy, Resource, Subject, canonical, digest, record_digest,
};
use crate::error::{Error, Result};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub(crate) inverse_prepared:
        Option<std::sync::Arc<crate::compensation_execution::PreparedIssuance>>,
    pub(crate) lease_check: Option<crate::leases::LeaseCheck>,
    pub(crate) review_facts: Vec<crate::review::ReviewFact>,
    pub(crate) tenant: String,
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
        let mut admitted = self.validate_lease_context(
            &inputs.context,
            signed_certificate,
            signed_grant,
            now,
            inputs.lease_digest.as_deref(),
        )?;
        admitted.review_facts = inputs.review_facts.clone();
        admitted.lease_check = inputs.lease_check.clone();
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
        self.validate_lease_context(context, signed_certificate, signed_grant, now_ms, None)
    }

    fn validate_lease_context(
        &self,
        context: &AdmissionContext,
        signed_certificate: &[u8],
        signed_grant: &[u8],
        now_ms: i64,
        lease: Option<&str>,
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
            || cert.lease_digest != serde_json::json!(lease)
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
            inverse_prepared: None,
            lease_check: None,
            review_facts: Vec::new(),
            tenant: context.tenant.clone(),
            key,
            binding,
            grant: verified.grant,
            grant_digest: verified.digest,
            signed_grant,
        })
    }
}

/// Trusted producer: callers provide verified inputs and a retained certificate,
/// never candidate roots, grant IDs, nonces or fences.
pub struct GrantAuthority {
    verifier: IssuanceVerifier,
    key_id: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl GrantAuthority {
    pub(crate) fn verify_retained(&self, raw: &[u8]) -> Result<crate::contracts::VerifiedGrant> {
        self.verifier.grants.verify_retained(raw)
    }

    pub(crate) fn reservation_configured(
        &self,
        ledger: &crate::ledger::EtcdLedger,
        trust: &crate::admission::AdmissionTrust,
    ) -> bool {
        ledger.reservation_service(trust, &self.verifier.grants.keys)
            && ledger.family_distinct(
                self.verifier
                    .grants
                    .keys
                    .values()
                    .chain(self.verifier.admission_keys.values())
                    .chain(trust.proposal_keys.values())
                    .chain(trust.registry_keys.values())
                    .chain(trust.manifest_keys.values())
                    .chain(trust.evidence.values().flat_map(|e| e.keys.values())),
            )
            && ledger.inverse_input_roles(
                trust,
                &self.verifier.admission_keys,
                &self.verifier.grants.keys,
            )
            && ledger.inverse_execution.as_ref().map(|e| &e.contract)
                == trust.inverse_contract.as_ref()
            && ledger.action_domain.as_ref().is_none_or(|s| {
                let r = s.registration();
                r.tenant == trust.tenant
                    && r.policy == trust.policy
                    && r.ownership_epoch == trust.ownership_epoch
                    && r.scope.action.digest == trust.descriptor_digest
                    && r.obligation_manifest_digest == trust.obligation_manifest_digest
                    && r.issuer_keys
                        == self
                            .verifier
                            .grants
                            .keys
                            .iter()
                            .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                            .collect::<BTreeMap<_, _>>()
                    && crate::governance::trust_digest(
                        trust,
                        &self.verifier.admission_keys,
                        &self.verifier.grants.keys,
                    )
                    .is_ok_and(|d| d == r.trust_digest)
            })
            && ledger
                .reservation
                .as_ref()
                .and_then(|r| r.saga.as_ref())
                .is_none_or(|p| p.distinct(self.verifier.admission_keys.values()))
            && ledger
                .reservation
                .as_ref()
                .and_then(|r| r.hierarchy.as_ref())
                .is_none_or(|h| h.distinct(self.verifier.admission_keys.values()))
    }
    pub(crate) fn configured_for(
        &self,
        trust: &crate::admission::AdmissionTrust,
        controller: &crate::policy::AdmissionController,
    ) -> bool {
        let (id, key) = controller.signing_role();
        let issuer = self.signing_key.verifying_key();
        self.verifier.tenant == trust.tenant
            && self.verifier.admission_keys.get(id) == Some(&key)
            && trust
                .leases
                .as_ref()
                .is_none_or(|leases| leases.keys == self.verifier.admission_keys)
            && [
                &trust.proposal_keys,
                &trust.registry_keys,
                &trust.manifest_keys,
            ]
            .iter()
            .flat_map(|r| r.values())
            .chain(trust.evidence.values().flat_map(|r| r.keys.values()))
            .all(|k| k != &key && k != &issuer)
    }
    pub fn new(
        verifier: IssuanceVerifier,
        key_id: String,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self> {
        let public = signing_key.verifying_key();
        if verifier.tenant.is_empty()
            || verifier.grants.keys.get(&key_id) != Some(&public)
            || verifier.admission_keys.is_empty()
            || verifier.admission_keys.values().any(|k| k == &public)
        {
            return Err(refuse("invalid or overlapping issuer signing role"));
        }
        Ok(Self {
            verifier,
            key_id,
            signing_key,
        })
    }

    fn prepare(
        &self,
        inputs: &crate::admission::VerifiedAdmissionInputs,
        certificate: &[u8],
        clock: &dyn crate::clock::Clock,
    ) -> Result<AdmittedIssuance> {
        if inputs
            .record_keys
            .contains(&self.signing_key.verifying_key())
        {
            return Err(refuse("issuer signer overlaps an input record role"));
        }
        let env = crate::schema::verify_record(
            certificate,
            "certificate",
            &self.verifier.admission_keys,
        )?;
        let cert: Certificate = serde_json::from_value(env.payload.clone())?;
        let c = &inputs.context;
        let now = clock.now_ms();
        let g = crate::contracts::Grant {
            gid: random_id("kf-grant")?,
            root_id: random_id("kf-root")?,
            nonce: random_id("kf-nonce")?,
            root_generation: 1,
            parent_grant_digest: None,
            saga_budget: Value::Null,
            fence: 1,
            proposal_digest: c.proposal_digest.clone(),
            certificate_digest: record_digest(&env)?,
            delegation_digest: c.delegation_digest.clone(),
            subject: c.subject.clone(),
            workload_id: c.workload_id.clone(),
            dpop_jkt: c.dpop_jkt.clone(),
            action: inputs.action.clone(),
            resources: inputs.resources.clone(),
            parameters_digest: inputs.parameters_digest.clone(),
            policy: c.policy.clone(),
            evidence_manifest_digest: c.evidence_manifest_digest.clone(),
            constraint_digest: cert.constraint_digest,
            ownership_epoch: c.ownership_epoch,
            predicate_descriptor: inputs.predicate_descriptor.clone(),
            adapter_contract: inputs.adapter_contract.clone(),
            conflict_domain: c.conflict_domain.clone(),
            audience: c.audience.clone(),
            issued_at: now,
            valid_from: now,
            expires_at: cert.expires_at,
            completion_mode: "dispatch_bound".into(),
        };
        let raw = crate::contracts::sign_grant(&g, &self.key_id, &self.signing_key)?;
        // All existing full-schema, certificate/discharge and executable-profile
        // checks run before fence allocation or issuance mutation.
        self.verifier
            .validate_inputs(inputs, certificate, &raw, clock)
    }

    pub async fn issue(
        &self,
        ledger: &crate::ledger::EtcdLedger,
        inputs: &crate::admission::VerifiedAdmissionInputs,
        certificate: &[u8],
        clock: &dyn crate::clock::Clock,
    ) -> Result<crate::ledger::IssuanceResult> {
        if !ledger.inverse_record_roles(
            inputs
                .record_keys
                .iter()
                .chain(self.verifier.admission_keys.values())
                .chain(self.verifier.grants.keys.values()),
        ) {
            return Err(refuse(
                "inverse signer overlaps target/applicability/outcome role",
            ));
        }
        if ledger
            .reservation
            .as_ref()
            .and_then(|r| r.hierarchy.as_ref())
            .is_some_and(|h| {
                !h.distinct(
                    inputs
                        .record_keys
                        .iter()
                        .chain(self.verifier.admission_keys.values()),
                )
            })
        {
            return Err(refuse(
                "composite delegation signer overlaps admission/input role",
            ));
        }
        if ledger
            .reservation
            .as_ref()
            .and_then(|r| r.saga.as_ref())
            .is_some_and(|p| {
                !p.distinct(
                    inputs
                        .record_keys
                        .iter()
                        .chain(self.verifier.admission_keys.values()),
                )
            })
        {
            return Err(refuse("saga outcome signer overlaps admission/input role"));
        }
        let mut candidate = self.prepare(inputs, certificate, clock)?;
        candidate.inverse_prepared = ledger.prepare_inverse_issuance().await?;
        if let Some(record) = ledger.lookup_issuance(&candidate).await? {
            self.validate_returned(inputs, certificate, &record, clock)?;
            return Ok(crate::ledger::IssuanceResult {
                record,
                reused: true,
            });
        }
        let reservation = ledger.reserve_fence(&candidate, clock).await?;
        let mut g = candidate.grant;
        g.fence = reservation.fence();
        let raw = crate::contracts::sign_grant(&g, &self.key_id, &self.signing_key)?;
        let mut admitted = self
            .verifier
            .validate_inputs(inputs, certificate, &raw, clock)?;
        admitted.inverse_prepared = candidate.inverse_prepared;
        let binding = ledger.sign_reservation(&admitted, &self.key_id, &self.signing_key)?;
        let inverse = ledger
            .sign_inverse(&admitted, &self.key_id, &self.signing_key)
            .await?;
        let issued = ledger
            .issue_reserved(
                &admitted,
                &reservation,
                binding.as_ref(),
                inverse.as_ref(),
                clock,
            )
            .await?;
        self.validate_returned(inputs, certificate, &issued.record, clock)?;
        Ok(issued)
    }

    fn validate_returned(
        &self,
        inputs: &crate::admission::VerifiedAdmissionInputs,
        certificate: &[u8],
        record: &crate::ledger::IssuanceRecord,
        clock: &dyn crate::clock::Clock,
    ) -> Result<()> {
        let validated = self.verifier.validate_inputs(
            inputs,
            certificate,
            record.signed_grant.as_bytes(),
            clock,
        )?;
        if validated.key != record.issuance_key
            || validated.binding != record.binding_digest
            || validated.grant_digest != record.grant_digest
        {
            return Err(refuse("retained issuance correlation mismatch"));
        }
        Ok(())
    }
}

fn random_id(prefix: &str) -> Result<String> {
    use rand::RngCore;
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Unavailable("issuer ID randomness unavailable".into()))?;
    Ok(format!("{prefix}-{}", hex::encode(bytes)))
}
