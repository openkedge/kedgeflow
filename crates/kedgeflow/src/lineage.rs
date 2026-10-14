//! Historical signed authorization lineage. Verification returns evidence, never
//! a live admission/issuance capability. The caller independently approves trust.
use crate::{
    admission::{AdmissionPacket, AdmissionTrust, StoredAdmissionPacket},
    auth::Identity,
    clock::Clock,
    contracts::{Envelope, GrantVerifier, Subject, canonical, digest, record_digest, strict_value},
    error::{Error, Result},
    issuance::IssuanceVerifier,
    ledger::{AdmissionRecord, EtcdLedger, IssuanceRecord},
    policy::{CedarAdmissionPolicy, CedarPolicyDefinition},
    recovery::{Candidate, OutcomeBundle, verify_outcomes},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const LEASE_PROFILE: &str = "KF-ADMISSION-LINEAGE-0.2-draft";
pub const PROFILE: &str = "KF-ADMISSION-LINEAGE-0.1-draft";
const MAX_BUNDLE: usize = 16 << 20;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageBundle {
    pub profile: String,
    pub admission: AdmissionRecord,
    pub packet: StoredAdmissionPacket,
    pub issuance: IssuanceRecord,
    pub outcomes: OutcomeBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_authority: Option<Vec<crate::leases::AuthorityLeaseBinding>>,
}
impl LineageBundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BUNDLE {
            return Err(invalid("lineage bundle exceeds bound"));
        }
        let value = strict_value(raw)?;
        validate(&value)?;
        let bundle: Self = serde_json::from_value(value)?;
        bundle.bound_records()?;
        Ok(bundle)
    }
    fn bound_records(&self) -> Result<()> {
        // JSON Schema maxLength counts Unicode characters. The carriage budget
        // is bytes, including for records with multibyte application strings.
        let records = [
            &self.packet.proposal,
            &self.packet.descriptor,
            &self.packet.manifest,
            &self.admission.signed_certificate,
            &self.issuance.signed_grant,
            &self.outcomes.execution.signed_grant,
        ];
        if records
            .into_iter()
            .chain(&self.packet.witnesses)
            .chain(&self.outcomes.receipts)
            .chain(self.packet.lease.iter())
            .any(|raw| raw.is_empty() || raw.len() > 1 << 20)
        {
            return Err(invalid("signed lineage record exceeds byte bound"));
        }
        if let Some(bindings) = &self.lease_authority
            && (bindings.len() != 2
                || bindings
                    .iter()
                    .any(|b| serde_json::to_vec(b).map_or(true, |r| r.len() > 1 << 20)))
        {
            return Err(invalid("lease authority carriage exceeds bound"));
        }
        Ok(())
    }
}
fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}
fn validate(value: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    static LEASE_SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let (slot, raw) = match value["profile"].as_str() {
        Some(PROFILE) => (
            &SCHEMA,
            include_str!("../../../spec/drafts/admission-lineage-v0.1.schema.json"),
        ),
        Some(LEASE_PROFILE) => (
            &LEASE_SCHEMA,
            include_str!("../../../spec/drafts/admission-lineage-v0.2.schema.json"),
        ),
        _ => return Err(invalid("unknown lineage profile")),
    };
    let schema = slot.get_or_init(|| {
        crate::schema::compile(&serde_json::from_str(raw).expect("embedded lineage schema"))
            .expect("valid lineage schema")
    });
    if !schema.is_valid(value) {
        return Err(invalid("closed lineage supplement mismatch"));
    }
    Ok(())
}
/// Public historical pins, independently approved by the verifier's operator.
/// No trust field is inferred from the exported bundle.
pub struct LineageTrust {
    pub admission: AdmissionTrust,
    pub policy: CedarPolicyDefinition,
    pub subjects: Vec<Subject>,
    pub delegation_audience: String,
    pub admission_keys: BTreeMap<String, VerifyingKey>,
    pub grants: GrantVerifier,
    pub outcome_keys: BTreeMap<String, VerifyingKey>,
    pub source_id: String,
}
impl LineageTrust {
    pub fn validate(&self) -> Result<()> {
        self.admission.validate_configuration()?;
        CedarAdmissionPolicy::new(self.policy.clone(), self.admission.policy.clone())?;
        if self
            .admission
            .leases
            .as_ref()
            .is_some_and(|leases| leases.keys != self.admission_keys)
            || self.subjects.is_empty()
            || self.delegation_audience.is_empty()
            || self.source_id.is_empty()
            || self.grants.audience.is_empty()
            || self.admission_keys.is_empty()
            || self.grants.keys.is_empty()
            || self.outcome_keys.is_empty()
        {
            return Err(invalid("incomplete historical trust"));
        }
        let input: Vec<_> = self
            .admission
            .proposal_keys
            .values()
            .chain(self.admission.registry_keys.values())
            .chain(self.admission.manifest_keys.values())
            .chain(
                self.admission
                    .evidence
                    .values()
                    .flat_map(|r| r.keys.values()),
            )
            .collect();
        let roles = [&self.admission_keys, &self.grants.keys, &self.outcome_keys];
        for (i, role) in roles.iter().enumerate() {
            if role.values().any(|k| {
                input.contains(&k)
                    || roles[..i]
                        .iter()
                        .any(|r| r.values().any(|other| other == k))
            }) {
                return Err(invalid("historical signer roles overlap"));
            }
        }
        Ok(())
    }
}
struct HistoricalTime(i64);
impl Clock for HistoricalTime {
    fn now_ms(&self) -> i64 {
        self.0
    }
}
#[derive(Debug, Serialize)]
pub struct LineageVerification {
    pub profile: String,
    pub tenant: String,
    pub operation_key: String,
    pub proposal_digest: String,
    pub certificate_digest: String,
    pub grant_digest: String,
    pub admitted_at: i64,
    pub issued_at: i64,
    pub witnesses_verified: usize,
    pub receipts_verified: usize,
    pub attempt_id: String,
    pub reported_status: String,
    pub missing_links: Vec<String>,
}
/// Re-evaluate signed historical inputs and policy. Original runtime token/TLS/
/// PoP authentication and installation history remain explicit missing links.
pub fn verify_lineage(bundle: &LineageBundle, trust: &LineageTrust) -> Result<LineageVerification> {
    bundle.bound_records()?;
    let value = serde_json::to_value(bundle)?;
    if canonical(&value)?.len() > MAX_BUNDLE {
        return Err(invalid("lineage bundle exceeds bound"));
    }
    validate(&value)?;
    trust.validate()?;
    let cert = crate::schema::verify_record(
        bundle.admission.signed_certificate.as_bytes(),
        "certificate",
        &trust.admission_keys,
    )?;
    let grant = trust
        .grants
        .verify_retained(bundle.issuance.signed_grant.as_bytes())?;
    let admitted_at = cert.payload["admitted_at"]
        .as_i64()
        .ok_or_else(|| invalid("invalid signed admission time"))?;
    let expires_at = cert.payload["expires_at"]
        .as_i64()
        .ok_or_else(|| invalid("invalid signed certificate expiry"))?;
    let proposal = crate::schema::verify_record(
        bundle.packet.proposal.as_bytes(),
        "proposal",
        &trust.admission.proposal_keys,
    )?;
    let p = &proposal.payload;
    let subject: Subject = serde_json::from_value(p["subject"].clone())?;
    let d = &p["delegation"];
    if !trust.subjects.contains(&subject)
        || d["authorization_server"] != subject.iss
        || d["token_audience"] != trust.delegation_audience
    {
        return Err(invalid("unapproved declared subject/delegation"));
    }
    let scopes = d["scopes"]
        .as_array()
        .ok_or_else(|| invalid("missing signed delegation scopes"))?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("invalid signed scope"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let identity = Identity {
        subject,
        workload_id: p["workload_id"]
            .as_str()
            .ok_or_else(|| invalid("missing workload"))?
            .into(),
        dpop_jkt: d["dpop_jkt"]
            .as_str()
            .ok_or_else(|| invalid("missing PoP binding"))?
            .into(),
        delegation_digest: digest("delegation", d)?,
        access_token: String::new(),
        scopes,
    };
    let evidence: Vec<_> = bundle
        .packet
        .witnesses
        .iter()
        .map(|w| w.as_bytes().to_vec())
        .collect();
    let packet = || AdmissionPacket {
        lease: bundle.packet.lease.as_deref().map(str::as_bytes),
        proposal: bundle.packet.proposal.as_bytes(),
        descriptor: bundle.packet.descriptor.as_bytes(),
        manifest: bundle.packet.manifest.as_bytes(),
        evidence: &evidence,
    };
    let inputs =
        trust
            .admission
            .verify_inputs(&identity, packet(), &HistoricalTime(admitted_at))?;
    CedarAdmissionPolicy::new(trust.policy.clone(), trust.admission.policy.clone())?
        .permit(&inputs, admitted_at)?;
    let max_expiry = admitted_at
        .checked_add(trust.policy.max_certificate_lifetime_ms)
        .ok_or_else(|| invalid("certificate lifetime overflow"))?
        .min(inputs.valid_until);
    if expires_at <= admitted_at || expires_at > max_expiry {
        return Err(invalid("certificate exceeds approved lifetime"));
    }
    let key = trust
        .admission
        .operation_key(&identity, bundle.packet.proposal.as_bytes())?;
    if bundle.admission.admission_key != key
        || bundle.admission.binding_digest != inputs.admission_binding()?
        || bundle.admission.certificate_digest != record_digest(&cert)?
        || bundle.admission.admitted_at != admitted_at
        || bundle.admission.expires_at != expires_at
    {
        return Err(invalid("retained admission metadata mismatch"));
    }
    let issued_inputs = trust.admission.verify_inputs(
        &identity,
        packet(),
        &HistoricalTime(grant.grant.issued_at),
    )?;
    let issuance = IssuanceVerifier {
        tenant: trust.admission.tenant.clone(),
        admission_keys: trust.admission_keys.clone(),
        grants: trust.grants.clone(),
    }
    .validate_inputs(
        &issued_inputs,
        bundle.admission.signed_certificate.as_bytes(),
        bundle.issuance.signed_grant.as_bytes(),
        &HistoricalTime(grant.grant.issued_at),
    )?;
    match (&trust.admission.leases, &bundle.lease_authority) {
        (None, None) => {}
        (Some(_), Some(bindings)) if bindings.len() == 2 => {
            bindings[0].verify(
                &trust.admission,
                &identity,
                &inputs,
                "admission",
                &bundle.admission.certificate_digest,
                admitted_at,
                expires_at,
            )?;
            bindings[1].verify(
                &trust.admission,
                &identity,
                &issued_inputs,
                "issuance",
                &bundle.issuance.grant_digest,
                grant.grant.issued_at,
                grant.grant.expires_at,
            )?;
            if bindings[1].checked_at < bindings[0].checked_at
                || bindings[1].member.generation < bindings[0].member.generation
            {
                return Err(invalid("lease authority time/generation rollback"));
            }
        }
        _ => return Err(invalid("missing or unexpected historical lease authority")),
    }
    let execution: Envelope = serde_json::from_value(strict_value(
        bundle.outcomes.execution.signed_grant.as_bytes(),
    )?)?;
    if bundle.issuance.issuance_key != key
        || issuance.key != key
        || bundle.issuance.binding_digest != issuance.binding
        || bundle.issuance.grant_digest != issuance.grant_digest
        || canonical(&serde_json::to_value(&execution)?)? != issuance.signed_grant.as_bytes()
        || bundle.outcomes.execution.parameters != p["parameters"]
    {
        return Err(invalid("retained issuance/execution mismatch"));
    }
    let result = verify_outcomes(
        &bundle.outcomes,
        &trust.grants,
        &trust.outcome_keys,
        &trust.source_id,
    )?;
    let mut phases = BTreeSet::new();
    for event in &bundle.outcomes.journal {
        crate::recovery::validate(event)?;
        let phase = event["phase"]
            .as_str()
            .ok_or_else(|| invalid("missing journal phase"))?;
        if event["attempt_id"] != bundle.outcomes.attempt_id
            || event["root_id"] != grant.grant.root_id
            || event["grant_digest"] != grant.digest
            || !phases.insert(phase)
        {
            return Err(invalid("journal correlation/duplicate phase mismatch"));
        }
    }
    let reported_phase = if result.reported_status == "failed" {
        "state_guard_violation"
    } else {
        &result.reported_status
    };
    if !phases.contains("claimed")
        || !phases.contains(reported_phase)
        || (result.reported_status != "not_dispatched" && !phases.contains("dispatch_authorized"))
    {
        return Err(invalid("missing correlated execution phases"));
    }
    Ok(LineageVerification {
        profile: bundle.profile.clone(),
        tenant: inputs.context.tenant,
        operation_key: key,
        proposal_digest: record_digest(&proposal)?,
        certificate_digest: record_digest(&cert)?,
        grant_digest: result.grant_digest,
        admitted_at,
        issued_at: grant.grant.issued_at,
        witnesses_verified: evidence.len(),
        receipts_verified: result.receipts_verified,
        attempt_id: result.attempt_id,
        reported_status: result.reported_status,
        missing_links: {
            let mut gaps = vec![
                "original OAuth/DPoP/mTLS authentication transcript".into(),
                "installed control/revocation/key history".into(),
                "independently authenticated authority journal/fence allocation".into(),
                "registered tool-name mapping".into(),
                "target-signed commit/no-effect proof and complete writer coverage".into(),
            ];
            if bundle.lease_authority.is_some() {
                gaps.push(
                    "lease membership lifecycle and authority CAS/observer/clock trust".into(),
                );
            }
            if trust
                .admission
                .evidence
                .values()
                .any(|r| r.review.is_some())
            {
                gaps.push("historical review enrollment and challenge consumption".into());
            }
            gaps
        },
    })
}
impl EtcdLedger {
    /// Privileged read: caller authorizes disclosure. Independent offline trust
    /// verifies signatures; unsigned retained metadata is only correlated here.
    pub async fn export_lineage(
        &self,
        candidate: &Candidate,
        operation_key: &str,
    ) -> Result<LineageBundle> {
        let (issuance, admission) = self
            .retained_operation(operation_key)
            .await?
            .ok_or_else(|| invalid("missing retained admission/issuance operation"))?;
        let outcomes = self.export_outcomes(candidate).await?;
        let issued: Envelope =
            serde_json::from_value(strict_value(issuance.signed_grant.as_bytes())?)?;
        let executed: Envelope =
            serde_json::from_value(strict_value(outcomes.execution.signed_grant.as_bytes())?)?;
        let cert: Envelope = serde_json::from_value(strict_value(
            admission.record.signed_certificate.as_bytes(),
        )?)?;
        let proposal: Envelope =
            serde_json::from_value(strict_value(admission.packet.proposal.as_bytes())?)?;
        if issued.kind != "grant"
            || cert.kind != "certificate"
            || proposal.kind != "proposal"
            || canonical(&serde_json::to_value(&issued)?)?
                != canonical(&serde_json::to_value(&executed)?)?
            || serde_json::from_value::<crate::contracts::Grant>(issued.payload.clone())?
                != candidate.grant
            || record_digest(&issued)? != issuance.grant_digest
            || record_digest(&cert)? != admission.record.certificate_digest
            || issued.payload["certificate_digest"] != admission.record.certificate_digest
            || issued.payload["proposal_digest"] != record_digest(&proposal)?
        {
            return Err(invalid(
                "export admission/issuance/outcome correlation mismatch",
            ));
        }
        let lease_authority = self.retained_lease_bindings(operation_key).await?;
        if admission.packet.lease.is_some() && lease_authority.is_none() {
            return Err(invalid("missing retained lease authority; no synthesis"));
        }
        let bundle = LineageBundle {
            profile: if lease_authority.is_some() {
                LEASE_PROFILE
            } else {
                PROFILE
            }
            .into(),
            lease_authority,
            admission: admission.record,
            packet: admission.packet,
            issuance,
            outcomes,
        };
        let raw = canonical(&serde_json::to_value(&bundle)?)?;
        LineageBundle::decode(&raw)
    }
}
