//! Verified leaf admission inputs. This layer verifies facts and bindings; it
//! does not replace a policy engine or expose a public admission endpoint.
use crate::{
    auth::Identity,
    clock::Clock,
    contracts::{Action, Policy, Resource, Subject, digest, record_digest},
    error::{Error, Result},
    issuance::{AdmissionContext, RequiredObligation},
    schema::{ClosedObjectSchema, verify_record},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordReference {
    pub id: String,
    pub schema: String,
    pub digest: String,
}

/// Server-selected comparisons over schema-validated evidence. Neither a signed
/// `satisfied` label nor a provider's choice of predicate can select these rules.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidencePredicate {
    IntegerAtLeast { field: String, minimum: i64 },
    StringEquals { field: String, expected: String },
    BooleanEquals { field: String, expected: bool },
}

#[derive(Debug, PartialEq, Eq)]
pub enum EvidenceVerdict {
    Satisfied,
    Violated,
    Unknown,
}

impl EvidencePredicate {
    pub fn evaluate(&self, result: &Value) -> EvidenceVerdict {
        let satisfied = match self {
            Self::IntegerAtLeast { field, minimum } => result
                .get(field)
                .and_then(Value::as_i64)
                .map(|v| v >= *minimum),
            Self::StringEquals { field, expected } => result
                .get(field)
                .and_then(Value::as_str)
                .map(|v| v == expected),
            Self::BooleanEquals { field, expected } => result
                .get(field)
                .and_then(Value::as_bool)
                .map(|v| v == *expected),
        };
        match satisfied {
            Some(true) => EvidenceVerdict::Satisfied,
            Some(false) => EvidenceVerdict::Violated,
            None => EvidenceVerdict::Unknown,
        }
    }
}

#[derive(Clone)]
pub struct EvidenceRequirement {
    pub obligation: RequiredObligation,
    pub provider_id: String,
    pub provider_version: String,
    pub keys: BTreeMap<String, VerifyingKey>,
    pub question: RecordReference,
    pub result_schema_ref: RecordReference,
    pub result_schema: Value,
    pub max_age_ms: i64,
    pub predicates: Vec<EvidencePredicate>,
}

/// Installed authority-side configuration. The caller must obtain the policy,
/// ownership and descriptor pins from its authorized control plane, not an agent.
#[derive(Clone)]
pub struct AdmissionTrust {
    pub tenant: String,
    pub proposal_keys: BTreeMap<String, VerifyingKey>,
    pub proposal_workload_id: String,
    pub registry_keys: BTreeMap<String, VerifyingKey>,
    pub manifest_keys: BTreeMap<String, VerifyingKey>,
    pub descriptor_digest: String,
    pub ownership_epoch: u64,
    pub policy: Policy,
    pub obligation_manifest_digest: String,
    pub required_scope: String,
    pub max_proposal_age_ms: i64,
    pub evidence: BTreeMap<String, EvidenceRequirement>,
}

pub struct AdmissionPacket<'a> {
    pub proposal: &'a [u8],
    pub descriptor: &'a [u8],
    pub manifest: &'a [u8],
    pub evidence: &'a [Vec<u8>],
}

/// Exact signed input records retained with admission, never a serialized
/// verification result. The issuer must reverify them against its current pins.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredAdmissionPacket {
    pub proposal: String,
    pub descriptor: String,
    pub manifest: String,
    pub witnesses: Vec<String>,
}

#[derive(Deserialize)]
struct Baseline {
    resource: Resource,
    version: String,
    state_digest: String,
    observed_at: i64,
    expires_at: i64,
}
#[derive(Deserialize)]
struct Proposal {
    qid: String,
    tenant: String,
    subject: Subject,
    workload_id: String,
    delegation: Value,
    action: Action,
    resources: Vec<Resource>,
    parameters: Value,
    dependencies: Vec<Value>,
    baseline_state: Vec<Baseline>,
    requested_completion: String,
    created_at: i64,
    workflow: Value,
}
#[derive(Deserialize)]
struct Descriptor {
    tenant: String,
    action: String,
    version: String,
    parameter_schema: Value,
    parameter_schema_digest: String,
    rendering: Value,
    adapter_contract: Value,
    concurrency: Value,
    ownership_epoch: u64,
    gateway_audience: String,
    compensation: Value,
}
#[derive(Deserialize)]
struct WitnessEntry {
    witness: RecordReference,
    obligation_id: String,
    execution_relevant: bool,
    expires_at: i64,
}
#[derive(Deserialize)]
struct Manifest {
    proposal_digest: String,
    policy: Policy,
    witnesses: Vec<WitnessEntry>,
    assembled_at: i64,
}
#[derive(Deserialize)]
struct Evidence {
    wid: String,
    provider_id: String,
    provider_version: String,
    question_ref: RecordReference,
    proposal_digest: String,
    state_scope: Vec<Resource>,
    state_digest: String,
    result_schema: RecordReference,
    result: Value,
    observed_at: i64,
    expires_at: i64,
    provenance_refs: Vec<Value>,
    exposure_domains: Vec<String>,
}

pub(crate) struct VerifiedWitness {
    pub reference: RecordReference,
    pub observed_at: i64,
    pub expires_at: i64,
}

/// Private construction prevents unverified request fields from supplying the
/// issuance context. Its validity is bounded and rechecked by the issuer.
pub struct VerifiedAdmissionInputs {
    pub(crate) context: AdmissionContext,
    pub(crate) action: Action,
    pub(crate) resources: Vec<Resource>,
    pub(crate) parameters_digest: String,
    pub(crate) predicate_descriptor: Value,
    pub(crate) adapter_contract: Value,
    pub(crate) valid_from: i64,
    pub(crate) valid_until: i64,
    pub(crate) witnesses: BTreeMap<String, VerifiedWitness>,
    pub(crate) record_keys: Vec<VerifyingKey>,
    pub(crate) packet: StoredAdmissionPacket,
}

fn refuse(message: &str) -> Error {
    Error::Refused(message.into())
}

impl AdmissionTrust {
    /// Authorize lookup without trusting unsigned qid/tenant fields. Full input
    /// verification, including freshness, follows after the retained chain loads.
    pub fn operation_key(&self, identity: &Identity, raw: &[u8]) -> Result<String> {
        let signed = verify_record(raw, "proposal", &self.proposal_keys)?;
        let p: Proposal = serde_json::from_value(signed.payload)?;
        if p.tenant != self.tenant
            || p.subject != identity.subject
            || p.workload_id != self.proposal_workload_id
            || p.workload_id != identity.workload_id
            || !identity.scopes.contains(&self.required_scope)
            || digest("delegation", &p.delegation)? != identity.delegation_digest
            || p.delegation["dpop_jkt"].as_str() != Some(&identity.dpop_jkt)
        {
            return Err(refuse("proposal lookup identity mismatch"));
        }
        digest(
            "issuance-key",
            &serde_json::json!({"tenant":p.tenant,"subject":p.subject,"workload_id":p.workload_id,"qid":p.qid}),
        )
    }

    /// Historical disclosure binds the signed operation to the current caller;
    /// an expired execution delegation confers no execution permission here.
    pub(crate) fn historical_operation_key(
        &self,
        identity: &Identity,
        raw: &[u8],
    ) -> Result<String> {
        let signed = verify_record(raw, "proposal", &self.proposal_keys)?;
        let p: Proposal = serde_json::from_value(signed.payload)?;
        if p.tenant != self.tenant
            || p.subject != identity.subject
            || p.workload_id != self.proposal_workload_id
            || p.workload_id != identity.workload_id
            || p.delegation["dpop_jkt"].as_str() != Some(&identity.dpop_jkt)
            || p.action.digest != self.descriptor_digest
        {
            return Err(refuse(
                "historical proposal identity or descriptor mismatch",
            ));
        }
        digest(
            "issuance-key",
            &serde_json::json!({"tenant":p.tenant,"subject":p.subject,"workload_id":p.workload_id,"qid":p.qid}),
        )
    }

    /// Draft local registration identity. Bind approved rules, schemas, provider
    /// keys and freshness limits before publishing the installed policy pin.
    pub fn registered_obligations_digest(&self) -> Result<String> {
        let definitions: BTreeMap<_, _> = self
            .evidence
            .iter()
            .map(|(id, r)| {
                let keys: BTreeMap<_, _> = r
                    .keys
                    .iter()
                    .map(|(id, key)| (id, hex::encode(key.as_bytes())))
                    .collect();
                (
                    id,
                    serde_json::json!({
                        "obligation": r.obligation,
                        "provider_id": r.provider_id,
                        "provider_version": r.provider_version,
                        "keys": keys,
                        "question": r.question,
                        "result_schema_ref": r.result_schema_ref,
                        "result_schema": r.result_schema,
                        "max_age_ms": r.max_age_ms,
                        "predicates": r.predicates
                    }),
                )
            })
            .collect();
        digest(
            "obligation-manifest",
            &serde_json::json!({"profile":"KF-CEDAR-LEAF-0.1-draft","obligations":definitions}),
        )
    }

    pub fn validate_configuration(&self) -> Result<()> {
        if self.max_proposal_age_ms <= 0
            || self.evidence.is_empty()
            || self.obligation_manifest_digest != self.registered_obligations_digest()?
        {
            return Err(refuse("invalid registered admission configuration"));
        }
        // Reject authority role confusion, including reuse under different key IDs.
        let roles = [
            &self.proposal_keys,
            &self.registry_keys,
            &self.manifest_keys,
        ];
        for (i, keys) in roles.iter().enumerate() {
            if keys.is_empty()
                || roles
                    .iter()
                    .skip(i + 1)
                    .any(|other| keys.values().any(|k| other.values().any(|o| k == o)))
            {
                return Err(refuse("admission record roles must use independent keys"));
            }
        }
        for requirement in self.evidence.values() {
            if requirement.predicates.is_empty()
                || requirement.obligation.predicate_digest
                    != digest(
                        "evidence-predicate",
                        &serde_json::to_value(&requirement.predicates)?,
                    )?
                || requirement.keys.is_empty()
                || requirement.max_age_ms <= 0
                || digest("result-schema", &requirement.result_schema)?
                    != requirement.result_schema_ref.digest
                || roles.iter().any(|role| {
                    requirement
                        .keys
                        .values()
                        .any(|k| role.values().any(|r| k == r))
                })
            {
                return Err(refuse(
                    "evidence provider lacks independent approved rules/keys",
                ));
            }
        }
        Ok(())
    }

    pub fn verify_inputs(
        &self,
        identity: &Identity,
        packet: AdmissionPacket<'_>,
        clock: &dyn Clock,
    ) -> Result<VerifiedAdmissionInputs> {
        let now = clock.now_ms();
        if self.max_proposal_age_ms <= 0
            || self.evidence.is_empty()
            || self.obligation_manifest_digest != self.registered_obligations_digest()?
            || !identity.scopes.contains(&self.required_scope)
            || identity.workload_id != self.proposal_workload_id
        {
            return Err(refuse(
                "unsupported admission configuration or caller scope",
            ));
        }
        self.validate_configuration()?;
        let roles = [
            &self.proposal_keys,
            &self.registry_keys,
            &self.manifest_keys,
        ];
        let q = verify_record(packet.proposal, "proposal", &self.proposal_keys)?;
        let ctd = verify_record(packet.descriptor, "ctd", &self.registry_keys)?;
        let manifest = verify_record(packet.manifest, "manifest", &self.manifest_keys)?;
        let proposal_digest = record_digest(&q)?;
        let descriptor_digest = record_digest(&ctd)?;
        let manifest_digest = record_digest(&manifest)?;
        let p: Proposal = serde_json::from_value(q.payload)?;
        let d: Descriptor = serde_json::from_value(ctd.payload)?;
        let m: Manifest = serde_json::from_value(manifest.payload)?;
        if p.tenant != self.tenant
            || d.tenant != self.tenant
            || p.subject != identity.subject
            || p.workload_id != identity.workload_id
            || digest("delegation", &p.delegation)? != identity.delegation_digest
            || p.delegation["dpop_jkt"].as_str() != Some(&identity.dpop_jkt)
            || descriptor_digest != self.descriptor_digest
            || p.action.digest != descriptor_digest
            || p.action.id != d.action
            || p.action.version != d.version
            || d.ownership_epoch != self.ownership_epoch
            || p.created_at > now
            || now.saturating_sub(p.created_at) >= self.max_proposal_age_ms
            || !p.workflow.is_null()
            || !p.dependencies.is_empty()
            || !d.compensation.is_null()
            || p.requested_completion != "dispatch_bound"
            || d.adapter_contract["completion_mode"] != "dispatch_bound"
            || d.adapter_contract["level"] != "Level_A"
            || d.adapter_contract["guard_primitive"] != "FencingToken"
            || p.resources.len() != 1
            || p.baseline_state.len() != 1
        {
            return Err(refuse(
                "proposal does not bind identity/current leaf descriptor",
            ));
        }
        let delegation_expiry = p.delegation["expires_at"]
            .as_i64()
            .ok_or_else(|| refuse("missing delegation validity"))?;
        if delegation_expiry <= now {
            return Err(refuse("delegation expired"));
        }
        if digest("parameter-schema", &d.parameter_schema)? != d.parameter_schema_digest
            || d.rendering["parameter_schema_digest"].as_str() != Some(&d.parameter_schema_digest)
        {
            return Err(refuse("descriptor parameter schema binding mismatch"));
        }
        ClosedObjectSchema::new(&d.parameter_schema)?.validate(&p.parameters)?;
        let baseline = &p.baseline_state[0];
        let predicate = &d.concurrency["predicate_descriptor"];
        let clauses = predicate["clauses"]
            .as_array()
            .ok_or_else(|| refuse("missing resource predicate"))?;
        if baseline.resource != p.resources[0]
            || baseline.observed_at > now
            || baseline.expires_at <= now
            || clauses.len() != 1
            || clauses[0]["kind"] != "version_eq"
            || serde_json::from_value::<Resource>(clauses[0]["resource"].clone())? != p.resources[0]
            || clauses[0]["expected_version"].as_str() != Some(&baseline.version)
            || p.parameters
                .as_object()
                .is_none_or(|fields| fields.len() != 2)
            || p.parameters["node"].as_str() != Some(&p.resources[0].id)
            || p.parameters["expected_version"]
                .as_u64()
                .is_none_or(|v| v == 0 || v.to_string() != baseline.version)
            || d.adapter_contract["guard_scope"] != serde_json::json!([p.resources[0].id])
            || !d.concurrency["coverage"]["uncoordinated_writers"]
                .as_array()
                .is_some_and(Vec::is_empty)
            || d.concurrency["coverage"]["coordinated_writers"]
                .as_array()
                .is_none_or(Vec::is_empty)
        {
            return Err(refuse("baseline, guard or writer coverage mismatch"));
        }
        if m.proposal_digest != proposal_digest
            || m.policy != self.policy
            || m.assembled_at > now
            || m.assembled_at < p.created_at
            || m.witnesses.len() != self.evidence.len()
            || packet.evidence.len() != m.witnesses.len()
        {
            return Err(refuse(
                "manifest lacks exact proposal/policy/obligation coverage",
            ));
        }
        // Match signed records by verified IDs/digests, never their array order.
        let mut records = BTreeMap::new();
        for raw in packet.evidence {
            let value = crate::contracts::strict_value(raw)?;
            let id = value["payload"]["wid"]
                .as_str()
                .ok_or_else(|| refuse("unsupported witness kind"))?
                .to_owned();
            if records.insert(id, raw).is_some() {
                return Err(refuse("duplicate evidence identity"));
            }
        }
        let mut valid_until = delegation_expiry
            .min(baseline.expires_at)
            .min(p.created_at.saturating_add(self.max_proposal_age_ms));
        let mut witnesses = BTreeMap::new();
        for entry in m.witnesses {
            let requirement = self
                .evidence
                .get(&entry.obligation_id)
                .ok_or_else(|| refuse("unregistered evidence obligation"))?;
            let raw = records
                .remove(&entry.witness.id)
                .ok_or_else(|| refuse("missing referenced evidence"))?;
            let signed = verify_record(raw, "evidence", &requirement.keys)?;
            let reference = RecordReference {
                id: entry.witness.id.clone(),
                schema: signed.schema.clone(),
                digest: record_digest(&signed)?,
            };
            let e: Evidence = serde_json::from_value(signed.payload)?;
            if reference != entry.witness
                || e.wid != reference.id
                || e.provider_id != requirement.provider_id
                || e.provider_version != requirement.provider_version
                || e.question_ref != requirement.question
                || e.result_schema != requirement.result_schema_ref
                || e.proposal_digest != proposal_digest
                || e.state_scope != p.resources
                || e.state_digest != baseline.state_digest
                || e.observed_at > m.assembled_at
                || e.observed_at > now
                || now.saturating_sub(e.observed_at) >= requirement.max_age_ms
                || e.expires_at <= now
                || entry.expires_at != e.expires_at
                || entry.execution_relevant != requirement.obligation.execution_relevant
                || !e.provenance_refs.is_empty()
                || e.exposure_domains.is_empty()
            {
                return Err(refuse(
                    "evidence identity, state, reference or freshness mismatch",
                ));
            }
            ClosedObjectSchema::new(&requirement.result_schema)?.validate(&e.result)?;
            if requirement
                .predicates
                .iter()
                .any(|rule| rule.evaluate(&e.result) != EvidenceVerdict::Satisfied)
            {
                return Err(refuse("required evidence predicate violated or unknown"));
            }
            valid_until = valid_until
                .min(e.expires_at)
                .min(e.observed_at.saturating_add(requirement.max_age_ms));
            if witnesses
                .insert(
                    entry.obligation_id,
                    VerifiedWitness {
                        reference,
                        observed_at: e.observed_at,
                        expires_at: e.expires_at,
                    },
                )
                .is_some()
            {
                return Err(refuse("duplicate manifest obligation"));
            }
        }
        let required: BTreeSet<_> = self.evidence.keys().collect();
        if required != witnesses.keys().collect() || !records.is_empty() {
            return Err(refuse("incomplete witness coverage"));
        }
        Ok(VerifiedAdmissionInputs {
            context: AdmissionContext {
                tenant: p.tenant,
                qid: p.qid,
                subject: p.subject,
                workload_id: p.workload_id,
                dpop_jkt: identity.dpop_jkt.clone(),
                proposal_digest,
                delegation_digest: identity.delegation_digest.clone(),
                descriptor_digest,
                obligation_manifest_digest: self.obligation_manifest_digest.clone(),
                evidence_manifest_digest: manifest_digest,
                policy: self.policy.clone(),
                ownership_epoch: self.ownership_epoch,
                audience: d.gateway_audience,
                conflict_domain: d.concurrency["conflict_domain"]
                    .as_str()
                    .ok_or_else(|| refuse("missing conflict domain"))?
                    .to_owned(),
                obligations: self
                    .evidence
                    .iter()
                    .map(|(id, r)| (id.clone(), r.obligation.clone()))
                    .collect(),
            },
            action: p.action,
            resources: p.resources,
            parameters_digest: digest("parameters", &p.parameters)?,
            predicate_descriptor: predicate.clone(),
            adapter_contract: d.adapter_contract,
            valid_from: now,
            valid_until,
            witnesses,
            record_keys: roles
                .iter()
                .flat_map(|keys| keys.values().copied())
                .chain(
                    self.evidence
                        .values()
                        .flat_map(|r| r.keys.values().copied()),
                )
                .collect(),
            packet: StoredAdmissionPacket {
                proposal: std::str::from_utf8(packet.proposal)
                    .map_err(|_| refuse("proposal UTF8"))?
                    .into(),
                descriptor: std::str::from_utf8(packet.descriptor)
                    .map_err(|_| refuse("descriptor UTF8"))?
                    .into(),
                manifest: std::str::from_utf8(packet.manifest)
                    .map_err(|_| refuse("manifest UTF8"))?
                    .into(),
                witnesses: packet
                    .evidence
                    .iter()
                    .map(|r| {
                        std::str::from_utf8(r)
                            .map(str::to_owned)
                            .map_err(|_| refuse("witness UTF8"))
                    })
                    .collect::<Result<_>>()?,
            },
        })
    }
}
