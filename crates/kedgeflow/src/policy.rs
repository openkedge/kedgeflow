//! Draft Cedar leaf ABI and certificate production from independently verified
//! inputs. Configuration and signing remain authority-side operations.
use crate::{
    admission::VerifiedAdmissionInputs,
    clock::Clock,
    contracts::{Envelope, PROFILE, Policy, canonical, digest, record_digest, signature_input},
    error::{Error, Result},
    issuance::AdmissionContext,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, str::FromStr};

pub const CEDAR_PROFILE: &str = "KF-CEDAR-LEAF-0.1-draft";
const CEDAR_SCHEMA: &str = include_str!("../../../spec/drafts/cedar-leaf-v0.1.schema.json");
const CERTIFICATE_SCHEMA: &str =
    "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/AdmissionCertificate";

/// Installed policy artifact, supplied by an authorized control-plane caller.
/// Its identity includes the exact Cedar source, ABI schema and obligation pin.
#[derive(Clone, Serialize)]
pub struct CedarPolicyDefinition {
    pub tenant: String,
    pub policy_id: String,
    pub cedar: String,
    pub obligation_manifest_digest: String,
    pub max_certificate_lifetime_ms: i64,
}

impl CedarPolicyDefinition {
    pub fn reference(&self, epoch: u64) -> Result<Policy> {
        Ok(Policy {
            id: self.policy_id.clone(),
            epoch,
            digest: digest(
                "policy",
                &json!({"profile":CEDAR_PROFILE,"definition":self,"schema":serde_json::from_str::<Value>(CEDAR_SCHEMA)?}),
            )?,
        })
    }
}

/// Only strictly validated, pinned Cedar policies can evaluate the leaf ABI.
pub struct CedarAdmissionPolicy {
    definition: CedarPolicyDefinition,
    installed: Policy,
    schema: Schema,
    policies: PolicySet,
    entities: Entities,
}

fn refuse(message: &str) -> Error {
    Error::Refused(message.into())
}

impl CedarAdmissionPolicy {
    pub fn new(definition: CedarPolicyDefinition, installed: Policy) -> Result<Self> {
        if definition.tenant.is_empty()
            || definition.policy_id.is_empty()
            || definition.max_certificate_lifetime_ms <= 0
            || !crate::grant_reference::valid_reference(&definition.obligation_manifest_digest)
            || installed.epoch == 0
            || definition.reference(installed.epoch)? != installed
        {
            return Err(refuse("invalid or unpinned Cedar policy definition"));
        }
        let schema = Schema::from_json_value(serde_json::from_str(CEDAR_SCHEMA)?)
            .map_err(|_| refuse("invalid Cedar ABI schema"))?;
        let policies = PolicySet::from_str(&definition.cedar)
            .map_err(|_| refuse("invalid Cedar policy syntax"))?;
        if policies.templates().next().is_some()
            || !Validator::new(schema.clone())
                .validate(&policies, ValidationMode::Strict)
                .validation_passed()
        {
            return Err(refuse("Cedar policy fails strict leaf ABI validation"));
        }
        let entities = schema
            .action_entities()
            .map_err(|_| refuse("invalid Cedar action entities"))?;
        Ok(Self {
            definition,
            installed,
            schema,
            policies,
            entities,
        })
    }

    fn permit(&self, inputs: &VerifiedAdmissionInputs, now: i64) -> Result<()> {
        let c = &inputs.context;
        if now < inputs.valid_from
            || now >= inputs.valid_until
            || c.tenant != self.definition.tenant
            || c.policy != self.installed
            || c.obligation_manifest_digest != self.definition.obligation_manifest_digest
            || inputs.resources.len() != 1
        {
            return Err(refuse(
                "Cedar inputs expired or differ from installed policy",
            ));
        }
        let resource = &inputs.resources[0];
        let action = EntityUid::from_str("KedgeFlow::Action::\"admit\"")
            .map_err(|_| refuse("invalid Cedar action"))?;
        let subject_id = digest(
            "cedar-subject",
            &json!({"tenant":c.tenant,"subject":c.subject}),
        )?;
        let resource_id = digest(
            "cedar-resource",
            &json!({"tenant":c.tenant,"resource":resource}),
        )?;
        let principal = EntityUid::from_type_name_and_id(
            "KedgeFlow::Subject"
                .parse()
                .map_err(|_| refuse("invalid Cedar subject type"))?,
            cedar_policy::EntityId::new(subject_id),
        );
        let target = EntityUid::from_type_name_and_id(
            "KedgeFlow::Resource"
                .parse()
                .map_err(|_| refuse("invalid Cedar resource type"))?,
            cedar_policy::EntityId::new(resource_id),
        );
        let context = Context::from_json_value(json!({
            "tenant":c.tenant,"subject_issuer":c.subject.iss,"subject_id":c.subject.sub,
            "workload_id":c.workload_id,"qid":c.qid,"action_id":inputs.action.id,
            "action_version":inputs.action.version,"descriptor_digest":c.descriptor_digest,
            "parameters_digest":inputs.parameters_digest,"resource_id":resource.id,
            "resource_incarnation":resource.incarnation,"audience":c.audience,
            "conflict_domain":c.conflict_domain,"delegation_digest":c.delegation_digest,
            "proposal_digest":c.proposal_digest,"evidence_manifest_digest":c.evidence_manifest_digest,
            "obligation_manifest_digest":c.obligation_manifest_digest,"policy_epoch":c.policy.epoch,
            "ownership_epoch":c.ownership_epoch,"now_ms":now,
            "obligation_ids":c.obligations.keys().collect::<Vec<_>>()
        }), Some((&self.schema, &action)))
            .map_err(|_| refuse("verified input does not satisfy Cedar ABI"))?;
        let request = Request::new(principal, action, target, context, Some(&self.schema))
            .map_err(|_| refuse("invalid Cedar admission request"))?;
        let response = Authorizer::new().is_authorized(&request, &self.policies, &self.entities);
        // Cedar normally skips policies with evaluation errors. This profile
        // refuses the entire decision even if another policy returns permit.
        if response.decision() != Decision::Allow
            || response.diagnostics().errors().next().is_some()
        {
            return Err(refuse(
                "Cedar denied admission or reported evaluation errors",
            ));
        }
        Ok(())
    }
}

/// Candidate certificates cannot be constructed from unverified request fields.
/// Persist with EtcdLedger::admit before returning a certificate to a client.
pub struct PreparedAdmission {
    pub(crate) key: String,
    pub(crate) binding: String,
    pub(crate) context: AdmissionContext,
    pub(crate) signed_certificate: String,
    pub(crate) certificate_digest: String,
    pub(crate) admitted_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) packet: crate::admission::StoredAdmissionPacket,
}

pub struct AdmissionController {
    policy: CedarAdmissionPolicy,
    key_id: String,
    signing_key: SigningKey,
}

impl AdmissionController {
    pub(crate) fn configured_for(&self, trust: &crate::admission::AdmissionTrust) -> bool {
        self.policy.definition.tenant == trust.tenant
            && self.policy.installed == trust.policy
            && self.policy.definition.obligation_manifest_digest == trust.obligation_manifest_digest
    }
    pub(crate) fn signing_role(&self) -> (&str, ed25519_dalek::VerifyingKey) {
        (&self.key_id, self.signing_key.verifying_key())
    }
    pub fn new(
        policy: CedarAdmissionPolicy,
        key_id: String,
        signing_key: SigningKey,
    ) -> Result<Self> {
        if key_id.is_empty() {
            return Err(refuse("missing admission signing key ID"));
        }
        Ok(Self {
            policy,
            key_id,
            signing_key,
        })
    }

    pub fn prepare(
        &self,
        inputs: &VerifiedAdmissionInputs,
        clock: &dyn Clock,
    ) -> Result<PreparedAdmission> {
        let now = clock.now_ms();
        self.policy.permit(inputs, now)?;
        if inputs
            .record_keys
            .contains(&self.signing_key.verifying_key())
        {
            return Err(refuse("admission signer overlaps an input record role"));
        }
        let c = &inputs.context;
        let expires_at = inputs.valid_until.min(
            now.checked_add(self.policy.definition.max_certificate_lifetime_ms)
                .ok_or_else(|| refuse("certificate validity overflow"))?,
        );
        let constraints = json!({"action":inputs.action,"resources":inputs.resources,
            "parameters_digest":inputs.parameters_digest,"predicate_descriptor":inputs.predicate_descriptor,
            "adapter_contract":inputs.adapter_contract,"audience":c.audience,"max_attempts":1,
            "expires_at":expires_at,"saga_budget":null});
        let mut discharges = Vec::new();
        for (id, obligation) in &c.obligations {
            let w = inputs
                .witnesses
                .get(id)
                .ok_or_else(|| refuse("missing verified obligation"))?;
            discharges.push(json!({"obligation_id":id,"predicate_digest":obligation.predicate_digest,
                "witness_refs":[w.reference],"result":"satisfied","stage":obligation.stage,
                "execution_relevant":obligation.execution_relevant,"observed_at":w.observed_at,"expires_at":w.expires_at}));
        }
        let mut random_id = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random_id)
            .map_err(|_| Error::Unavailable("admission ID randomness unavailable".into()))?;
        let payload = json!({"cid":format!("kf-cert:{}",hex::encode(random_id)),
            "proposal_digest":c.proposal_digest,"delegation_digest":c.delegation_digest,"subject":c.subject,
            "workload_id":c.workload_id,"policy":c.policy,"ownership_epoch":c.ownership_epoch,
            "descriptor_digest":c.descriptor_digest,"obligation_manifest_digest":c.obligation_manifest_digest,
            "evidence_manifest_digest":c.evidence_manifest_digest,"discharges":discharges,
            "constraint_digest":digest("constraints",&constraints)?,"constraints":constraints,
            "lease_digest":null,"admitted_at":now,"expires_at":expires_at});
        let mut envelope = Envelope {
            profile: PROFILE.into(),
            kind: "certificate".into(),
            schema: CERTIFICATE_SCHEMA.into(),
            key_id: self.key_id.clone(),
            payload,
            signature: String::new(),
        };
        envelope.signature = URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(&signature_input(&envelope)?)
                .to_bytes(),
        );
        let signed = canonical(&serde_json::to_value(&envelope)?)?;
        crate::schema::verify_record(
            &signed,
            "certificate",
            &BTreeMap::from([(self.key_id.clone(), self.signing_key.verifying_key())]),
        )?;
        let key = digest(
            "issuance-key",
            &json!({"tenant":c.tenant,"subject":c.subject,"workload_id":c.workload_id,"qid":c.qid}),
        )?;
        // Exclude certificate ID, signature, verification time and derived TTL:
        // concurrent replicas and lost replies resolve the original certificate.
        let witnesses: BTreeMap<_,_> = inputs.witnesses.iter().map(|(id,w)| (id,json!({"reference":w.reference,"observed_at":w.observed_at,"expires_at":w.expires_at}))).collect();
        let binding = digest(
            "admission-binding",
            &json!({"context":c,"action":inputs.action,
            "resources":inputs.resources,"parameters_digest":inputs.parameters_digest,
            "predicate_descriptor":inputs.predicate_descriptor,"adapter_contract":inputs.adapter_contract,
            "valid_until":inputs.valid_until,"witnesses":witnesses}),
        )?;
        Ok(PreparedAdmission {
            key,
            binding,
            context: c.clone(),
            signed_certificate: String::from_utf8(signed)
                .map_err(|_| refuse("invalid certificate encoding"))?,
            certificate_digest: record_digest(&envelope)?,
            admitted_at: now,
            expires_at,
            packet: inputs.packet.clone(),
        })
    }
}
