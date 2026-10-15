//! Native review result in the existing Evidence envelope, with explicit opt-in.
use crate::{
    admission::RecordReference,
    clock::Clock,
    contracts::{
        Action, Envelope, Policy, Resource, Subject, canonical, digest, record_digest,
        signature_input,
    },
    error::{Error, Result},
    ledger::{EtcdLedger, get, put, range_kv, record, value_eq, version_zero},
    review::{Approval, ReviewEnrollment, ReviewFact},
    schema::{ClosedObjectSchema, verify_record},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub const PROFILE: &str = "KF-REVIEW-EVIDENCE-HTTP-0.1-draft";
pub const RESULT_PROFILE: &str = "KF-REVIEW-RESULT-0.1-draft";
fn refuse() -> Error {
    Error::Refused("native review context or permission refused".into())
}
pub fn result_schema() -> Value {
    serde_json::from_str(include_str!(
        "../../../spec/drafts/review-evidence-result-v0.1.schema.json"
    ))
    .expect("embedded review result schema")
}
pub fn template_digest() -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical(
        &json!({"profile":"KF-CANONICAL-REVIEW-0.1-draft","fields":["tenant","qid","initiating_subject","initiating_workload","proposal_digest","descriptor_digest","policy","ownership_epoch","action","resources","parameters","baseline_state"]}),
    )?)))
}
pub fn rendering(
    proposal: &Value,
    descriptor_digest: &str,
    policy: &Policy,
    ownership_epoch: u64,
) -> Result<String> {
    String::from_utf8(canonical(&json!({"profile":"KF-CANONICAL-REVIEW-0.1-draft","tenant":proposal["tenant"],"qid":proposal["qid"],"initiating_subject":proposal["subject"],"initiating_workload":proposal["workload_id"],"proposal_digest":proposal["_record_digest"],"descriptor_digest":descriptor_digest,"policy":policy,"ownership_epoch":ownership_epoch,"action":proposal["action"],"resources":proposal["resources"],"parameters":proposal["parameters"],"baseline_state":proposal["baseline_state"]}))?).map_err(|_|refuse())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRule {
    pub credentials: BTreeMap<String, ReviewEnrollment>,
}
impl ReviewRule {
    pub fn validate(&self) -> Result<()> {
        if self.credentials.is_empty() || self.credentials.len() > 64 {
            return Err(refuse());
        }
        for (id, e) in &self.credentials {
            e.validate()?;
            if id != &e.credential_id {
                return Err(refuse());
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // Independent signed-context pins are explicit.
    pub(crate) fn verify(
        &self,
        result: &Value,
        proposal: &Value,
        proposal_digest: &str,
        descriptor: &Value,
        descriptor_digest: &str,
        policy: &Policy,
        ownership_epoch: u64,
        now: i64,
    ) -> Result<ReviewFact> {
        self.validate()?;
        let fact = ReviewFact::from_value(result.clone())?;
        let enrollment = self
            .credentials
            .get(&fact.credential_id)
            .ok_or_else(refuse)?;
        fact.validate(enrollment, now)?;
        let mut q = proposal.clone();
        q["_record_digest"] = json!(proposal_digest);
        let rendered = rendering(&q, descriptor_digest, policy, ownership_epoch)?;
        if !fact.approved
            || fact.approval.proposal_digest != proposal_digest
            || proposal["created_at"]
                .as_i64()
                .is_none_or(|t| fact.approval.reviewed_at < t)
            || fact.approval.parameters_digest != digest("parameters", &proposal["parameters"])?
            || fact.approval.policy_epoch != policy.epoch
            || fact.approval.rendering_template_digest != template_digest()?
            || descriptor["rendering"]["template_digest"] != template_digest()?
            || descriptor["rendering"]["media_type"] != "text/plain"
            || fact.approval.rendered_digest != hex::encode(Sha256::digest(rendered.as_bytes()))
        {
            return Err(refuse());
        }
        Ok(fact)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRegistration {
    pub tenant: String,
    pub initiating_workload: String,
    pub initiating_subjects: Vec<Subject>,
    pub proposal_keys: BTreeMap<String, String>,
    pub registry_keys: BTreeMap<String, String>,
    pub descriptor_digest: String,
    pub ownership_epoch: u64,
    pub policy: Policy,
    pub rule: ReviewRule,
    pub provider_id: String,
    pub provider_version: String,
    pub question: RecordReference,
    pub result_schema_ref: RecordReference,
    pub max_proposal_age_ms: i64,
    pub lifetime_ms: i64,
}
impl ReviewRegistration {
    pub fn validate(&self) -> Result<()> {
        self.rule.validate()?;
        let proposal = crate::control_config::keys(&self.proposal_keys)?;
        let registry = crate::control_config::keys(&self.registry_keys)?;
        if self.tenant.is_empty()
            || self.tenant.len() > 256
            || !crate::auth::valid_spiffe_id(&self.initiating_workload)
            || self.initiating_subjects.is_empty()
            || self.initiating_subjects.len() > 64
            || self
                .initiating_subjects
                .iter()
                .any(|s| s.iss.is_empty() || s.sub.is_empty())
            || !crate::grant_reference::valid_reference(&self.descriptor_digest)
            || self.ownership_epoch == 0
            || self.policy.epoch == 0
            || self.policy.id.is_empty()
            || !crate::grant_reference::valid_reference(&self.policy.digest)
            || self.provider_id.is_empty()
            || self.provider_version.is_empty()
            || self.question.id.is_empty()
            || self.question.schema.is_empty()
            || !crate::grant_reference::valid_reference(&self.question.digest)
            || self.result_schema_ref.id.is_empty()
            || self.result_schema_ref.schema.is_empty()
            || self.result_schema_ref.digest != digest("result-schema", &result_schema())?
            || !(1..=300_000).contains(&self.max_proposal_age_ms)
            || !(1..=300_000).contains(&self.lifetime_ms)
            || proposal.values().any(|a| registry.values().any(|b| a == b))
        {
            return Err(refuse());
        }
        Ok(())
    }
}
pub(crate) struct Context {
    pub approval: Approval,
    pub rendered: String,
    pub resource: Resource,
    pub state_digest: String,
    pub scope: crate::governance::EnforcementScope,
}
impl ReviewRegistration {
    pub(crate) fn context(
        &self,
        proposal: &str,
        descriptor: &str,
        credential: &str,
        verdict: &str,
        now: i64,
    ) -> Result<Context> {
        self.validate()?;
        if proposal.len() > 262144
            || descriptor.len() > 262144
            || !["approve", "reject"].contains(&verdict)
        {
            return Err(refuse());
        }
        let q = verify_record(
            proposal.as_bytes(),
            "proposal",
            &crate::control_config::keys(&self.proposal_keys)?,
        )?;
        let ctd = verify_record(
            descriptor.as_bytes(),
            "ctd",
            &crate::control_config::keys(&self.registry_keys)?,
        )?;
        let qd = record_digest(&q)?;
        let dd = record_digest(&ctd)?;
        let p = &q.payload;
        let d = &ctd.payload;
        let enrollment = self.rule.credentials.get(credential).ok_or_else(refuse)?;
        let resources: Vec<Resource> = serde_json::from_value(p["resources"].clone())?;
        let subject: Subject = serde_json::from_value(p["subject"].clone())?;
        let baseline = p["baseline_state"].as_array().ok_or_else(refuse)?;
        if dd != self.descriptor_digest
            || p["action"]["digest"] != dd
            || p["action"]["id"] != d["action"]
            || p["action"]["version"] != d["version"]
            || p["tenant"] != self.tenant
            || d["tenant"] != self.tenant
            || p["workload_id"] != self.initiating_workload
            || !self.initiating_subjects.contains(&subject)
            || d["ownership_epoch"] != self.ownership_epoch
            || resources.len() != 1
            || baseline.len() != 1
            || !p["dependencies"].as_array().is_some_and(Vec::is_empty)
            || !p["workflow"].is_null()
            || !d["compensation"].is_null()
            || p["requested_completion"] != "dispatch_bound"
            || p["created_at"]
                .as_i64()
                .is_none_or(|t| t > now || now.saturating_sub(t) >= self.max_proposal_age_ms)
            || d["rendering"]["template_digest"] != template_digest()?
            || d["rendering"]["media_type"] != "text/plain"
        {
            return Err(refuse());
        }
        let parameter_pin = digest("parameter-schema", &d["parameter_schema"])?;
        if d["parameter_schema_digest"] != parameter_pin
            || d["rendering"]["parameter_schema_digest"] != parameter_pin
        {
            return Err(refuse());
        }
        let action: Action = serde_json::from_value(p["action"].clone())?;
        crate::leaf_action::validate_schema(&action.id, &action.version, &d["parameter_schema"])?;
        ClosedObjectSchema::new(&d["parameter_schema"])?.validate(&p["parameters"])?;
        let version = crate::leaf_action::bind(
            &action.id,
            &action.version,
            &p["parameters"],
            &resources[0],
            "expected_version",
        )?;
        let b = &baseline[0];
        let version_text = version.to_string();
        if b["resource"] != json!(resources[0])
            || b["version"].as_str() != Some(version_text.as_str())
            || b["observed_at"].as_i64().is_none_or(|t| t > now)
            || !crate::grant_reference::valid_reference(
                b["state_digest"].as_str().ok_or_else(refuse)?,
            )
        {
            return Err(refuse());
        }
        let valid_until = [
            b["expires_at"].as_i64(),
            p["delegation"]["expires_at"].as_i64(),
            p["created_at"]
                .as_i64()
                .and_then(|t| t.checked_add(self.max_proposal_age_ms)),
            now.checked_add(self.lifetime_ms),
        ]
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(refuse)?
        .into_iter()
        .min()
        .ok_or_else(refuse)?;
        if valid_until <= now {
            return Err(refuse());
        }
        let scope = crate::governance::EnforcementScope {
            conflict_domain: d["concurrency"]["conflict_domain"]
                .as_str()
                .ok_or_else(refuse)?
                .into(),
            action,
            resource: resources[0].clone(),
            audience: d["gateway_audience"].as_str().ok_or_else(refuse)?.into(),
            adapter_contract: d["adapter_contract"].clone(),
            predicate_descriptor: d["concurrency"]["predicate_descriptor"].clone(),
        };
        crate::contracts::validate_adapter_contract(
            &scope.adapter_contract,
            &scope.resource,
            Some("fence"),
        )?;
        let clauses = scope.predicate_descriptor["clauses"]
            .as_array()
            .ok_or_else(refuse)?;
        if scope.conflict_domain.is_empty()
            || clauses.len() != 1
            || clauses[0]["kind"] != "version_eq"
            || clauses[0]["resource"] != json!(scope.resource)
            || clauses[0]["expected_version"].as_str() != Some(version_text.as_str())
            || !d["concurrency"]["coverage"]["uncoordinated_writers"]
                .as_array()
                .is_some_and(Vec::is_empty)
            || d["concurrency"]["coverage"]["coordinated_writers"]
                .as_array()
                .is_none_or(Vec::is_empty)
        {
            return Err(refuse());
        }
        let mut rendered_p = p.clone();
        rendered_p["_record_digest"] = json!(qd);
        let rendered = rendering(&rendered_p, &dd, &self.policy, self.ownership_epoch)?;
        let approval = Approval {
            proposal_digest: qd,
            policy_epoch: self.policy.epoch,
            reviewer: enrollment.reviewer.clone(),
            rendering_template_digest: template_digest()?,
            rendered_digest: hex::encode(Sha256::digest(rendered.as_bytes())),
            parameters_digest: digest("parameters", &p["parameters"])?,
            reviewed_at: now,
            expires_at: valid_until,
            verdict: verdict.into(),
            nonce: String::new(),
            rp_id: enrollment.rp_id.clone(),
        };
        Ok(Context {
            approval,
            rendered,
            resource: resources[0].clone(),
            state_digest: b["state_digest"].as_str().ok_or_else(refuse)?.into(),
            scope,
        })
    }
    pub(crate) fn matches(&self, expected: &Approval, actual: &Approval) -> bool {
        expected.proposal_digest == actual.proposal_digest
            && expected.policy_epoch == actual.policy_epoch
            && expected.reviewer == actual.reviewer
            && expected.rendering_template_digest == actual.rendering_template_digest
            && expected.rendered_digest == actual.rendered_digest
            && expected.parameters_digest == actual.parameters_digest
            && expected.verdict == actual.verdict
            && expected.rp_id == actual.rp_id
            && actual.expires_at <= expected.expires_at
    }
}
impl EtcdLedger {
    pub(crate) async fn review_context_compares(
        &self,
        registration: &ReviewRegistration,
        context: &Context,
    ) -> Result<Vec<Value>> {
        let mut compares = self
            .control_check(
                &context.scope,
                &registration.policy,
                registration.ownership_epoch,
                None,
                None,
            )
            .await?
            .compare;
        let domain = self.domain_base(&context.scope.conflict_domain);
        compares.extend([
            value_eq(&format!("{domain}/policy"), &record(&registration.policy)?),
            value_eq(
                &format!("{domain}/ownership"),
                &registration.ownership_epoch.to_string(),
            ),
        ]);
        Ok(compares)
    }
    pub(crate) async fn publish_review(
        &self,
        registration: &ReviewRegistration,
        context: &Context,
        fact: &ReviewFact,
        key_id: &str,
        signer: &SigningKey,
        clock: &dyn Clock,
    ) -> Result<String> {
        fact.validate(
            registration
                .rule
                .credentials
                .get(&fact.credential_id)
                .ok_or_else(refuse)?,
            clock.now_ms(),
        )?;
        if !registration.matches(&context.approval, &fact.approval) {
            return Err(refuse());
        }
        let wid = format!(
            "kf-review:{}",
            hex::encode(Sha256::digest(fact.approval.nonce.as_bytes()))
        );
        let mut envelope = Envelope {
            profile: crate::contracts::PROFILE.into(),
            kind: "evidence".into(),
            schema: "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Evidence".into(),
            key_id: key_id.into(),
            signature: String::new(),
            payload: json!({"wid":wid,"provider_id":registration.provider_id,"provider_version":registration.provider_version,"question_ref":registration.question,"proposal_digest":fact.approval.proposal_digest,"state_scope":[context.resource],"state_digest":context.state_digest,"result_schema":registration.result_schema_ref,"result":fact,"observed_at":fact.verified_at,"expires_at":fact.approval.expires_at,"provenance_refs":[],"exposure_domains":["canonical-review"]}),
        };
        envelope.signature =
            URL_SAFE_NO_PAD.encode(signer.sign(&signature_input(&envelope)?).to_bytes());
        let witness = String::from_utf8(canonical(&serde_json::to_value(&envelope)?)?)
            .map_err(|_| refuse())?;
        verify_record(
            witness.as_bytes(),
            "evidence",
            &BTreeMap::from([(key_id.into(), signer.verifying_key())]),
        )?;
        let binding = digest(
            "review-publisher",
            &json!({"registration":registration,"key_id":key_id,"public_key":hex::encode(signer.verifying_key().as_bytes())}),
        )?;
        let saved = record(&json!({"binding":binding,"witness":witness}))?;
        let key = format!(
            "{}/review/evidence/{}",
            self.prefix,
            digest("review-nonce", &json!(fact.approval.nonce))?
        );
        let mut compares = self.review_context_compares(registration, context).await?;
        compares.extend(
            self.review_compares(std::slice::from_ref(fact), clock.now_ms())
                .await?,
        );
        let mut create = compares.clone();
        create.push(version_zero(&key));
        if !self
            .txn(create, vec![put(&key, &saved)], Vec::new())
            .await?
            .succeeded
        {
            let read = self.txn(compares, vec![get(&key)], Vec::new()).await?;
            if !read.succeeded
                || range_kv(read.responses.first().ok_or_else(refuse)?)?
                    .is_none_or(|kv| kv.value != saved.as_bytes())
            {
                return Err(refuse());
            }
        }
        fact.validate(
            registration
                .rule
                .credentials
                .get(&fact.credential_id)
                .ok_or_else(refuse)?,
            clock.now_ms(),
        )?;
        Ok(witness)
    }
}
