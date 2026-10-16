//! Independently signed inverse prerequisites. No issuance, spend or dispatch port.
use crate::{
    contracts::{Policy, Resource, canonical, digest, record_digest, strict_value},
    coordination::ReservationState as S,
    error::{Error, Result},
    governance::EnforcementScope,
    hierarchical_leaf::Principal,
    ledger::{EtcdLedger, get, put, record, value_eq, version_zero},
    reserved_lineage::{Bundle, Trust},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub const PROFILE: &str = "KF-INVERSE-QUALIFICATION-0.1-draft";
pub const ACTION: &str = "kedgeflow.compensation.restore.v1";
pub const MAX_PROOF: usize = 512 << 10;
pub const MAX_RECORDS: u64 = 32;
fn refuse() -> Error {
    Error::Refused("inverse contract, original effect or qualification proof refused".into())
}
fn schema(v: &Value, kind: &str) -> Result<()> {
    static PIN: std::sync::OnceLock<BTreeMap<&'static str, jsonschema::Validator>> =
        std::sync::OnceLock::new();
    let pins = PIN.get_or_init(|| {
        ["contract", "proof", "barrier", "applicability"]
            .into_iter()
            .map(|kind| {
                let mut v: Value = serde_json::from_str(include_str!(
                    "../../../spec/drafts/inverse-qualification-v0.1.schema.json"
                ))
                .expect("inverse schema");
                v.as_object_mut().expect("schema object").remove("oneOf");
                v["$ref"] = json!(format!("#/$defs/{kind}"));
                (
                    kind,
                    crate::schema::compile(&v).expect("valid inverse schema"),
                )
            })
            .collect()
    });
    if pins.get(kind).is_some_and(|s| s.is_valid(v)) {
        Ok(())
    } else {
        Err(refuse())
    }
}
/// Fixed application parameters for the draft inverse; metadata is never authority.
pub fn parameter_schema() -> Value {
    let v: Value = serde_json::from_str(include_str!(
        "../../../spec/drafts/inverse-qualification-v0.1.schema.json"
    ))
    .expect("inverse schema");
    v["$defs"]["parameters"].clone()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub profile: String,
    pub contract_id: String,
    pub registration_digest: String,
    pub node_id: String,
    pub forward_operation_key: String,
    pub inverse_operation_key: String,
    pub inverse_principal: Principal,
    pub inverse_scope: EnforcementScope,
    pub inverse_policy: Policy,
    pub signed_inverse_ctd: String,
    pub restore_state_digest: String,
    pub semantics: String,
    pub forward_version_step: u64,
    pub compensation_units: u64,
    pub valid_from: i64,
    pub expires_at: i64,
    pub deadline_ms: i64,
    pub target_id: String,
    pub barrier_keys: BTreeMap<String, String>,
    pub evaluator_id: String,
    pub applicability_keys: BTreeMap<String, String>,
}
impl Contract {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 128 << 10 {
            return Err(refuse());
        }
        let v = strict_value(raw)?;
        schema(&v, "contract")?;
        Ok(serde_json::from_value(v)?)
    }
    pub fn digest(&self) -> Result<String> {
        digest("inverse-contract", &json!(self))
    }
    pub fn validate(&self, t: &Trust) -> Result<()> {
        t.validate()?;
        schema(&json!(self), "contract")?;
        let r = &t.registration;
        let saga = r.saga.as_ref().ok_or_else(refuse)?;
        let node = saga.node(&self.forward_operation_key)?;
        if canonical(&json!(self))?.len() > 128 << 10
            || r.profile != crate::saga_forward::PROFILE
            || self.registration_digest != r.digest()?
            || self.node_id != node.node_id
            || self.inverse_operation_key == self.forward_operation_key
            || saga
                .nodes
                .iter()
                .any(|n| n.operation_key == self.inverse_operation_key)
            || self.inverse_scope.resource != r.scope.resource
            || self.inverse_scope.conflict_domain != r.scope.conflict_domain
            || self.inverse_scope.action.id != ACTION
            || self.inverse_scope.action.id == r.scope.action.id
            || self.inverse_scope.action.version != "1.0"
            || self.compensation_units > r.compensation_units
            || self.valid_from < saga.valid_from
            || self.valid_from >= self.expires_at
            || !t.lineage.subjects.contains(&self.inverse_principal.subject)
        {
            return Err(refuse());
        }
        crate::grant_reference::fixed_https(&self.inverse_scope.audience)?;
        let ctd = crate::schema::verify_record(
            self.signed_inverse_ctd.as_bytes(),
            "ctd",
            &t.lineage.admission.registry_keys,
        )?;
        let p = &ctd.payload;
        let ps = parameter_schema();
        let pd = digest("parameter-schema", &ps)?;
        if record_digest(&ctd)? != self.inverse_scope.action.digest
            || p["action"] != ACTION
            || p["version"] != "1.0"
            || p["tenant"] != r.enrollment.tenant
            || p["ownership_epoch"] != r.ownership_epoch
            || p["gateway_audience"] != self.inverse_scope.audience
            || p["parameter_schema"] != ps
            || p["parameter_schema_digest"] != pd
            || p["rendering"]["parameter_schema_digest"] != pd
            || p["concurrency"]["conflict_domain"] != r.scope.conflict_domain
            || p["concurrency"]["predicate_descriptor"] != self.inverse_scope.predicate_descriptor
            || p["adapter_contract"] != self.inverse_scope.adapter_contract
            || !p["compensation"].is_null()
            || p["adapter_contract"]["level"] != "Level_A"
            || p["adapter_contract"]["guard_primitive"] != "FencingToken"
            || p["adapter_contract"]["completion_mode"] != "dispatch_bound"
            || p["adapter_contract"]["guard_scope"] != json!([r.scope.resource.id])
            || p["adapter_contract"]["idempotency"]["mode"] != "resource_key"
            || p["adapter_contract"]["idempotency"]["parameter"] != "kf_attempt_id"
            || p["adapter_contract"]["fence_parameter"] != "fence"
            || p["concurrency"]["predicate_descriptor"]["language"] != "kf-conjunction-v1"
            || p["concurrency"]["predicate_descriptor"]["clauses"]
                .as_array()
                .is_none_or(|all| {
                    all.len() != 1
                        || all[0]["kind"] != "version_eq"
                        || all[0]["resource"] != json!(r.scope.resource)
                })
        {
            return Err(refuse());
        }
        let barrier = crate::control_config::keys(&self.barrier_keys)?;
        let app = crate::control_config::keys(&self.applicability_keys)?;
        let a = &t.lineage.admission;
        let mut roles: Vec<&VerifyingKey> = a
            .proposal_keys
            .values()
            .chain(a.registry_keys.values())
            .chain(a.manifest_keys.values())
            .chain(a.evidence.values().flat_map(|e| e.keys.values()))
            .chain(t.lineage.admission_keys.values())
            .chain(t.lineage.grants.keys.values())
            .chain(t.lineage.outcome_keys.values())
            .chain(t.observer_keys.values())
            .collect();
        if barrier.values().any(|k| roles.contains(&k))
            || !r
                .hierarchy
                .as_ref()
                .ok_or_else(refuse)?
                .distinct(barrier.values().chain(app.values()))
        {
            return Err(refuse());
        }
        roles.extend(barrier.values());
        if app.values().any(|k| roles.contains(&k)) {
            return Err(refuse());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub registration_digest: String,
    pub root_id: String,
    pub saga_id: String,
    pub node_id: String,
    pub operation_key: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub receipt_digest: String,
    pub resource: Resource,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Barrier {
    pub contract_digest: String,
    pub forward: Forward,
    pub target_id: String,
    pub original_terminal: bool,
    pub no_late_commit: bool,
    pub observed_version: u64,
    pub valid_from: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    pub contract_digest: String,
    pub forward: Forward,
    pub barrier_digest: String,
    pub evaluator_id: String,
    pub inverse_operation_key: String,
    pub inverse_principal: Principal,
    pub parameters_digest: String,
    pub restore_state_digest: String,
    pub applicable: bool,
    pub valid_from: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub profile: String,
    pub kind: String,
    pub key_id: String,
    pub payload: Value,
    pub signature: String,
}
impl Statement {
    pub fn message(&self) -> Result<Vec<u8>> {
        let mut raw = format!("KedgeFlow:{PROFILE}\0").into_bytes();
        raw.extend(canonical(&json!({"profile":self.profile,"kind":self.kind,"key_id":self.key_id,"payload":self.payload}))?);
        Ok(raw)
    }
    pub fn digest(&self) -> Result<String> {
        digest("inverse-statement", &json!(self))
    }
    fn verify(&self, kind: &str, keys: &BTreeMap<String, String>) -> Result<()> {
        schema(&json!(self), kind)?;
        let keys = crate::control_config::keys(keys)?;
        let key = keys.get(&self.key_id).ok_or_else(refuse)?;
        let sig = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&self.signature)
                .map_err(|_| refuse())?,
        )
        .map_err(|_| refuse())?;
        key.verify_strict(&self.message()?, &sig)
            .map_err(|_| refuse())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub resource_id: String,
    pub expected_version: u64,
    pub forward_grant_digest: String,
    pub forward_attempt_id: String,
    pub restore_state_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub profile: String,
    pub forward: Bundle,
    pub barrier: Statement,
    pub applicability: Statement,
    pub parameters: Parameters,
}
impl Proof {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_PROOF {
            return Err(refuse());
        }
        let v = strict_value(raw)?;
        schema(&v, "proof")?;
        Bundle::decode(&serde_json::to_vec(&v["forward"])?)?;
        Ok(serde_json::from_value(v)?)
    }
    pub fn digest(&self) -> Result<String> {
        digest("inverse-qualification-proof", &json!(self))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub profile: String,
    pub contract_digest: String,
    pub proof_digest: String,
    pub forward: Forward,
    pub inverse_operation_key: String,
    pub parameters_digest: String,
    pub valid_until: i64,
    pub validated_at: i64,
    pub execution_authority: bool,
    pub fresh_admission_required: bool,
}
/// Historical proof verification at an explicit instant; never a grant or spend.
pub fn verify(c: &Contract, t: &Trust, p: &Proof, at: i64) -> Result<Verification> {
    c.validate(t)?;
    if canonical(&json!(p))?.len() > MAX_PROOF {
        return Err(refuse());
    }
    schema(&json!(p), "proof")?;
    let v = crate::reserved_lineage::verify(&p.forward, t)?;
    if v.budget_state != S::Committed
        || v.lineage.reported_status != "committed"
        || v.held_compensation < c.compensation_units
        || v.lineage.operation_key != c.forward_operation_key
    {
        return Err(refuse());
    }
    let r = &t.registration;
    let saga = r.saga.as_ref().ok_or_else(refuse)?;
    let outcomes = &p.forward.lineage.outcomes;
    let receipt = crate::schema::verify_record(
        outcomes.receipts.last().ok_or_else(refuse)?.as_bytes(),
        "receipt",
        &t.lineage.outcome_keys,
    )?;
    let committed_at = receipt.payload["event_time"].as_i64().ok_or_else(refuse)?;
    let deadline = committed_at
        .checked_add(c.deadline_ms)
        .ok_or_else(refuse)?
        .min(c.expires_at);
    let identity = Forward {
        registration_digest: r.digest()?,
        root_id: r.root_id.clone(),
        saga_id: saga.saga_id.clone(),
        node_id: c.node_id.clone(),
        operation_key: c.forward_operation_key.clone(),
        grant_digest: v.lineage.grant_digest,
        attempt_id: v.lineage.attempt_id,
        receipt_digest: record_digest(&receipt)?,
        resource: r.scope.resource.clone(),
    };
    p.barrier.verify("barrier", &c.barrier_keys)?;
    p.applicability
        .verify("applicability", &c.applicability_keys)?;
    let b: Barrier = serde_json::from_value(p.barrier.payload.clone())?;
    let a: Applicability = serde_json::from_value(p.applicability.payload.clone())?;
    let proposal = crate::schema::verify_record(
        p.forward.lineage.packet.proposal.as_bytes(),
        "proposal",
        &t.lineage.admission.proposal_keys,
    )?;
    let baseline = proposal.payload["baseline_state"]
        .as_array()
        .and_then(|all| {
            all.iter()
                .find(|b| b["resource"] == json!(identity.resource))
        })
        .ok_or_else(refuse)?;
    let prior_version = baseline["version"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(refuse)?;
    if c.inverse_scope.predicate_descriptor["clauses"][0]["expected_version"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        != Some(b.observed_version)
        || baseline["state_digest"] != c.restore_state_digest
        || prior_version.checked_add(c.forward_version_step) != Some(b.observed_version)
    {
        return Err(refuse());
    }
    let contract_digest = c.digest()?;
    let parameters_digest = digest("parameters", &json!(p.parameters))?;
    if p.forward.checkpoint.payload.captured_at > at
        || c.valid_from > at
        || at >= deadline
        || b.contract_digest != contract_digest
        || b.forward != identity
        || b.target_id != c.target_id
        || !b.original_terminal
        || !b.no_late_commit
        || b.valid_from < committed_at
        || b.valid_from < c.valid_from
        || b.valid_from > at
        || at >= b.expires_at
        || b.expires_at > deadline
        || a.contract_digest != contract_digest
        || a.forward != identity
        || a.barrier_digest != p.barrier.digest()?
        || a.evaluator_id != c.evaluator_id
        || !a.applicable
        || a.inverse_operation_key != c.inverse_operation_key
        || a.inverse_principal != c.inverse_principal
        || a.parameters_digest != parameters_digest
        || a.restore_state_digest != c.restore_state_digest
        || a.valid_from < b.valid_from
        || a.valid_from > at
        || at >= a.expires_at
        || a.expires_at > b.expires_at
        || p.parameters.resource_id != identity.resource.id
        || p.parameters.expected_version != b.observed_version
        || p.parameters.forward_grant_digest != identity.grant_digest
        || p.parameters.forward_attempt_id != identity.attempt_id
        || p.parameters.restore_state_digest != c.restore_state_digest
    {
        return Err(refuse());
    }
    Ok(Verification {
        profile: PROFILE.into(),
        contract_digest,
        proof_digest: p.digest()?,
        forward: identity,
        inverse_operation_key: c.inverse_operation_key.clone(),
        parameters_digest,
        valid_until: a.expires_at,
        validated_at: at,
        execution_authority: false,
        fresh_admission_required: true,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub profile: String,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub verification: Verification,
    pub proof: Proof,
}
impl Qualification {
    pub fn digest(&self) -> Result<String> {
        digest("inverse-qualification-record", &json!(self))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    profile: String,
    sequence: u64,
    record_digest: String,
}
#[derive(Serialize)]
pub struct Status {
    pub profile: String,
    pub qualification: Option<Verification>,
    pub within_validity_window: bool,
    pub live_revalidation_required: bool,
    pub budget_active: bool,
    pub execution_authority: bool,
    pub fresh_admission_required: bool,
}
/// Operator-owned proof retention. No target client, signer or execution port.
pub struct Qualifier {
    ledger: EtcdLedger,
    contract: Contract,
    trust: Trust,
    base: String,
}
impl Qualifier {
    pub fn new(ledger: EtcdLedger, contract: Contract, trust: Trust) -> Result<Self> {
        contract.validate(&trust)?;
        if ledger.namespace() != trust.namespace
            || ledger.reservation.as_deref() != Some(&trust.registration)
            || ledger.action_domain.as_ref().is_some_and(|s| {
                s.lane != crate::action_domain::Lane::Forward
                    || s.topology.inverse.scope != contract.inverse_scope
                    || s.topology.inverse.policy != contract.inverse_policy
            })
        {
            return Err(refuse());
        }
        let base = format!(
            "{}/inverse-contracts/{}",
            ledger.namespace(),
            contract.forward_operation_key
        );
        Ok(Self {
            ledger,
            contract,
            trust,
            base,
        })
    }
    pub(crate) fn marker(&self) -> Result<String> {
        let t = &self.trust.lineage;
        let encode = |keys: &BTreeMap<String, VerifyingKey>| {
            keys.iter()
                .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                .collect::<BTreeMap<_, _>>()
        };
        let mut marker = json!({"profile":PROFILE,"contract":self.contract,"trust_digest":digest("inverse-forward-trust",&json!({"registration":self.trust.registration.digest()?,"namespace":self.trust.namespace,"enforcement":crate::governance::trust_digest(&t.admission,&t.admission_keys,&t.grants.keys)?,"policy":t.policy,"subjects":t.subjects,"delegation_audience":t.delegation_audience,"workload":t.admission.proposal_workload_id,"scope":t.admission.required_scope,"max_proposal_age_ms":t.admission.max_proposal_age_ms,"outcome_keys":encode(&t.outcome_keys),"source_id":t.source_id,"observer_id":self.trust.observer_id,"observer_keys":encode(&self.trust.observer_keys)}))?});
        if let Some(s) = &self.ledger.action_domain {
            marker["paired_topology_digest"] = json!(s.topology.digest()?);
        }
        record(&marker)
    }
    fn operation_marker(&self) -> String {
        format!(
            "{}/inverse-operations/{}",
            self.ledger.namespace(),
            self.contract.inverse_operation_key
        )
    }
    fn record_key(&self, n: u64) -> String {
        format!("{}/records/{n:04}", self.base)
    }
    async fn commit(&self, mut compare: Vec<Value>, writes: Vec<Value>) -> Result<()> {
        let mut seen = BTreeSet::new();
        compare.retain(|v| seen.insert(v.to_string()));
        if compare.len() > 96
            || canonical(&json!({"compare":compare,"success":writes,"failure":[]}))?.len() > 1 << 20
        {
            return Err(refuse());
        }
        if !self.ledger.txn(compare, writes, vec![]).await?.succeeded {
            return Err(refuse());
        }
        Ok(())
    }
    pub async fn enroll(&self) -> Result<()> {
        let r = &self.trust.registration;
        let gate = self
            .ledger
            .reservation_gate_for(&r.scope.conflict_domain, true)
            .await?
            .ok_or_else(refuse)?;
        let now = self.ledger.authority_clock.now_ms();
        if now < self.contract.valid_from
            || now >= self.contract.expires_at
            || gate
                .state
                .allocations
                .get(&self.contract.forward_operation_key)
                .is_none_or(|a| a.state != S::Allocated || a.attempt_id.is_some())
        {
            return Err(refuse());
        }
        let mut compare = gate.compare;
        let marker = self.marker()?;
        let key = format!("{}/contract", self.base);
        let head = format!("{}/head", self.base);
        compare.extend([
            version_zero(&key),
            version_zero(&head),
            version_zero(&self.operation_marker()),
            version_zero(&format!(
                "{}/issuance/{}",
                self.ledger.namespace(),
                self.contract.forward_operation_key
            )),
        ]);
        for collection in [
            "admission",
            "admission-chain",
            "fence-allocation",
            "issuance",
        ] {
            compare.push(version_zero(&format!(
                "{}/{collection}/{}",
                self.ledger.namespace(),
                self.contract.inverse_operation_key
            )));
        }
        self.commit(
            compare,
            vec![
                put(&key, &marker),
                put(&self.operation_marker(), &marker),
                put(
                    &head,
                    &record(&Head {
                        profile: PROFILE.into(),
                        sequence: 0,
                        record_digest: digest("inverse-contract-genesis", &json!(marker))?,
                    })?,
                ),
            ],
        )
        .await
    }
    pub(crate) async fn retained_history(&self) -> Result<(Vec<Qualification>, Vec<Value>)> {
        let (records, _, compare) = self.retained().await?;
        Ok((records, compare))
    }
    async fn retained(&self) -> Result<(Vec<Qualification>, Head, Vec<Value>)> {
        let marker = self.marker()?;
        let mut compare = vec![];
        for key in [format!("{}/contract", self.base), self.operation_marker()] {
            let raw = self.ledger.read_key(&key).await?.ok_or_else(refuse)?;
            if raw != marker.as_bytes() {
                return Err(refuse());
            }
            compare.push(value_eq(&key, &marker));
        }
        let key = format!("{}/head", self.base);
        let raw = self.ledger.read_key(&key).await?.ok_or_else(refuse)?;
        if raw.len() > 2048 {
            return Err(refuse());
        }
        let head: Head = serde_json::from_value(strict_value(&raw)?)?;
        if head.profile != PROFILE || head.sequence > MAX_RECORDS {
            return Err(refuse());
        }
        compare.push(value_eq(
            &key,
            std::str::from_utf8(&raw).map_err(|_| refuse())?,
        ));
        let mut records = vec![];
        let mut previous = None;
        for n in 1..=head.sequence {
            let key = self.record_key(n);
            let raw = self.ledger.read_key(&key).await?.ok_or_else(refuse)?;
            if raw.len() > MAX_PROOF + 16384 {
                return Err(refuse());
            }
            let q: Qualification = serde_json::from_value(strict_value(&raw)?)?;
            if q.profile != PROFILE
                || q.sequence != n
                || q.previous_digest != previous
                || q.verification
                    != verify(
                        &self.contract,
                        &self.trust,
                        &q.proof,
                        q.verification.validated_at,
                    )?
            {
                return Err(refuse());
            }
            if records.last().is_some_and(|old: &Qualification| {
                old.verification.forward != q.verification.forward
                    || old.verification.validated_at > q.verification.validated_at
            }) {
                return Err(refuse());
            }
            previous = Some(q.digest()?);
            compare.push(value_eq(
                &key,
                std::str::from_utf8(&raw).map_err(|_| refuse())?,
            ));
            records.push(q);
        }
        if head.record_digest
            != previous.unwrap_or(digest("inverse-contract-genesis", &json!(marker))?)
        {
            return Err(refuse());
        }
        Ok((records, head, compare))
    }
    pub(crate) async fn native_proof_compares(&self, proof: &Proof) -> Result<Vec<Value>> {
        let mut compare = vec![];
        let r = &self.trust.registration;
        let mut gate = self
            .ledger
            .reservation_gate_for(&r.scope.conflict_domain, true)
            .await?
            .ok_or_else(refuse)?;
        if proof
            .forward
            .events
            .last()
            .is_none_or(|e| e.after != gate.state)
        {
            return Err(refuse());
        }
        self.ledger
            .saga_committed_operation(&mut gate, &self.contract.forward_operation_key)
            .await?;
        let auth = self
            .ledger
            .export_authorization(&self.contract.forward_operation_key)
            .await?;
        if auth.issuance != proof.forward.lineage.issuance
            || json!(auth.admission) != json!(proof.forward.lineage.admission)
            || json!(auth.packet) != json!(proof.forward.lineage.packet)
            || json!(auth.lease_authority) != json!(proof.forward.lineage.lease_authority)
        {
            return Err(refuse());
        }
        for phase in ["admission", "issuance"] {
            let key = self
                .ledger
                .lease_authority_key(&self.contract.forward_operation_key, phase);
            if let Some(binding) = auth
                .lease_authority
                .as_ref()
                .and_then(|all| all.iter().find(|b| b.phase == phase))
            {
                let raw = self.ledger.read_key(&key).await?.ok_or_else(refuse)?;
                if strict_value(&raw)? != json!(binding) {
                    return Err(refuse());
                }
                compare.push(value_eq(
                    &key,
                    std::str::from_utf8(&raw).map_err(|_| refuse())?,
                ));
            } else {
                compare.push(version_zero(&key));
            }
        }
        // Pin complete submitted budget history, not just an observer checkpoint.
        let base = crate::reservation_history::base(&self.ledger, r)?;
        let mut last = None;
        for e in &proof.forward.events {
            let key = format!("{base}/events/{:06}", e.sequence);
            let raw = self.ledger.read_key(&key).await?.ok_or_else(refuse)?;
            if strict_value(&raw)? != json!(e) {
                return Err(refuse());
            }
            compare.push(value_eq(
                &key,
                std::str::from_utf8(&raw).map_err(|_| refuse())?,
            ));
            last = Some(e);
        }
        let last = last.ok_or_else(refuse)?;
        let head_key = format!("{base}/head");
        let expected = record(
            &json!({"sequence":last.sequence,"digest":last.digest()?,"state_digest":digest("reservation-history-state",&json!(last.after))?}),
        )?;
        if self.ledger.read_key(&head_key).await?.as_deref() != Some(expected.as_bytes()) {
            return Err(refuse());
        }
        compare.push(value_eq(&head_key, &expected));
        compare.extend(gate.compare);
        Ok(compare)
    }
    pub(crate) async fn live_qualification(&self) -> Result<(Qualification, Vec<Value>)> {
        let (records, _, mut compare) = self.retained().await?;
        let q = records.last().ok_or_else(refuse)?.clone();
        let at = self.ledger.authority_clock.now_ms();
        verify(&self.contract, &self.trust, &q.proof, at)?;
        compare.extend(self.native_proof_compares(&q.proof).await?);
        let now = self.ledger.authority_clock.now_ms();
        if now < at || now >= q.verification.valid_until {
            return Err(refuse());
        }
        Ok((q, compare))
    }
    pub(crate) async fn historical_qualification(
        &self,
        digest: &str,
    ) -> Result<(Qualification, Vec<Value>)> {
        let (records, _, compare) = self.retained().await?;
        let q = records
            .into_iter()
            .find(|q| q.digest().is_ok_and(|d| d == digest))
            .ok_or_else(refuse)?;
        Ok((q, compare))
    }
    pub(crate) async fn begin_native_compensation(&self) -> Result<()> {
        let selected = self.ledger.action_domain.as_ref().ok_or_else(refuse)?;
        if selected.lane != crate::action_domain::Lane::Forward {
            return Err(refuse());
        }
        let (q, mut compare) = self.live_qualification().await?;
        if q.proof
            .forward
            .events
            .last()
            .ok_or_else(refuse)?
            .after
            .allocations
            .values()
            .any(|a| a.state == S::Unknown)
        {
            return Err(refuse());
        }
        let r = &self.trust.registration;
        compare.extend(self.ledger.action_domain_authority(
            &r.scope,
            &r.policy,
            r.ownership_epoch,
        )?);
        let key = crate::compensation_execution::mode_key(&self.ledger, r)?;
        let expected = record(
            &json!({"profile":crate::compensation_execution::PROFILE,"registration_digest":r.digest()?,"topology_digest":selected.topology.digest()?,"mode":"compensating"}),
        )?;
        let mut create = compare.clone();
        create.push(version_zero(&key));
        if self
            .ledger
            .txn(create, vec![put(&key, &expected)], vec![])
            .await?
            .succeeded
        {
            return Ok(());
        }
        compare.push(value_eq(&key, &expected));
        self.commit(compare, vec![get(&key)]).await
    }
    pub async fn qualify(&self, proof: Proof) -> Result<Verification> {
        let at = self.ledger.authority_clock.now_ms();
        let verified = verify(&self.contract, &self.trust, &proof, at)?;
        let (records, head, mut compare) = self.retained().await?;
        compare.extend(self.native_proof_compares(&proof).await?);
        // Check time once more after potentially slow reads; timestamps do not renew.
        let now = self.ledger.authority_clock.now_ms();
        if now < at || now >= verified.valid_until {
            return Err(refuse());
        }
        if let Some(old) = records.last() {
            if old.verification.forward != verified.forward
                || verified.validated_at < old.verification.validated_at
            {
                return Err(refuse());
            }
            if old.verification.proof_digest == verified.proof_digest {
                self.commit(compare, vec![get(&format!("{}/head", self.base))])
                    .await?;
                return Ok(old.verification.clone());
            }
        }
        if head.sequence >= MAX_RECORDS {
            return Err(refuse());
        }
        let q = Qualification {
            profile: PROFILE.into(),
            sequence: head.sequence + 1,
            previous_digest: records.last().map(Qualification::digest).transpose()?,
            verification: verified.clone(),
            proof,
        };
        let raw = record(&q)?;
        if raw.len() > MAX_PROOF + 16384 {
            return Err(refuse());
        }
        let key = self.record_key(q.sequence);
        compare.push(version_zero(&key));
        self.commit(
            compare,
            vec![
                put(&key, &raw),
                put(
                    &format!("{}/head", self.base),
                    &record(&Head {
                        profile: PROFILE.into(),
                        sequence: q.sequence,
                        record_digest: q.digest()?,
                    })?,
                ),
            ],
        )
        .await?;
        Ok(verified)
    }
    pub async fn status(&self) -> Result<Status> {
        let (records, _, mut compare) = self.retained().await?;
        let r = &self.trust.registration;
        let gate = self
            .ledger
            .reservation_gate_for(&r.scope.conflict_domain, false)
            .await?
            .ok_or_else(refuse)?;
        let now = self.ledger.authority_clock.now_ms();
        let current = records.last().is_some_and(|q| {
            now >= q.verification.validated_at && now < q.verification.valid_until
        }) && gate.state.active;
        compare.extend(gate.compare);
        self.commit(compare, vec![get(&format!("{}/head", self.base))])
            .await?;
        Ok(Status {
            profile: PROFILE.into(),
            qualification: records.last().map(|q| q.verification.clone()),
            within_validity_window: current,
            live_revalidation_required: true,
            budget_active: gate.state.active,
            execution_authority: false,
            fresh_admission_required: true,
        })
    }
    pub async fn history(&self) -> Result<Vec<Qualification>> {
        let (records, _, compare) = self.retained().await?;
        self.commit(compare, vec![get(&format!("{}/head", self.base))])
            .await?;
        Ok(records)
    }
}
