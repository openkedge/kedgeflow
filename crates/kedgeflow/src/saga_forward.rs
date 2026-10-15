//! Explicit native forward-DAG authority. Inverses remain unsupported.
use crate::{
    contracts::{Grant, canonical, digest, record_digest, strict_value},
    coordination::{Allocation, ReservationScope, ReservationSnapshot, ReservationState as S},
    error::{Error, Result},
    hierarchical_leaf::Principal,
    ledger::{EtcdLedger, key_part, record, value_eq, version_zero},
    recovery::{Candidate, verify_outcomes},
    reserved_leaf::{Gate, Registration},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub const PROFILE: &str = "KF-SAGA-FORWARD-0.1-draft";
pub const LINEAGE_PROFILE: &str = "KF-SAGA-FORWARD-LINEAGE-0.1-draft";
fn refuse() -> Error {
    Error::Refused("native forward saga identity, dependency or authority refused".into())
}
pub(crate) fn validate(v: &Value, kind: &str) -> Result<()> {
    static CONFIG: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    static BINDING: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let slot = match kind {
        "config" => &CONFIG,
        "binding" => &BINDING,
        _ => return Err(refuse()),
    };
    let s = slot.get_or_init(|| {
        let mut v: Value = serde_json::from_str(include_str!(
            "../../../spec/drafts/saga-forward-v0.1.schema.json"
        ))
        .expect("saga forward schema");
        v["$ref"] = json!(format!("#/$defs/{kind}"));
        crate::schema::compile(&v).expect("valid saga forward schema")
    });
    if s.is_valid(v) { Ok(()) } else { Err(refuse()) }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub node_id: String,
    pub operation_key: String,
    pub principal: Principal,
    pub depends_on: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub profile: String,
    pub saga_id: String,
    pub valid_from: i64,
    pub expires_at: i64,
    pub nodes: Vec<Node>,
    pub outcome_keys: BTreeMap<String, String>,
    pub source_id: String,
}
pub(crate) fn deserialize_optional<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Plan>, D::Error> {
    let v = crate::contracts::strict_deserialize(d)?;
    validate(&v, "config").map_err(serde::de::Error::custom)?;
    serde_json::from_value(v)
        .map(Some)
        .map_err(serde::de::Error::custom)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub saga_id: String,
    pub node_id: String,
    pub plan_digest: String,
}
pub(crate) fn deserialize_binding<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Binding>, D::Error> {
    Binding::deserialize(d).map(Some)
}
impl Plan {
    pub fn digest(&self) -> Result<String> {
        digest("saga-forward-plan", &json!(self))
    }
    pub(crate) fn keys(&self) -> Result<BTreeMap<String, VerifyingKey>> {
        crate::control_config::keys(&self.outcome_keys)
    }
    pub(crate) fn distinct<'a>(&self, keys: impl IntoIterator<Item = &'a VerifyingKey>) -> bool {
        let keys: Vec<_> = keys.into_iter().collect();
        self.keys()
            .is_ok_and(|ours| ours.values().all(|k| !keys.contains(&k)))
    }
    pub(crate) fn node(&self, op: &str) -> Result<&Node> {
        self.nodes
            .iter()
            .find(|n| n.operation_key == op)
            .ok_or_else(refuse)
    }
    pub(crate) fn binding(&self, op: &str) -> Result<Binding> {
        let n = self.node(op)?;
        Ok(Binding {
            saga_id: self.saga_id.clone(),
            node_id: n.node_id.clone(),
            plan_digest: self.digest()?,
        })
    }
    pub(crate) fn grant(&self, g: &Grant) -> Result<()> {
        if g.issued_at < self.valid_from
            || g.valid_from < self.valid_from
            || g.expires_at > self.expires_at
            || !self
                .nodes
                .iter()
                .any(|n| n.principal == Principal::from_grant(g))
        {
            return Err(refuse());
        }
        Ok(())
    }
    fn current(&self, now: i64) -> Result<()> {
        if now < self.valid_from || now >= self.expires_at {
            Err(refuse())
        } else {
            Ok(())
        }
    }
    pub(crate) fn allocations(&self, r: &Registration) -> Result<BTreeMap<String, Allocation>> {
        let h = r.hierarchy.as_ref().ok_or_else(refuse)?;
        let mut all = h.initial()?;
        for n in &self.nodes {
            let a = h
                .assignments
                .iter()
                .find(|a| a.principal == n.principal)
                .ok_or_else(refuse)?;
            let allocation = Allocation {
                operation_digest: n.operation_key.clone(),
                parent: Some(a.parent_grant_digest.clone()),
                scope: ReservationScope {
                    actions: BTreeSet::from([r.scope.action.id.clone()]),
                    resources: BTreeSet::from([r.scope.resource.id.clone()]),
                },
                forward: r.forward_units,
                compensation: r.compensation_units,
                state: S::Allocated,
                attempt_id: None,
            };
            if all.insert(n.operation_key.clone(), allocation).is_some() {
                return Err(refuse());
            }
        }
        Ok(all)
    }
    pub(crate) fn validate(&self, r: &Registration) -> Result<()> {
        validate(&json!(self), "config")?;
        if self.valid_from >= self.expires_at
            || canonical(&json!(self))?.len() > 64 << 10
            || !self.distinct(crate::control_config::keys(&r.issuer_keys)?.values())
        {
            return Err(refuse());
        }
        let h = r.hierarchy.as_ref().ok_or_else(refuse)?;
        if !h.distinct(self.keys()?.values()) {
            return Err(refuse());
        }
        let nodes: BTreeMap<_, _> = self.nodes.iter().map(|n| (n.node_id.as_str(), n)).collect();
        let grants: BTreeMap<_, _> = h
            .grants
            .iter()
            .map(|g| g.digest().map(|d| (d, g)))
            .collect::<Result<_>>()?;
        if nodes.len() != self.nodes.len()
            || self
                .nodes
                .iter()
                .map(|n| &n.operation_key)
                .collect::<BTreeSet<_>>()
                .len()
                != self.nodes.len()
        {
            return Err(refuse());
        }
        for n in &self.nodes {
            if n.depends_on.iter().collect::<BTreeSet<_>>().len() != n.depends_on.len() {
                return Err(refuse());
            }
            let mut pending = n.depends_on.clone();
            let mut seen = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if id == n.node_id {
                    return Err(refuse());
                }
                let parent = nodes.get(id.as_str()).ok_or_else(refuse)?;
                if seen.insert(id) {
                    pending.extend(parent.depends_on.clone());
                }
            }
            let parent = &h
                .assignments
                .iter()
                .find(|a| a.principal == n.principal)
                .ok_or_else(refuse)?
                .parent_grant_digest;
            let p = &grants.get(parent).ok_or_else(refuse)?.payload;
            if self.valid_from < p.valid_from || self.expires_at > p.expires_at {
                return Err(refuse());
            }
        }
        ReservationSnapshot {
            profile: crate::coordination::PROFILE.into(),
            enrollment: r.enrollment.clone(),
            active: true,
            execution_authority: false,
            allocations: self.allocations(r)?,
        }
        .validate()
    }
    pub(crate) fn dependencies(&self, state: &ReservationSnapshot, op: &str) -> Result<()> {
        for id in &self.node(op)?.depends_on {
            let n = self
                .nodes
                .iter()
                .find(|n| &n.node_id == id)
                .ok_or_else(refuse)?;
            if state
                .allocations
                .get(&n.operation_key)
                .is_none_or(|a| a.state != S::Committed)
            {
                return Err(refuse());
            }
        }
        Ok(())
    }
}
pub(crate) fn plan_key(ledger: &EtcdLedger, r: &Registration) -> String {
    format!(
        "{}/saga-forward-plans/{}",
        ledger.namespace(),
        key_part(&r.root_id)
    )
}
impl EtcdLedger {
    pub(crate) async fn saga_dependencies(
        &self,
        gate: &mut Gate,
        op: &str,
        principal: &Principal,
    ) -> Result<()> {
        let Some(plan) = gate.r.saga.clone() else {
            return Ok(());
        };
        if self.action_domain.is_some() {
            gate.compare.push(crate::ledger::version_zero(
                &crate::compensation_execution::mode_key(self, &gate.r)?,
            ));
        }
        plan.current(self.authority_clock.now_ms())?;
        if plan.node(op)?.principal != *principal {
            return Err(refuse());
        }
        plan.dependencies(&gate.state, op)?;
        for id in &plan.node(op)?.depends_on {
            let node = plan
                .nodes
                .iter()
                .find(|n| &n.node_id == id)
                .ok_or_else(refuse)?;
            self.saga_committed_operation(gate, &node.operation_key)
                .await?;
        }
        let mut seen = BTreeSet::new();
        gate.compare.retain(|v| seen.insert(v.to_string()));
        if gate.compare.len() > 88 + usize::from(self.action_domain.is_some())
            || canonical(&json!(gate.compare))?.len() > 512 << 10
        {
            return Err(refuse());
        }
        Ok(())
    }
    /// Original committed proof comparisons shared by live DAG authority and
    /// nonauthorizing inverse qualification. Historical proofs may outlive grants.
    pub(crate) async fn saga_committed_operation(&self, gate: &mut Gate, op: &str) -> Result<()> {
        let plan = gate.r.saga.clone().ok_or_else(refuse)?;
        let node = plan.node(op)?;
        let (issued, admission) = self
            .retained_operation(&node.operation_key)
            .await?
            .ok_or_else(refuse)?;
        let g = crate::contracts::GrantVerifier {
            keys: crate::control_config::keys(&gate.r.issuer_keys)?,
            audience: gate.r.scope.audience.clone(),
        }
        .verify_retained(issued.signed_grant.as_bytes())?;
        let (dependency, binding) = self
            .reservation_bound(&g.grant, &g.digest, false)
            .await?
            .ok_or_else(refuse)?;
        if binding.payload.operation_key != node.operation_key
            || Principal::from_grant(&g.grant) != node.principal
        {
            return Err(refuse());
        }
        let a = dependency
            .state
            .allocations
            .get(&node.operation_key)
            .ok_or_else(refuse)?;
        if a.state != S::Committed {
            return Err(refuse());
        }
        let id = a.attempt_id.as_ref().ok_or_else(refuse)?;
        let candidate = Candidate {
            grant: g.grant.clone(),
            attempt_id: id.clone(),
        };
        let s = self.recovery_snapshot(&candidate).await?;
        s.context.validate(&g.grant, &g.digest)?;
        let head = s.head.as_ref().ok_or_else(refuse)?;
        let outcomes = self.export_outcomes(&candidate).await?;
        let v = verify_outcomes(
            &outcomes,
            &crate::contracts::GrantVerifier {
                keys: crate::control_config::keys(&gate.r.issuer_keys)?,
                audience: gate.r.scope.audience.clone(),
            },
            &plan.keys()?,
            &plan.source_id,
        )?;
        let receipt = crate::schema::verify_record(
            outcomes.receipts.last().ok_or_else(refuse)?.as_bytes(),
            "receipt",
            &plan.keys()?,
        )?;
        if v.reported_status != "committed"
            || record_digest(&receipt)? != head.receipt_digest
            || head.state != "committed"
        {
            return Err(refuse());
        }
        // Pin every original proof read to the successor authority CAS.
        // A head digest alone cannot protect an older receipt from deletion.
        let base = self.attempt(&g.grant, id);
        let mut proofs = vec![
            (
                format!("{}/admission/{}", self.namespace(), node.operation_key),
                json!(admission.record),
            ),
            (
                format!(
                    "{}/admission-chain/{}",
                    self.namespace(),
                    node.operation_key
                ),
                json!({"admission_key":node.operation_key,"certificate_digest":admission.record.certificate_digest,"packet":admission.packet}),
            ),
        ];
        for raw in &outcomes.receipts {
            let e: crate::contracts::Envelope =
                serde_json::from_value(strict_value(raw.as_bytes())?)?;
            let key = format!("{base}/receipts/{}", record_digest(&e)?);
            let retained = self.read_key(&key).await?.ok_or_else(refuse)?;
            if retained != raw.as_bytes() {
                return Err(refuse());
            }
            gate.compare.push(value_eq(&key, raw));
        }
        for (ed, body) in &outcomes.evidence {
            proofs.push((format!("{base}/reports/evidence/{ed}"), body.clone()));
        }
        for phase in ["claimed", "dispatch_authorized"] {
            let event = outcomes
                .journal
                .iter()
                .find(|v| v["phase"] == phase)
                .ok_or_else(refuse)?;
            crate::recovery::validate(event)?;
            if event["root_id"] != g.grant.root_id
                || event["grant_digest"] != g.digest
                || event["attempt_id"] != *id
            {
                return Err(refuse());
            }
        }
        for event in &outcomes.journal {
            let phase = event["phase"].as_str().ok_or_else(refuse)?;
            proofs.push((
                crate::recovery::journal_key(self, &g.grant, id, phase),
                event.clone(),
            ));
        }
        let evidence_key = crate::recovery::evidence_key(self, &g.grant, id);
        match &s.evidence {
            Some(v) => proofs.push((evidence_key, v.clone())),
            None => gate.compare.push(version_zero(&evidence_key)),
        }
        for (key, expected) in proofs {
            let raw = self.read_key(&key).await?.ok_or_else(refuse)?;
            if strict_value(&raw)? != expected {
                return Err(refuse());
            }
            gate.compare.push(value_eq(
                &key,
                std::str::from_utf8(&raw).map_err(|_| refuse())?,
            ));
        }
        let mut root = crate::ledger::expected_root(&g.grant);
        root.status = "claimed".into();
        gate.compare.extend([
            value_eq(&self.root(&g.grant), &record(&root)?),
            value_eq(&self.grant_key(&g.grant), &g.digest),
            value_eq(&self.nonce(&g.grant), id),
        ]);
        gate.compare.extend(dependency.compare);
        gate.compare.extend([
            value_eq(
                &format!("{}/issuance/{}", self.namespace(), node.operation_key),
                &record(&issued)?,
            ),
            value_eq(&self.attempt(&g.grant, id), &record(&s.attempt)?),
            value_eq(&self.outbox(&g.grant, id), &s.outbox),
            value_eq(
                &crate::recovery::context_key(self, &g.grant, id),
                &s.context_raw,
            ),
            value_eq(
                &format!("{}/receipt-head", self.attempt(&g.grant, id)),
                s.head_raw.as_ref().ok_or_else(refuse)?,
            ),
        ]);
        Ok(())
    }
    pub(crate) async fn saga_admission(
        &self,
        p: &crate::policy::PreparedAdmission,
        now: i64,
    ) -> Result<Vec<Value>> {
        let key = crate::reserved_leaf::required_key(self, &p.context.conflict_domain);
        let raw = self.read_key(&key).await?;
        let required = raw
            .as_ref()
            .map(|r| strict_value(r))
            .transpose()?
            .is_some_and(|v| v["profile"] == PROFILE);
        if self.reservation.as_ref().is_none_or(|r| r.saga.is_none()) {
            if required {
                return Err(refuse());
            }
            return Ok(vec![match raw {
                None => version_zero(&key),
                Some(v) => value_eq(&key, std::str::from_utf8(&v).map_err(|_| refuse())?),
            }]);
        }
        let mut gate = self
            .reservation_gate_for(&p.context.conflict_domain, true)
            .await?
            .ok_or_else(refuse)?;
        let r = &gate.r;
        if r.scope != p.control_scope
            || r.enrollment.tenant != p.context.tenant
            || r.policy != p.context.policy
            || r.ownership_epoch != p.context.ownership_epoch
        {
            return Err(refuse());
        }
        let plan = r.saga.as_ref().ok_or_else(refuse)?;
        plan.current(now)?;
        if p.expires_at > plan.expires_at || p.admitted_at < plan.valid_from {
            return Err(refuse());
        }
        self.saga_dependencies(
            &mut gate,
            &p.key,
            &Principal {
                subject: p.context.subject.clone(),
                workload_id: p.context.workload_id.clone(),
            },
        )
        .await?;
        Ok(gate.compare)
    }
}
