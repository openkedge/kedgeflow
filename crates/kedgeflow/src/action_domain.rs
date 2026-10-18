//! Explicit static pairing. This control prerequisite grants no inverse authority.
use crate::{
    contracts::{Policy, canonical, digest, strict_value},
    error::{Error, Result},
    governance::{ControlRegistration, EnforcementScope},
    ledger::{EtcdLedger, get, key_part, put, range_kv, record, value_eq, version_zero},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PROFILE: &str = "KF-PAIRED-ACTION-DOMAIN-0.1-draft";
const MAX_TOPOLOGY: usize = 64 << 10;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Forward,
    Inverse,
}
impl Lane {
    fn name(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Inverse => "inverse",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub profile: String,
    pub forward: ControlRegistration,
    pub inverse: ControlRegistration,
}
impl Topology {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_TOPOLOGY {
            return Err(Error::Invalid("paired topology exceeds bound".into()));
        }
        let t: Self = serde_json::from_value(strict_value(raw)?)?;
        t.validate()?;
        Ok(t)
    }
    pub fn validate(&self) -> Result<()> {
        let raw = serde_json::to_value(self)?;
        static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
        let schema = SCHEMA.get_or_init(|| {
            let raw: Value = serde_json::from_str(include_str!(
                "../../../spec/drafts/paired-action-domain-v0.1.schema.json"
            ))
            .expect("embedded paired-domain schema");
            crate::schema::compile(&raw).expect("valid embedded paired-domain schema")
        });
        if canonical(&raw)?.len() > MAX_TOPOLOGY
            || !schema.is_valid(&raw)
            || self.forward.tenant != self.inverse.tenant
            || self.forward.scope.conflict_domain != self.inverse.scope.conflict_domain
            || self.forward.scope.resource != self.inverse.scope.resource
            || self.forward.ownership_epoch != self.inverse.ownership_epoch
            || self.forward.scope.action.id == self.inverse.scope.action.id
        {
            return Err(Error::Invalid("invalid paired physical domain".into()));
        }
        for r in [&self.forward, &self.inverse] {
            crate::contracts::validate_adapter_contract(
                &r.scope.adapter_contract,
                &r.scope.resource,
                None,
            )?;
            let predicate = &r.scope.predicate_descriptor;
            if predicate["language"] != "kf-conjunction-v1"
                || predicate["clauses"].as_array().is_none_or(|clauses| {
                    clauses.len() != 1
                        || clauses[0]["kind"] != "version_eq"
                        || clauses[0]["resource"] != json!(r.scope.resource)
                })
            {
                return Err(Error::Invalid(
                    "paired lane requires one exact resource predicate".into(),
                ));
            }
            for (id, key) in &r.issuer_keys {
                let bytes: [u8; 32] = hex::decode(key)
                    .map_err(|_| Error::Invalid("paired issuer key hex".into()))?
                    .try_into()
                    .map_err(|_| Error::Invalid("paired issuer key length".into()))?;
                if id.is_empty()
                    || id.len() > 512
                    || ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_err()
                {
                    return Err(Error::Invalid("paired issuer key invalid".into()));
                }
            }
            crate::governance::acknowledgement_keys(&r.acknowledger)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("paired-action-domain", &serde_json::to_value(self)?)
    }
    fn base(&self, ledger: &EtcdLedger) -> String {
        format!(
            "{}/domains/{}",
            ledger.namespace(),
            key_part(&self.forward.scope.conflict_domain)
        )
    }
    pub fn registration(&self, lane: Lane) -> &ControlRegistration {
        match lane {
            Lane::Forward => &self.forward,
            Lane::Inverse => &self.inverse,
        }
    }
    /// Privileged protected enrollment, never a request-controlled operation.
    pub(crate) fn initial_writes(&self, ledger: &EtcdLedger) -> Result<Vec<Value>> {
        self.validate()?;
        let base = self.base(ledger);
        Ok(vec![
            put(&format!("{base}/paired-topology"), &record(self)?),
            put(&format!("{base}/control-required"), PROFILE),
        ])
    }
    pub async fn enroll(&self, ledger: &EtcdLedger) -> Result<()> {
        self.validate()?;
        if ledger.action_domain.is_some() {
            return Err(Error::Invalid(
                "enroll using the unselected operator ledger".into(),
            ));
        }
        let base = self.base(ledger);
        let key = format!("{base}/paired-topology");
        let sentinel = format!("{base}/control-required");
        let stop = format!("{base}/paired-stop");
        let encoded = record(self)?;
        let checks = [
            "policy",
            "ownership",
            "reservation-required",
            "control/publish_policy",
            "control/register_descriptor",
            "control/installation",
            "control/ack",
            "control/history/head",
            "revocations/domain",
        ];
        let mut compare = checks
            .iter()
            .map(|s| version_zero(&format!("{base}/{s}")))
            .collect::<Vec<_>>();
        compare.push(version_zero(&stop));
        let mut create = compare.clone();
        create.extend([version_zero(&key), version_zero(&sentinel)]);
        let t = ledger
            .txn(
                create,
                vec![put(&key, &encoded), put(&sentinel, PROFILE)],
                vec![],
            )
            .await?;
        if t.succeeded {
            return Ok(());
        }
        compare.extend([value_eq(&key, &encoded), value_eq(&sentinel, PROFILE)]);
        if !ledger.txn(compare, vec![], vec![]).await?.succeeded {
            return Err(Error::Refused(
                "paired enrollment conflicts with retained state".into(),
            ));
        }
        Ok(())
    }
    /// Permanent whole-physical-domain stop. Historical recovery stays readable.
    pub async fn stop(&self, ledger: &EtcdLedger) -> Result<()> {
        self.validate()?;
        let base = self.base(ledger);
        let stop = format!("{base}/paired-stop");
        let encoded = self.digest()?;
        let mut create = self.compares(ledger)?;
        create.push(version_zero(&stop));
        if ledger
            .txn(create, vec![put(&stop, &encoded)], vec![])
            .await?
            .succeeded
        {
            return Ok(());
        }
        let mut duplicate = self.compares(ledger)?;
        duplicate.push(value_eq(&stop, &encoded));
        if !ledger.txn(duplicate, vec![], vec![]).await?.succeeded {
            return Err(Error::Refused("paired stop topology mismatch".into()));
        }
        Ok(())
    }
    pub async fn status(&self, ledger: &EtcdLedger) -> Result<Value> {
        self.validate()?;
        let base = self.base(ledger);
        let t = ledger
            .txn(
                self.compares(ledger)?,
                vec![get(&format!("{base}/paired-stop"))],
                vec![],
            )
            .await?;
        if !t.succeeded || t.responses.len() != 1 {
            return Err(Error::Refused("paired topology absent or changed".into()));
        }
        let stopped = match range_kv(&t.responses[0])? {
            None => false,
            Some(kv) if kv.value == self.digest()?.as_bytes() => true,
            Some(_) => return Err(Error::Refused("corrupt paired stop marker".into())),
        };
        Ok(
            json!({"profile":PROFILE,"topology_digest":self.digest()?,"stopped":stopped,"execution_authority":false,"inverse_execution_available":false}),
        )
    }
    fn compares(&self, ledger: &EtcdLedger) -> Result<Vec<Value>> {
        let base = self.base(ledger);
        Ok(vec![
            value_eq(&format!("{base}/paired-topology"), &record(self)?),
            value_eq(&format!("{base}/control-required"), PROFILE),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub topology: Topology,
    pub lane: Lane,
}
impl Selection {
    pub fn registration(&self) -> &ControlRegistration {
        self.topology.registration(self.lane)
    }
    pub(crate) fn base(&self, ledger: &EtcdLedger) -> String {
        format!("{}/paired/{}", self.topology.base(ledger), self.lane.name())
    }
    pub(crate) fn accepts_reservation(&self, r: &crate::reserved_leaf::Registration) -> bool {
        let c = self.registration();
        self.lane == Lane::Forward
            && r.enrollment.tenant == c.tenant
            && r.scope == c.scope
            && r.policy == c.policy
            && r.ownership_epoch == c.ownership_epoch
            && crate::control_config::keys(&r.issuer_keys).is_ok_and(|keys| {
                keys.iter()
                    .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    == c.issuer_keys
            })
    }
}
/// Omission preserves old profiles; an explicit null never selects a profile.
pub fn deserialize_selection<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Selection>, D::Error> {
    let s = Selection::deserialize(deserializer)?;
    s.topology.validate().map_err(serde::de::Error::custom)?;
    Ok(Some(s))
}
impl EtcdLedger {
    pub fn with_action_domain(mut self, selection: Selection) -> Result<Self> {
        selection.topology.validate()?;
        if self
            .action_domain
            .as_ref()
            .is_some_and(|s| s.as_ref() != &selection)
            || self
                .reservation
                .as_ref()
                .is_some_and(|r| !selection.accepts_reservation(r))
            || self
                .required_trust_digest
                .as_ref()
                .is_some_and(|d| d != &selection.registration().trust_digest)
        {
            return Err(Error::Invalid("paired lane configuration conflict".into()));
        }
        self.require_control = true;
        self.required_trust_digest = Some(selection.registration().trust_digest.clone());
        self.action_domain = Some(std::sync::Arc::new(selection));
        Ok(self)
    }
    pub(crate) fn domain_base(&self, domain: &str) -> String {
        match &self.action_domain {
            Some(s) => s.base(self),
            None => format!("{}/domains/{}", self.prefix, key_part(domain)),
        }
    }
    pub(crate) fn action_domain_scope(&self, domain: &str) -> Result<()> {
        if self
            .action_domain
            .as_ref()
            .is_some_and(|s| s.registration().scope.conflict_domain != domain)
        {
            return Err(Error::Refused(
                "physical domain differs from selected lane".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn action_domain_compares(&self) -> Result<Vec<Value>> {
        self.action_domain
            .as_ref()
            .map_or(Ok(vec![]), |s| s.topology.compares(self))
    }
    pub(crate) fn action_domain_registration(&self, r: &ControlRegistration) -> Result<()> {
        if self
            .action_domain
            .as_ref()
            .is_some_and(|s| s.registration() != r)
        {
            return Err(Error::Refused(
                "control differs from protected paired lane".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn action_domain_authority(
        &self,
        scope: &EnforcementScope,
        policy: &Policy,
        ownership: u64,
    ) -> Result<Vec<Value>> {
        if scope.action.id == crate::compensation::ACTION && self.inverse_execution.is_none() {
            return Err(Error::Refused("inverse execution profile required".into()));
        }
        let Some(s) = &self.action_domain else {
            return Ok(vec![]);
        };
        let r = s.registration();
        // Installing the inverse lane must not open an ordinary inverse port.
        if (s.lane == Lane::Inverse && self.inverse_execution.is_none())
            || &r.scope != scope
            || &r.policy != policy
            || r.ownership_epoch != ownership
        {
            return Err(Error::Refused(
                "paired lane has no matching execution authority".into(),
            ));
        }
        Ok(vec![version_zero(&format!(
            "{}/paired-stop",
            s.topology.base(self)
        ))])
    }
}
