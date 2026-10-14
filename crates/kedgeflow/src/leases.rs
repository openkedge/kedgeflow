//! Exact-proposal static caches. No executable nonce, allowance or credential.
use crate::{
    admission::{AdmissionPacket, AdmissionTrust, StoredAdmissionPacket, VerifiedAdmissionInputs},
    auth::Identity,
    clock::Clock,
    contracts::{Subject, canonical, digest, record_digest},
    error::{Error, Result},
    governance::EnforcementScope,
    ledger::{EtcdLedger, get, key_part, put, range_kv, record, value_eq, version_zero},
    policy::AdmissionController,
    schema::verify_record,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub const PROFILE: &str = "KF-STATIC-LEASE-HTTP-0.1-draft";
fn refuse() -> Error {
    Error::Refused("static lease binding, membership or freshness refused".into())
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRegistration {
    pub keys: BTreeMap<String, String>,
    pub max_lifetime_ms: i64,
    pub jit_max_age_ms: i64,
}
impl LeaseRegistration {
    pub fn trust(&self) -> Result<LeaseTrust> {
        Ok(LeaseTrust {
            keys: crate::control_config::keys(&self.keys)?,
            max_lifetime_ms: self.max_lifetime_ms,
            jit_max_age_ms: self.jit_max_age_ms,
        })
    }
}
#[derive(Clone)]
pub struct LeaseTrust {
    pub keys: BTreeMap<String, VerifyingKey>,
    pub max_lifetime_ms: i64,
    pub jit_max_age_ms: i64,
}
impl LeaseTrust {
    pub(crate) fn binding(&self) -> Value {
        let keys: BTreeMap<_, _> = self
            .keys
            .iter()
            .map(|(id, key)| (id, hex::encode(key.as_bytes())))
            .collect();
        json!({"profile":PROFILE,"keys":keys,"max_lifetime_ms":self.max_lifetime_ms,"jit_max_age_ms":self.jit_max_age_ms})
    }
    pub(crate) fn validate(&self, trust: &AdmissionTrust) -> Result<()> {
        if self.keys.is_empty()
            || self.keys.len() > 64
            || self.keys.keys().any(String::is_empty)
            || !(1..=300000).contains(&self.max_lifetime_ms)
            || !(1..=300000).contains(&self.jit_max_age_ms)
            || !trust
                .evidence
                .values()
                .any(|r| r.obligation.stage == "static")
            || !trust.evidence.values().any(|r| r.obligation.stage == "jit")
        {
            return Err(refuse());
        }
        let inputs = trust
            .proposal_keys
            .values()
            .chain(trust.registry_keys.values())
            .chain(trust.manifest_keys.values())
            .chain(trust.evidence.values().flat_map(|r| r.keys.values()));
        if inputs
            .into_iter()
            .any(|key| self.keys.values().any(|lease| lease == key))
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        raw: &[u8],
        inputs: &VerifiedAdmissionInputs,
        now: i64,
    ) -> Result<LeaseUse> {
        let signed = verify_record(raw, "lease", &self.keys)?;
        let p = &signed.payload;
        let c = &inputs.context;
        let issued = p["issued_at"].as_i64().ok_or_else(refuse)?;
        let expires = p["expires_at"].as_i64().ok_or_else(refuse)?;
        let proposal: Value = crate::contracts::strict_value(inputs.packet.proposal.as_bytes())?;
        let static_discharges = static_discharges(inputs)?;
        let pending: Vec<_> = c
            .obligations
            .iter()
            .filter(|(_, o)| o.stage == "jit")
            .map(|(id, _)| id)
            .collect();
        let lid = p["lid"].as_str().ok_or_else(refuse)?;
        if p["proposal_digest"] != c.proposal_digest
            || p["delegation_digest"] != c.delegation_digest
            || p["subject"] != json!(c.subject)
            || p["workload_id"] != c.workload_id
            || p["policy"] != json!(c.policy)
            || p["descriptor_digest"] != c.descriptor_digest
            || p["ownership_epoch"] != c.ownership_epoch
            || p["execution_authority"] != false
            || p["static_discharges"] != json!(static_discharges)
            || p["pending_jit_obligations"] != json!(pending)
            || !lid
                .strip_prefix("kf-lease:")
                .is_some_and(crate::grant_reference::valid_reference)
            || issued
                < proposal["payload"]["created_at"]
                    .as_i64()
                    .ok_or_else(refuse)?
            || issued > now
            || expires <= now
            || expires > inputs.static_valid_until
            || expires
                .checked_sub(issued)
                .is_none_or(|d| d <= 0 || d > self.max_lifetime_ms)
        {
            return Err(refuse());
        }
        for (id, o) in &c.obligations {
            if o.stage == "jit"
                && inputs
                    .witnesses
                    .get(id)
                    .is_some_and(|w| w.observed_at < issued)
            {
                return Err(refuse());
            }
        }
        let key_id = signed.key_id.clone();
        let public_key = hex::encode(self.keys.get(&key_id).ok_or_else(refuse)?.as_bytes());
        Ok(LeaseUse {
            key_id,
            public_key,
            lid: lid.into(),
            digest: record_digest(&signed)?,
            raw: String::from_utf8(canonical(&serde_json::to_value(signed)?)?)
                .map_err(|_| refuse())?,
            expires_at: expires,
        })
    }
}
fn static_discharges(inputs: &VerifiedAdmissionInputs) -> Result<Vec<Value>> {
    inputs.context.obligations.iter().filter(|(_,o)|o.stage=="static").map(|(id,o)|{
        let w=inputs.witnesses.get(id).ok_or_else(refuse)?;
        Ok(json!({"obligation_id":id,"predicate_digest":o.predicate_digest,"witness_refs":[w.reference],"result":"satisfied","stage":"static","execution_relevant":o.execution_relevant,"observed_at":w.observed_at,"expires_at":w.expires_at}))
    }).collect()
}
#[derive(Clone, Debug)]
pub(crate) struct LeaseUse {
    pub lid: String,
    pub digest: String,
    pub raw: String,
    pub expires_at: i64,
    key_id: String,
    public_key: String,
}
#[derive(Clone, Debug)]
pub(crate) struct LeaseCheck {
    pub tenant: String,
    pub subject: Subject,
    pub workload: String,
    pub registration_binding: String,
    pub lease: Option<LeaseUse>,
}
impl LeaseCheck {
    pub(crate) fn membership(trust: &AdmissionTrust, subject: &Subject) -> Result<Self> {
        if trust.leases.is_none()
            || subject.iss.is_empty()
            || subject.sub.is_empty()
            || subject.iss.len() > 1024
            || subject.sub.len() > 1024
        {
            return Err(refuse());
        }
        let keys = |map: &BTreeMap<String, VerifyingKey>| {
            map.iter()
                .map(|(id, key)| (id.clone(), hex::encode(key.as_bytes())))
                .collect::<BTreeMap<_, _>>()
        };
        let registration_binding = digest(
            "lease-membership-registration",
            &json!({"tenant":trust.tenant,"subject":subject,"workload":trust.proposal_workload_id,"policy":trust.policy,"descriptor":trust.descriptor_digest,"ownership":trust.ownership_epoch,"obligations":trust.obligation_manifest_digest,"proposal_keys":keys(&trust.proposal_keys),"registry_keys":keys(&trust.registry_keys),"manifest_keys":keys(&trust.manifest_keys),"scope":trust.required_scope,"max_proposal_age_ms":trust.max_proposal_age_ms}),
        )?;
        Ok(Self {
            tenant: trust.tenant.clone(),
            subject: subject.clone(),
            workload: trust.proposal_workload_id.clone(),
            registration_binding,
            lease: None,
        })
    }
    fn key(&self, ledger: &EtcdLedger) -> Result<String> {
        Ok(format!(
            "{}/lease-members/{}",
            ledger.prefix,
            digest(
                "lease-member",
                &json!({"tenant":self.tenant,"subject":self.subject,"workload":self.workload})
            )?
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    registration_binding: String,
    generation: u64,
    active: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    inputs_binding: String,
    binding: String,
    member: Member,
    signed_lease: String,
    packet: StoredAdmissionPacket,
}
fn cache_binding(
    inputs_binding: &str,
    member: &Member,
    key_id: &str,
    public_key: &str,
) -> Result<String> {
    if !crate::grant_reference::valid_reference(inputs_binding) {
        return Err(refuse());
    }
    digest(
        "lease-cache",
        &json!({"inputs":inputs_binding,"member":member,"key_id":key_id,"public_key":public_key}),
    )
}

fn cache_key(ledger: &EtcdLedger, lid: &str) -> Result<String> {
    let pin = lid
        .strip_prefix("kf-lease:")
        .filter(|s| crate::grant_reference::valid_reference(s))
        .ok_or_else(refuse)?;
    Ok(format!("{}/leases/{pin}", ledger.prefix))
}
fn scope(inputs: &VerifiedAdmissionInputs) -> EnforcementScope {
    EnforcementScope {
        conflict_domain: inputs.context.conflict_domain.clone(),
        action: inputs.action.clone(),
        resource: inputs.resources[0].clone(),
        audience: inputs.context.audience.clone(),
        adapter_contract: inputs.adapter_contract.clone(),
        predicate_descriptor: inputs.predicate_descriptor.clone(),
    }
}
impl EtcdLedger {
    async fn lease_read<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        bound: usize,
    ) -> Result<T> {
        let response = self.txn(Vec::new(), vec![get(key)], Vec::new()).await?;
        let kv = range_kv(response.responses.first().ok_or_else(refuse)?)?.ok_or_else(refuse)?;
        if kv.value.len() > bound {
            return Err(refuse());
        }
        Ok(serde_json::from_value(crate::contracts::strict_value(
            &kv.value,
        )?)?)
    }
    /// Privileged create-only membership, never called by an HTTP agent route.
    pub async fn enroll_lease_member(
        &self,
        trust: &AdmissionTrust,
        subject: &Subject,
    ) -> Result<()> {
        trust.validate_configuration()?;
        let check = LeaseCheck::membership(trust, subject)?;
        let key = check.key(self)?;
        let value = record(&Member {
            registration_binding: check.registration_binding,
            generation: 1,
            active: true,
        })?;
        if !self
            .txn(
                vec![version_zero(&key)],
                vec![put(&key, &value)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    /// Explicit operator replacement changes generation even when pins are identical.
    pub async fn replace_lease_member(
        &self,
        trust: &AdmissionTrust,
        subject: &Subject,
        expected_generation: u64,
    ) -> Result<()> {
        self.change_lease_member(trust, subject, Some(expected_generation), true)
            .await
    }
    pub async fn withdraw_lease_member(
        &self,
        trust: &AdmissionTrust,
        subject: &Subject,
    ) -> Result<()> {
        self.change_lease_member(trust, subject, None, false).await
    }
    async fn change_lease_member(
        &self,
        trust: &AdmissionTrust,
        subject: &Subject,
        expected: Option<u64>,
        active: bool,
    ) -> Result<()> {
        trust.validate_configuration()?;
        let check = LeaseCheck::membership(trust, subject)?;
        let key = check.key(self)?;
        let old: Member = self.lease_read(&key, 16384).await?;
        if expected.is_some_and(|g| g != old.generation)
            || old.generation >= crate::contracts::MAX_SAFE_INTEGER
        {
            return Err(refuse());
        }
        let next = Member {
            registration_binding: check.registration_binding,
            generation: old.generation + 1,
            active,
        };
        if !self
            .txn(
                vec![value_eq(&key, &record(&old)?)],
                vec![put(&key, &record(&next)?)],
                Vec::new(),
            )
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
    async fn active_member(&self, check: &LeaseCheck) -> Result<Member> {
        let member: Member = self.lease_read(&check.key(self)?, 16384).await?;
        if !member.active
            || member.generation == 0
            || member.generation > crate::contracts::MAX_SAFE_INTEGER
            || member.registration_binding != check.registration_binding
        {
            return Err(refuse());
        }
        Ok(member)
    }
    pub(crate) async fn lease_compares(
        &self,
        check: &Option<LeaseCheck>,
        now: i64,
    ) -> Result<Vec<Value>> {
        let Some(check) = check else {
            return Ok(Vec::new());
        };
        let member = self.active_member(check).await?;
        let mut compares = vec![value_eq(&check.key(self)?, &record(&member)?)];
        if let Some(lease) = &check.lease {
            if now >= lease.expires_at {
                return Err(refuse());
            }
            let key = cache_key(self, &lease.lid)?;
            let cached: Cache = self.lease_read(&key, 1 << 20).await?;
            if cached.member != member
                || cached.signed_lease != lease.raw
                || cached.binding != lease.lid.strip_prefix("kf-lease:").ok_or_else(refuse)?
                || cached.binding
                    != cache_binding(
                        &cached.inputs_binding,
                        &member,
                        &lease.key_id,
                        &lease.public_key,
                    )?
            {
                return Err(refuse());
            }
            compares.push(value_eq(&key, &record(&cached)?));
        }
        Ok(compares)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn prevalidate_lease(
        &self,
        trust: &AdmissionTrust,
        controller: &AdmissionController,
        identity: &Identity,
        packet: AdmissionPacket<'_>,
        clock: &dyn Clock,
    ) -> Result<String> {
        let inputs = trust.verify_static_inputs(identity, packet, clock)?;
        let registration = trust.leases.as_ref().ok_or_else(refuse)?;
        let check = inputs.lease_check.as_ref().ok_or_else(refuse)?;
        let member = self.active_member(check).await?;
        let (key_id, key) = controller.signing_role();
        if !controller.configured_for(trust) || registration.keys.get(key_id) != Some(&key) {
            return Err(refuse());
        }
        let inputs_binding = inputs.admission_binding()?;
        let binding = cache_binding(
            &inputs_binding,
            &member,
            key_id,
            &hex::encode(key.as_bytes()),
        )?;
        let lid = format!("kf-lease:{binding}");
        let key_path = cache_key(self, &lid)?;
        let now = clock.now_ms();
        let expires = inputs.valid_until.min(
            now.checked_add(registration.max_lifetime_ms)
                .ok_or_else(refuse)?,
        );
        if expires <= now {
            return Err(refuse());
        }
        let c = &inputs.context;
        let pending: Vec<_> = c
            .obligations
            .iter()
            .filter(|(_, o)| o.stage == "jit")
            .map(|(id, _)| id)
            .collect();
        let payload = json!({"lid":lid,"proposal_digest":c.proposal_digest,"delegation_digest":c.delegation_digest,"subject":c.subject,"workload_id":c.workload_id,"policy":c.policy,"descriptor_digest":c.descriptor_digest,"ownership_epoch":c.ownership_epoch,"static_discharges":static_discharges(&inputs)?,"pending_jit_obligations":pending,"issued_at":now,"expires_at":expires,"execution_authority":false});
        let signed = controller.sign_lease(payload)?;
        registration.verify(signed.as_bytes(), &inputs, now)?;
        let cached = Cache {
            inputs_binding: inputs_binding.clone(),
            binding: binding.clone(),
            member: member.clone(),
            signed_lease: signed.clone(),
            packet: inputs.packet.clone(),
        };
        let saved = record(&cached)?;
        if saved.len() > 1 << 20 {
            return Err(refuse());
        }
        let mut compares = self
            .control_check(&scope(&inputs), &c.policy, c.ownership_epoch, None, None)
            .await?
            .compare;
        let domain = format!("{}/domains/{}", self.prefix, key_part(&c.conflict_domain));
        compares.extend([
            value_eq(&format!("{domain}/policy"), &record(&c.policy)?),
            value_eq(
                &format!("{domain}/ownership"),
                &c.ownership_epoch.to_string(),
            ),
            value_eq(&check.key(self)?, &record(&member)?),
        ]);
        compares.extend(
            self.review_compares(&inputs.review_facts, clock.now_ms())
                .await?,
        );
        let mut create = compares.clone();
        create.push(version_zero(&key_path));
        let result = if self
            .txn(create, vec![put(&key_path, &saved)], Vec::new())
            .await?
            .succeeded
        {
            signed
        } else {
            let read = self.txn(compares, vec![get(&key_path)], Vec::new()).await?;
            if !read.succeeded {
                return Err(refuse());
            }
            let kv = range_kv(read.responses.first().ok_or_else(refuse)?)?.ok_or_else(refuse)?;
            if kv.value.len() > 1 << 20 {
                return Err(refuse());
            }
            let old: Cache = serde_json::from_value(crate::contracts::strict_value(&kv.value)?)?;
            if old.binding != binding
                || old.inputs_binding != inputs_binding
                || old.member != member
                || old.packet != inputs.packet
            {
                return Err(refuse());
            }
            old.signed_lease
        };
        registration.verify(result.as_bytes(), &inputs, clock.now_ms())?;
        Ok(result)
    }
}
