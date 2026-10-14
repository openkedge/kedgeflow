//! Independent historical verification. Successful results describe authenticated
//! retained assertions, never an operation's non-revocation or execution permission.
use crate::{
    contracts::{Grant, canonical, digest},
    control_history::ControlHistoryBundle,
    error::{Error, Result},
    governance::{
        Acknowledgement, ControlRegistration, DescriptorPublication, Installation,
        PolicyPublication, Revocation, RevocationTarget, acknowledgement_keys, trust_digest,
        validate_ack, verify_control,
    },
    lineage::{LineageTrust, LineageVerification, verify_lineage},
};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub struct ApprovedHistoryRegistration {
    pub registration: ControlRegistration,
    pub trust: LineageTrust,
}
pub struct ControlHistoryTrust {
    pub operation: LineageTrust,
    pub historical: Vec<ApprovedHistoryRegistration>,
    pub administrative_keys: BTreeMap<String, BTreeMap<String, VerifyingKey>>,
    pub observer_keys: BTreeMap<String, VerifyingKey>,
    pub observer_id: String,
    pub namespace: String,
}
fn refuse(message: &str) -> Error {
    Error::Refused(message.into())
}
impl ControlHistoryTrust {
    pub fn validate(&self) -> Result<()> {
        self.operation.validate()?;
        if self.historical.is_empty()
            || self.historical.len() > 16
            || self.observer_keys.is_empty()
            || self.observer_id.is_empty()
            || self.namespace.is_empty()
            || self.administrative_keys.len() != 4
        {
            return Err(refuse("incomplete historical governance trust"));
        }
        let mut roles: BTreeMap<[u8; 32], String> = BTreeMap::new();
        let mut add = |role: &str, keys: &BTreeMap<String, VerifyingKey>| -> Result<()> {
            if keys.is_empty() {
                return Err(refuse("empty history signer role"));
            }
            for (id, k) in keys {
                if id.is_empty() {
                    return Err(refuse("empty history key ID"));
                }
                if roles
                    .insert(k.to_bytes(), role.into())
                    .is_some_and(|before| before != role)
                {
                    return Err(refuse("historical governance signer role overlap"));
                }
            }
            Ok(())
        };
        for kind in ["publish_policy", "register_descriptor", "install", "revoke"] {
            add(
                kind,
                self.administrative_keys
                    .get(kind)
                    .ok_or_else(|| refuse("missing historical administrative role"))?,
            )?;
        }
        add("observer", &self.observer_keys)?;
        for t in std::iter::once(&self.operation).chain(self.historical.iter().map(|s| &s.trust)) {
            t.validate()?;
            add("proposal", &t.admission.proposal_keys)?;
            add("registry", &t.admission.registry_keys)?;
            add("manifest", &t.admission.manifest_keys)?;
            for e in t.admission.evidence.values() {
                add("evidence", &e.keys)?;
            }
            add("admission", &t.admission_keys)?;
            add("issuer", &t.grants.keys)?;
            add("outcome", &t.outcome_keys)?;
        }
        for snapshot in &self.historical {
            let r = &snapshot.registration;
            let t = &snapshot.trust;
            add("acknowledge", &acknowledgement_keys(&r.acknowledger)?)?;
            let issuer_keys = t
                .grants
                .keys
                .iter()
                .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                .collect::<BTreeMap<_, _>>();
            if r.tenant != t.admission.tenant
                || r.tenant != self.operation.admission.tenant
                || r.policy != t.admission.policy
                || r.ownership_epoch != t.admission.ownership_epoch
                || r.obligation_manifest_digest != t.admission.obligation_manifest_digest
                || r.trust_digest != trust_digest(&t.admission, &t.admission_keys, &t.grants.keys)?
                || r.issuer_keys != issuer_keys
                || r.scope.action.digest != t.admission.descriptor_digest
                || r.scope.audience != t.grants.audience
                || r.acknowledger.component_id.is_empty()
                || r.acknowledger.workload_id.is_empty()
                || r.acknowledger.workload_id == t.admission.proposal_workload_id
                || !(1..=60000).contains(&r.acknowledger.max_lifetime_ms)
            {
                return Err(refuse("unapproved historical scope/key membership"));
            }
        }
        Ok(())
    }
    fn snapshot(&self, r: &ControlRegistration) -> Result<&ApprovedHistoryRegistration> {
        self.historical
            .iter()
            .find(|s| s.registration == *r)
            .ok_or_else(|| refuse("unknown historical control registration"))
    }
}
#[derive(Debug, Serialize)]
pub struct KnownRevocation {
    pub sequence: u64,
    pub accepted_at: i64,
    pub target: RevocationTarget,
    pub reason_digest: String,
    pub relation_to_issuance: String,
}
#[derive(Debug, Serialize)]
pub struct ControlHistoryVerification {
    pub profile: String,
    pub observer_id: String,
    pub namespace: String,
    pub captured_at: i64,
    pub head_digest: String,
    pub events_verified: usize,
    pub installations_verified: usize,
    pub acknowledgements_verified: usize,
    pub matching_installation_digests: Vec<String>,
    pub revocations: Vec<KnownRevocation>,
    pub operation_control_state: String,
    pub lineage: LineageVerification,
}
fn monotonic(before: &ControlRegistration, new: &ControlRegistration) -> Result<()> {
    if before.tenant != new.tenant
        || before.scope.resource.id != new.scope.resource.id
        || before.scope.action.id != new.scope.action.id
        || before.policy.id != new.policy.id
        || new.policy.epoch < before.policy.epoch
        || new.ownership_epoch < before.ownership_epoch
        || (new.policy.epoch == before.policy.epoch
            && (new.policy.digest != before.policy.digest
                || new.obligation_manifest_digest != before.obligation_manifest_digest
                || new.trust_digest != before.trust_digest))
        || (new.ownership_epoch == before.ownership_epoch
            && (new.scope.action.digest != before.scope.action.digest
                || new.scope.resource != before.scope.resource))
    {
        return Err(refuse(
            "historical publication rollback/same-epoch conflict",
        ));
    }
    Ok(())
}
fn descriptor_binding(
    p: &DescriptorPublication,
    snapshot: &ApprovedHistoryRegistration,
) -> Result<()> {
    let r = &p.registration;
    let s = &r.scope;
    let d = crate::schema::verify_record(
        p.descriptor.as_bytes(),
        "ctd",
        &snapshot.trust.admission.registry_keys,
    )?;
    if crate::contracts::record_digest(&d)? != s.action.digest
        || d.payload["tenant"] != r.tenant
        || d.payload["action"] != s.action.id
        || d.payload["version"] != s.action.version
        || d.payload["ownership_epoch"] != r.ownership_epoch
        || d.payload["gateway_audience"] != s.audience
        || d.payload["concurrency"]["conflict_domain"] != s.conflict_domain
        || d.payload["adapter_contract"] != s.adapter_contract
        || d.payload["concurrency"]["predicate_descriptor"] != s.predicate_descriptor
    {
        return Err(refuse("historical descriptor scope mismatch"));
    }
    Ok(())
}
pub fn verify_control_history(
    bundle: &ControlHistoryBundle,
    trust: &ControlHistoryTrust,
) -> Result<ControlHistoryVerification> {
    verify_history(bundle, trust, true)
}
pub(crate) fn verify_history(
    bundle: &ControlHistoryBundle,
    trust: &ControlHistoryTrust,
    require_clock_cover: bool,
) -> Result<ControlHistoryVerification> {
    bundle.bound()?;
    trust.validate()?;
    bundle.checkpoint.verify(&trust.observer_keys)?;
    let mut lineage = verify_lineage(&bundle.lineage, &trust.operation)?;
    let c = &bundle.checkpoint.payload;
    let g: Grant = trust
        .operation
        .grants
        .verify_retained(bundle.lineage.issuance.signed_grant.as_bytes())?
        .grant;
    if c.observer_id != trust.observer_id
        || c.namespace != trust.namespace
        || c.tenant != lineage.tenant
        || c.conflict_domain != g.conflict_domain
        || c.event_count != bundle.events.len() as u64
        || c.captured_at < lineage.issued_at
        || bundle
            .lineage
            .lease_authority
            .as_ref()
            .is_some_and(|bindings| bindings.iter().any(|b| b.checked_at > c.captured_at))
        || c.lineage_digest
            != digest(
                "control-history-lineage",
                &serde_json::to_value(&bundle.lineage)?,
            )?
    {
        return Err(refuse("checkpoint/operation history correlation mismatch"));
    }
    let mut previous = None;
    let mut accepted_at = 0;
    let mut seen = BTreeSet::new();
    let mut policies: Option<(PolicyPublication, String)> = None;
    let mut descriptors: Option<(DescriptorPublication, String)> = None;
    let mut installed: Option<(Installation, String)> = None;
    let mut last_ack: Option<Acknowledgement> = None;
    let mut installations: Vec<(Installation, String, i64)> = Vec::new();
    let mut acks: Vec<(Acknowledgement, i64)> = Vec::new();
    let mut revocations = Vec::new();
    let mut revoked = BTreeSet::new();
    let mut domain_revoked = false;
    for (index, event) in bundle.events.iter().enumerate() {
        if event.sequence != index as u64 + 1
            || event.previous_digest != previous
            || event.accepted_at < accepted_at
            || event.accepted_at > c.captured_at
            || !seen.insert(event.control.digest.clone())
        {
            return Err(refuse(
                "history sequence/predecessor/time/duplicate mismatch",
            ));
        }
        let keys = if event.kind == "acknowledge" {
            acknowledgement_keys(
                &installed
                    .as_ref()
                    .ok_or_else(|| refuse("acknowledgement precedes installation"))?
                    .0
                    .registration
                    .acknowledger,
            )?
        } else {
            trust
                .administrative_keys
                .get(&event.kind)
                .ok_or_else(|| refuse("unsupported historical control kind"))?
                .clone()
        };
        let (payload, stored): (serde_json::Value, _) =
            verify_control(&event.control.record, &event.kind, &keys)?;
        if stored.digest != event.control.digest {
            return Err(refuse("history stored control digest mismatch"));
        }
        match event.kind.as_str() {
            "publish_policy" => {
                let p: PolicyPublication = serde_json::from_value(payload)?;
                let snapshot = trust.snapshot(&p.registration)?;
                if p.registration.scope.conflict_domain != g.conflict_domain
                    || canonical(&serde_json::to_value(&p.definition)?)?
                        != canonical(&serde_json::to_value(&snapshot.trust.policy)?)?
                {
                    return Err(refuse("historical policy/definition mismatch"));
                }
                if let Some((old, _)) = &policies {
                    monotonic(&old.registration, &p.registration)?;
                }
                policies = Some((p, stored.digest));
            }
            "register_descriptor" => {
                let p: DescriptorPublication = serde_json::from_value(payload)?;
                let snapshot = trust.snapshot(&p.registration)?;
                if p.registration.scope.conflict_domain != g.conflict_domain {
                    return Err(refuse("historical descriptor domain mismatch"));
                }
                descriptor_binding(&p, snapshot)?;
                if let Some((old, _)) = &descriptors {
                    monotonic(&old.registration, &p.registration)?;
                }
                descriptors = Some((p, stored.digest));
            }
            "install" => {
                let i: Installation = serde_json::from_value(payload)?;
                trust.snapshot(&i.registration)?;
                let p = policies
                    .as_ref()
                    .ok_or_else(|| refuse("installation lacks policy publication"))?;
                let d = descriptors
                    .as_ref()
                    .ok_or_else(|| refuse("installation lacks descriptor publication"))?;
                let expected = installed.as_ref().map_or(0, |s| s.0.revision);
                if domain_revoked
                    || i.expected_revision != expected
                    || expected.checked_add(1) != Some(i.revision)
                    || i.policy_publication_digest != p.1
                    || i.descriptor_publication_digest != d.1
                    || i.registration != p.0.registration
                    || i.registration != d.0.registration
                {
                    return Err(refuse(
                        "historical installation revision/publication mismatch",
                    ));
                }
                if let Some((old, _)) = &installed {
                    monotonic(&old.registration, &i.registration)?;
                }
                installations.push((i.clone(), stored.digest.clone(), event.accepted_at));
                installed = Some((i, stored.digest));
            }
            "acknowledge" => {
                let a: Acknowledgement = serde_json::from_value(payload)?;
                let i = installed
                    .as_ref()
                    .ok_or_else(|| refuse("historical installation absent"))?;
                validate_ack(&a, &i.0, &i.1, event.accepted_at)?;
                if last_ack.as_ref().is_some_and(|before| {
                    before.revision == a.revision
                        && (a.installed_at <= before.installed_at
                            || a.expires_at < before.expires_at)
                }) {
                    return Err(refuse("historical acknowledgement refresh rollback"));
                }
                acks.push((a.clone(), event.accepted_at));
                last_ack = Some(a);
            }
            "revoke" => {
                let r: Revocation = serde_json::from_value(payload)?;
                if installed.is_none()
                    || r.tenant != c.tenant
                    || r.conflict_domain != g.conflict_domain
                    || r.revision != 1
                    || !crate::grant_reference::valid_reference(&r.reason_digest)
                    || !revoked.insert(serde_json::to_string(&r.target)?)
                {
                    return Err(refuse(
                        "historical revocation scope/immutable target mismatch",
                    ));
                }
                if r.target == RevocationTarget::Domain {
                    domain_revoked = true;
                }
                let relation = match event.accepted_at.cmp(&lineage.issued_at) {
                    std::cmp::Ordering::Less => "before_issuance_by_recorded_clock",
                    std::cmp::Ordering::Equal => "same_millisecond_order_unproven",
                    std::cmp::Ordering::Greater => "after_issuance_by_recorded_clock",
                };
                revocations.push(KnownRevocation {
                    sequence: event.sequence,
                    accepted_at: event.accepted_at,
                    target: r.target,
                    reason_digest: r.reason_digest,
                    relation_to_issuance: relation.into(),
                });
            }
            _ => return Err(refuse("unsupported historical kind")),
        }
        previous = Some(event.digest()?);
        accepted_at = event.accepted_at;
    }
    if previous.as_deref() != Some(&c.head_digest) {
        return Err(refuse("history checkpoint head mismatch"));
    }
    let expected_scope = crate::governance::EnforcementScope::grant(&g)?;
    let pin = trust_digest(
        &trust.operation.admission,
        &trust.operation.admission_keys,
        &trust.operation.grants.keys,
    )?;
    let expected_issuers = trust
        .operation
        .grants
        .keys
        .iter()
        .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    let matching: Vec<_> = installations
        .iter()
        .filter(|(i, id, time)| {
            i.registration.scope == expected_scope
                && i.registration.policy == g.policy
                && i.registration.ownership_epoch == g.ownership_epoch
                && i.registration.trust_digest == pin
                && i.registration.issuer_keys == expected_issuers
                && (!require_clock_cover
                    || (*time <= lineage.admitted_at
                        && acks.iter().any(|(a, time)| {
                            a.installation_digest == *id
                                && *time <= lineage.admitted_at
                                && a.installed_at <= lineage.admitted_at
                                && a.expires_at > lineage.issued_at
                        })))
        })
        .map(|(_, id, _)| id.clone())
        .collect();
    if matching.is_empty() {
        return Err(refuse(
            "no approved installation/acknowledgement covers historical operation",
        ));
    }
    lineage
        .missing_links
        .retain(|s| s != "installed control/revocation/key history");
    lineage
        .missing_links
        .push("operation-bound installation/revocation CAS sequence and clock trust".into());
    Ok(ControlHistoryVerification {
        profile: bundle.profile.clone(),
        observer_id: c.observer_id.clone(),
        namespace: c.namespace.clone(),
        captured_at: c.captured_at,
        head_digest: c.head_digest.clone(),
        events_verified: bundle.events.len(),
        installations_verified: installations.len(),
        acknowledgements_verified: acks.len(),
        matching_installation_digests: matching,
        revocations,
        operation_control_state: "not_attested; history prefix is not a non-revocation proof"
            .into(),
        lineage,
    })
}
