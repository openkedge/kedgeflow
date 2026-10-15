//! Administrative records and authority-transition comparisons share etcd CAS.
use crate::{
    contracts::Policy,
    error::{Error, Result},
    governance::*,
    ledger::{
        EtcdLedger, get, key_part, mod_revision, put, range_kv, record, value_eq, version_zero,
    },
};
use serde_json::Value;
impl EtcdLedger {
    fn control_domain(&self, domain: &str) -> String {
        self.domain_base(domain)
    }
    pub async fn control_snapshot(
        &self,
        domain: &str,
    ) -> Result<(Option<StoredControl>, Option<StoredControl>)> {
        self.action_domain_scope(domain)?;
        let base = self.control_domain(domain);
        let t = self
            .txn(
                vec![],
                vec![
                    get(&format!("{base}/control/installation")),
                    get(&format!("{base}/control/ack")),
                ],
                vec![],
            )
            .await?;
        if !t.succeeded || t.responses.len() != 2 {
            return Err(Error::Unavailable("invalid control snapshot".into()));
        }
        let parse = |r: &Value| -> Result<Option<StoredControl>> {
            range_kv(r)?
                .map(|v| serde_json::from_slice(&v.value).map_err(Error::from))
                .transpose()
        };
        Ok((parse(&t.responses[0])?, parse(&t.responses[1])?))
    }
    pub(crate) async fn publish_control(
        &self,
        incoming: &StoredControl,
        kind: &str,
    ) -> Result<StoredControl> {
        let new = match kind {
            "publish_policy" => incoming.payload::<PolicyPublication>(kind)?.registration,
            "register_descriptor" => {
                incoming
                    .payload::<DescriptorPublication>(kind)?
                    .registration
            }
            _ => return Err(Error::Invalid("publication kind".into())),
        };
        self.action_domain_registration(&new)?;
        let base = self.control_domain(&new.scope.conflict_domain);
        let latest = format!("{base}/control/{kind}");
        let retained = format!("{base}/control/records/{}", incoming.digest);
        let t = self.txn(vec![], vec![get(&latest)], vec![]).await?;
        if !t.succeeded || t.responses.len() != 1 {
            return Err(Error::Unavailable("invalid publication read".into()));
        }
        let compare = if let Some(kv) = range_kv(&t.responses[0])? {
            let old: StoredControl = serde_json::from_slice(&kv.value)?;
            let before = match kind {
                "publish_policy" => old.payload::<PolicyPublication>(kind)?.registration,
                _ => old.payload::<DescriptorPublication>(kind)?.registration,
            };
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
                return Err(Error::Refused(
                    "control publication rollback or same-epoch conflict".into(),
                ));
            }
            if old.record == incoming.record {
                return Ok(old);
            }
            mod_revision(&latest, &kv.mod_revision)
        } else {
            version_zero(&latest)
        };
        let (history_compare, mut writes) = self
            .history_append(&new.scope.conflict_domain, incoming, kind)
            .await?;
        let mut compares = vec![compare, version_zero(&retained)];
        compares.extend(history_compare);
        writes.extend([
            put(&latest, &record(incoming)?),
            put(&retained, &record(incoming)?),
        ]);
        let t = self.txn(compares, writes, vec![]).await?;
        if !t.succeeded {
            return Err(Error::Refused(
                "publication revision changed; retry unchanged record".into(),
            ));
        }
        Ok(incoming.clone())
    }
    pub(crate) async fn install_control(&self, incoming: &StoredControl) -> Result<StoredControl> {
        let i: Installation = incoming.payload("install")?;
        self.action_domain_registration(&i.registration)?;
        let base = self.control_domain(&i.registration.scope.conflict_domain);
        let install_key = format!("{base}/control/installation");
        let policy_key = format!("{base}/policy");
        let ownership_key = format!("{base}/ownership");
        let pp = format!("{base}/control/publish_policy");
        let rp = format!("{base}/control/register_descriptor");
        let t = self
            .txn(
                vec![],
                vec![
                    get(&install_key),
                    get(&pp),
                    get(&rp),
                    get(&policy_key),
                    get(&ownership_key),
                ],
                vec![],
            )
            .await?;
        if !t.succeeded || t.responses.len() != 5 {
            return Err(Error::Unavailable("invalid installation read".into()));
        }
        let p = range_kv(&t.responses[1])?
            .ok_or_else(|| Error::Refused("policy not published".into()))?;
        let r = range_kv(&t.responses[2])?
            .ok_or_else(|| Error::Refused("descriptor not published".into()))?;
        let p: StoredControl = serde_json::from_slice(&p.value)?;
        let r: StoredControl = serde_json::from_slice(&r.value)?;
        if p.digest != i.policy_publication_digest
            || r.digest != i.descriptor_publication_digest
            || p.payload::<PolicyPublication>("publish_policy")?
                .registration
                != i.registration
            || r.payload::<DescriptorPublication>("register_descriptor")?
                .registration
                != i.registration
        {
            return Err(Error::Refused(
                "installation does not bind current publications".into(),
            ));
        }
        let mut compare = vec![
            value_eq(&pp, &record(&p)?),
            value_eq(&rp, &record(&r)?),
            version_zero(&self.revocation_key(
                &i.registration.scope.conflict_domain,
                &RevocationTarget::Domain,
            )),
        ];
        match range_kv(&t.responses[0])? {
            Some(kv) => {
                let old: StoredControl = serde_json::from_slice(&kv.value)?;
                let old_i: Installation = old.payload("install")?;
                if old.record == incoming.record {
                    return Ok(old);
                }
                if i.expected_revision != old_i.revision
                    || i.revision
                        != old_i.revision.checked_add(1).ok_or_else(|| {
                            Error::Refused("installation revision exhausted".into())
                        })?
                {
                    return Err(Error::Refused("installation revision conflict".into()));
                }
                compare.push(mod_revision(&install_key, &kv.mod_revision));
            }
            None => {
                if i.expected_revision != 0 || i.revision != 1 {
                    return Err(Error::Refused(
                        "first installation must be revision one".into(),
                    ));
                }
                compare.push(version_zero(&install_key));
            }
        }
        if let Some(kv) = range_kv(&t.responses[3])? {
            let old: Policy = serde_json::from_slice(&kv.value)?;
            let new = &i.registration.policy;
            if old.id != new.id
                || new.epoch < old.epoch
                || (new.epoch == old.epoch && new.digest != old.digest)
            {
                return Err(Error::Refused("installed policy rollback".into()));
            }
            compare.push(mod_revision(&policy_key, &kv.mod_revision));
        } else {
            compare.push(version_zero(&policy_key));
        }
        if let Some(kv) = range_kv(&t.responses[4])? {
            let old = std::str::from_utf8(&kv.value)
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| Error::Refused("invalid ownership".into()))?;
            if i.registration.ownership_epoch < old {
                return Err(Error::Refused("installed ownership rollback".into()));
            }
            compare.push(mod_revision(&ownership_key, &kv.mod_revision));
        } else {
            compare.push(version_zero(&ownership_key));
        }
        let (history_compare, mut writes) = self
            .history_append(&i.registration.scope.conflict_domain, incoming, "install")
            .await?;
        compare.extend(history_compare);
        writes.extend([
            put(&install_key, &record(incoming)?),
            put(&format!("{base}/control-required"), PROFILE),
            put(&policy_key, &record(&i.registration.policy)?),
            put(&ownership_key, &i.registration.ownership_epoch.to_string()),
        ]);
        let t = self.txn(compare, writes, vec![]).await?;
        if !t.succeeded {
            return Err(Error::Refused("installation compare refused".into()));
        }
        Ok(incoming.clone())
    }
    pub(crate) async fn acknowledge_in_domain(
        &self,
        incoming: &StoredControl,
        a: &Acknowledgement,
        domain: &str,
    ) -> Result<StoredControl> {
        self.action_domain_scope(domain)?;
        let base = self.control_domain(domain);
        let ik = format!("{base}/control/installation");
        let ak = format!("{base}/control/ack");
        let t = self.txn(vec![], vec![get(&ik), get(&ak)], vec![]).await?;
        if !t.succeeded || t.responses.len() != 2 {
            return Err(Error::Unavailable("invalid acknowledgement read".into()));
        }
        let iv = range_kv(&t.responses[0])?
            .ok_or_else(|| Error::Refused("control not installed".into()))?;
        let installed: StoredControl = serde_json::from_slice(&iv.value)?;
        let i: Installation = installed.payload("install")?;
        let _: (Acknowledgement, _) = verify_control(
            &incoming.record,
            "acknowledge",
            &acknowledgement_keys(&i.registration.acknowledger)?,
        )?;
        validate_ack(a, &i, &installed.digest, self.authority_clock.now_ms())?;
        let mut compare = vec![value_eq(&ik, &record(&installed)?)];
        match range_kv(&t.responses[1])? {
            Some(kv) => {
                let old: StoredControl = serde_json::from_slice(&kv.value)?;
                if old.record == incoming.record {
                    return Ok(old);
                }
                let before: Acknowledgement = old.payload("acknowledge")?;
                if before.revision == a.revision
                    && (a.installed_at <= before.installed_at || a.expires_at < before.expires_at)
                {
                    return Err(Error::Refused("acknowledgement refresh rollback".into()));
                }
                compare.push(mod_revision(&ak, &kv.mod_revision));
            }
            None => compare.push(version_zero(&ak)),
        }
        let (history_compare, mut writes) =
            self.history_append(domain, incoming, "acknowledge").await?;
        compare.extend(history_compare);
        writes.push(put(&ak, &record(incoming)?));
        let t = self.txn(compare, writes, vec![]).await?;
        if !t.succeeded {
            return Err(Error::Refused("acknowledgement revision conflict".into()));
        }
        Ok(incoming.clone())
    }
    fn revocation_key(&self, domain: &str, target: &RevocationTarget) -> String {
        let base = self.control_domain(domain);
        match target {
            RevocationTarget::Domain => format!("{base}/revocations/domain"),
            RevocationTarget::Root { id } => format!("{base}/revocations/roots/{}", key_part(id)),
            RevocationTarget::Grant { id } => format!("{base}/revocations/grants/{}", key_part(id)),
        }
    }
    pub(crate) async fn revoke_control(&self, incoming: &StoredControl) -> Result<StoredControl> {
        let r: Revocation = incoming.payload("revoke")?;
        self.action_domain_scope(&r.conflict_domain)?;
        let key = self.revocation_key(&r.conflict_domain, &r.target);
        let ik = format!(
            "{}/control/installation",
            self.control_domain(&r.conflict_domain)
        );
        let t = self.txn(vec![], vec![get(&key), get(&ik)], vec![]).await?;
        if !t.succeeded || t.responses.len() != 2 {
            return Err(Error::Unavailable("invalid revocation read".into()));
        }
        if let Some(kv) = range_kv(&t.responses[0])? {
            let old: StoredControl = serde_json::from_slice(&kv.value)?;
            if old.record == incoming.record {
                return Ok(old);
            }
            return Err(Error::Refused("revocation is immutable".into()));
        }
        let kv = range_kv(&t.responses[1])?
            .ok_or_else(|| Error::Refused("control not installed".into()))?;
        let installed: StoredControl = serde_json::from_slice(&kv.value)?;
        if installed
            .payload::<Installation>("install")?
            .registration
            .tenant
            != r.tenant
        {
            return Err(Error::Refused("revocation tenant mismatch".into()));
        }
        let (history_compare, mut writes) = self
            .history_append(&r.conflict_domain, incoming, "revoke")
            .await?;
        let mut compare = vec![version_zero(&key), mod_revision(&ik, &kv.mod_revision)];
        compare.extend(history_compare);
        writes.push(put(&key, &record(incoming)?));
        let t = self.txn(compare, writes, vec![]).await?;
        if !t.succeeded {
            return Err(Error::Refused("revocation compare refused".into()));
        }
        Ok(incoming.clone())
    }
    pub(crate) async fn control_compare(
        &self,
        scope: &EnforcementScope,
        policy: &Policy,
        ownership: u64,
        root: Option<&str>,
        gid: Option<&str>,
    ) -> Result<Vec<Value>> {
        Ok(self
            .control_check(scope, policy, ownership, root, gid)
            .await?
            .compare)
    }
    pub(crate) async fn control_check(
        &self,
        scope: &EnforcementScope,
        policy: &Policy,
        ownership: u64,
        root: Option<&str>,
        gid: Option<&str>,
    ) -> Result<crate::control_bindings::ControlCheck> {
        let paired_compare = self.action_domain_authority(scope, policy, ownership)?;
        let base = self.control_domain(&scope.conflict_domain);
        let marker = format!("{base}/control-required");
        let ik = format!("{base}/control/installation");
        let ak = format!("{base}/control/ack");
        let mut revocations =
            vec![self.revocation_key(&scope.conflict_domain, &RevocationTarget::Domain)];
        if let Some(id) = root {
            revocations.push(self.revocation_key(
                &scope.conflict_domain,
                &RevocationTarget::Root { id: id.into() },
            ));
        }
        if let Some(id) = gid {
            revocations.push(self.revocation_key(
                &scope.conflict_domain,
                &RevocationTarget::Grant { id: id.into() },
            ));
        }
        let hk = format!("{base}/control/history/head");
        let mut gets = vec![get(&marker), get(&ik), get(&ak), get(&hk)];
        gets.extend(revocations.iter().map(|key| get(key)));
        let t = self.txn(vec![], gets, vec![]).await?;
        if !t.succeeded || t.responses.len() != 4 + revocations.len() {
            return Err(Error::Unavailable("invalid enforcement read".into()));
        }
        for r in &t.responses[4..] {
            if range_kv(r)?.is_some() {
                return Err(Error::Refused("authority explicitly revoked".into()));
            }
        }
        let mut compare = revocations
            .iter()
            .map(|k| version_zero(k))
            .collect::<Vec<_>>();
        compare.extend(paired_compare);
        let m = range_kv(&t.responses[0])?;
        if m.is_none() {
            if self.require_control {
                return Err(Error::Refused("required control not installed".into()));
            }
            compare.push(version_zero(&marker));
            return Ok(crate::control_bindings::ControlCheck {
                compare,
                state: None,
            });
        }
        if m.unwrap().value != PROFILE.as_bytes() {
            return Err(Error::Refused("unknown managed control profile".into()));
        }
        let iv = range_kv(&t.responses[1])?
            .ok_or_else(|| Error::Refused("installed control missing".into()))?;
        let av = range_kv(&t.responses[2])?
            .ok_or_else(|| Error::Refused("installation unacknowledged".into()))?;
        let installed: StoredControl = serde_json::from_slice(&iv.value)?;
        let i: Installation = installed.payload("install")?;
        if i.registration.scope != *scope
            || i.registration.policy != *policy
            || i.registration.ownership_epoch != ownership
            || self
                .required_trust_digest
                .as_ref()
                .is_some_and(|d| d != &i.registration.trust_digest)
        {
            return Err(Error::Refused("stale installed control binding".into()));
        }
        let stored_ack: StoredControl = serde_json::from_slice(&av.value)?;
        let (a, _): (Acknowledgement, _) = verify_control(
            &stored_ack.record,
            "acknowledge",
            &acknowledgement_keys(&i.registration.acknowledger)?,
        )?;
        let checked_at = self.authority_clock.now_ms();
        validate_ack(&a, &i, &installed.digest, checked_at)?;
        let hv = range_kv(&t.responses[3])?
            .ok_or_else(|| Error::Refused("managed control history absent".into()))?;
        let head: crate::control_history::HistoryHead =
            serde_json::from_value(crate::contracts::strict_value(&hv.value)?)?;
        if head.sequence == 0
            || head.accepted_at > checked_at
            || !crate::grant_reference::valid_reference(&head.digest)
        {
            return Err(Error::Refused("invalid managed history head".into()));
        }
        let ek = format!("{base}/control/history/events/{:020}", head.sequence);
        let raw = self
            .read_key(&ek)
            .await?
            .ok_or_else(|| Error::Unavailable("control history head event absent".into()))?;
        let event: crate::control_history::HistoryEvent =
            serde_json::from_value(crate::contracts::strict_value(&raw)?)?;
        if event.sequence != head.sequence
            || event.digest()? != head.digest
            || event.accepted_at != head.accepted_at
        {
            return Err(Error::Unavailable(
                "control history head event mismatch".into(),
            ));
        }
        compare.extend([
            value_eq(&ek, &record(&event)?),
            value_eq(&hk, &record(&head)?),
            value_eq(&marker, PROFILE),
            value_eq(&ik, &record(&installed)?),
            value_eq(&ak, &record(&stored_ack)?),
        ]);
        let mut absent_revocations = vec![RevocationTarget::Domain];
        if let Some(id) = root {
            absent_revocations.push(RevocationTarget::Root { id: id.into() });
        }
        if let Some(id) = gid {
            absent_revocations.push(RevocationTarget::Grant { id: id.into() });
        }
        Ok(crate::control_bindings::ControlCheck {
            compare,
            state: Some(crate::control_bindings::ControlState {
                history_sequence: head.sequence,
                history_digest: head.digest,
                installation_digest: installed.digest,
                acknowledgement_digest: stored_ack.digest,
                checked_at,
                absent_revocations,
            }),
        })
    }
}
