//! Native managed-operation anchor, immutable event/source retention and
//! expected-head CAS. Observation, delivery and physical mutation use no refund.
use crate::{
    contracts::{Grant, digest, strict_value},
    error::{Error, Result},
    family::{Access, Selection},
    kube_drain_proof::Trust,
    ledger::{EtcdLedger, IssuanceRecord, get, put, range_kv, record, value_eq, version_zero},
    managed_drain::Enrollment,
    managed_drain_evidence::{Ack, ControlKind, ControlProof},
    managed_drain_journal::{Change, Core, Event, MAX_EVENTS, MAX_SOURCE_BYTES, Origin},
    physical_operations::{Observation, Original},
    recovery::{Candidate, context_key},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
fn refuse() -> Error {
    Error::Refused("native managed drain anchor, history or evidence refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "record_kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Material {
    Aggregate(Box<crate::family_saga::AggregateBundle>),
    Controller(Box<ControlProof>),
    Acknowledgement(Ack),
}
impl Material {
    pub fn digest(&self) -> Result<String> {
        match self {
            Self::Aggregate(b) => digest("physical-operating-aggregate", &json!(b)),
            Self::Controller(p) => p.digest(),
            Self::Acknowledgement(a) => a.digest(),
        }
    }
}
#[derive(Clone)]
pub struct Context {
    pub selection: Selection,
    pub physical: Trust,
    pub enrollment: Enrollment,
}
impl Context {
    pub fn from_ledger(l: &EtcdLedger) -> Result<Self> {
        let Some(access) = l.family.as_deref() else {
            return Err(refuse());
        };
        let Access::Child(selection) = access else {
            return Err(refuse());
        };
        let r = &selection.registration;
        r.validate()?;
        let n = r
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&selection.child_id)?;
        let physical = n.physical.as_ref().ok_or_else(refuse)?.clone();
        let e = physical.operating.as_ref().ok_or_else(refuse)?.clone();
        e.validate_child(r, &selection.child_id, &physical.contract)?;
        if l.namespace() != r.namespace
            || r.child(&selection.child_id)?.reservation.scope.action.id
                != crate::managed_drain::ACTION
        {
            return Err(refuse());
        }
        Ok(Self {
            selection: selection.clone(),
            physical,
            enrollment: e,
        })
    }
    pub fn base(&self) -> String {
        format!(
            "{}/family/drain/{}/operating",
            self.enrollment.namespace, self.enrollment.operation_key
        )
    }
    pub fn marker(&self) -> String {
        format!(
            "{}/family/drain/{}/contract",
            self.enrollment.namespace, self.enrollment.operation_key
        )
    }
    pub fn validate_origin(&self, o: &Origin) -> Result<(Grant, Grant)> {
        let r = &self.selection.registration;
        let n = r
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&self.selection.child_id)?;
        let verified = n
            .forward()?
            .lineage
            .grants
            .verify_retained(o.signed_grant.as_bytes())?;
        let g = &verified.grant;
        r.child(&n.child_id)?.reservation.grant(g)?;
        let e = &self.enrollment;
        let c = &self.physical.contract;
        let a = &o.original;
        let journal = json!({"profile":crate::recovery::PROFILE,"attempt_id":a.attempt_id,"root_id":g.root_id,"grant_digest":verified.digest,"phase":"dispatch_authorized","event_time":a.dispatched_at});
        let expected = Original {
            profile: crate::physical_operations::PROFILE.into(),
            enrollment_digest: e.digest()?,
            policy_digest: e.policy.digest()?,
            family_registration_digest: r.digest()?,
            child_id: n.child_id.clone(),
            operation_key: n.operation_key.clone(),
            root_id: g.root_id.clone(),
            grant_digest: verified.digest,
            attempt_id: a.attempt_id.clone(),
            contract_digest: c.digest()?,
            resource: c.resource()?,
            realm_uid: c.cluster_uid.clone(),
            node_uid: c.node.uid.clone(),
            dispatched_at: a.dispatched_at,
            native_dispatch_digest: digest("kube-drain-native-dispatch", &journal)?,
        };
        if a != &expected
            || a.attempt_id.is_empty()
            || a.attempt_id.len() > 256
            || a.dispatched_at < g.valid_from
            || a.dispatched_at >= g.expires_at
            || g.expires_at != o.grant_expires_at
            || g.action.id != crate::managed_drain::ACTION
            || g.adapter_contract != crate::managed_drain::adapter_contract()
        {
            return Err(refuse());
        }
        let sql_node = r
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&e.current_sql.forward_child_id)?;
        let sql = sql_node
            .forward()?
            .lineage
            .grants
            .verify_retained(o.forward_signed_grant.as_bytes())?;
        r.child(&sql_node.child_id)?.reservation.grant(&sql.grant)?;
        if sql.grant.action.id != crate::postgres_action::ACTION
            || sql.grant.resources != [e.current_sql.resource.clone()]
            || o.forward_attempt_id.is_empty()
            || o.forward_attempt_id.len() > 256
        {
            return Err(refuse());
        }
        Ok((verified.grant, sql.grant))
    }
    pub fn view(&self, o: &Origin, b: &crate::family_saga::AggregateBundle) -> Result<Observation> {
        let trust = crate::physical_operations::Trust {
            profile: crate::physical_operations::PROFILE.into(),
            enrollment_digest: self.enrollment.digest()?,
            policy_digest: self.enrollment.policy.digest()?,
            child_id: self.selection.child_id.clone(),
            physical: crate::family_saga::AuditTrust {
                registration: self.selection.registration.clone(),
            },
            observer: self.enrollment.operating_observer.clone(),
        };
        let (original, view) =
            crate::physical_operations::managed_input(b, &trust, &self.enrollment.policy)?;
        if original != o.original {
            return Err(refuse());
        }
        Ok(view)
    }
    fn validate_material(
        &self,
        o: &Origin,
        before: &Core,
        change: &Change,
        at: i64,
        records: &BTreeMap<String, Material>,
    ) -> Result<Option<Observation>> {
        let e = &self.enrollment;
        if let Change::Observed {
            aggregate_digest, ..
        } = change
        {
            let Some(Material::Aggregate(b)) = records.get(aggregate_digest) else {
                return Err(refuse());
            };
            return Ok(Some(self.view(o, b)?));
        }
        if let Change::DeliveryAcknowledged {
            acknowledgement_digest,
            ..
        } = change
        {
            let Some(Material::Acknowledgement(a)) = records.get(acknowledgement_digest) else {
                return Err(refuse());
            };
            let pin = crate::family_saga::ObserverPin {
                id: e.policy.incident_sink.id.clone(),
                keys: e.policy.incident_sink.acknowledgement_keys.clone(),
            };
            a.verify("incident_ack", &pin)?;
            let i = before.incident.as_ref().ok_or_else(refuse)?;
            if a.body.incident_id != i.id
                || a.body.event_digest != i.event_digest
                || a.body.received_at < i.opened_at
                || a.body.received_at > at
            {
                return Err(refuse());
            }
        }
        let pair = match change {
            Change::ControllerAccepted { proof_digest } => {
                Some((proof_digest, ControlKind::Accepted, 0))
            }
            Change::ControllerPending {
                sequence,
                proof_digest,
            } => Some((proof_digest, ControlKind::Pending, *sequence)),
            Change::SendChecked {
                sequence,
                proof_digest,
            } => Some((proof_digest, ControlKind::Send, *sequence)),
            Change::ClosedNoEffect { proof_digest } => {
                Some((proof_digest, ControlKind::ClosedNoEffect, 0))
            }
            Change::ClosedAbsence { proof_digest } => {
                Some((proof_digest, ControlKind::ClosedAbsence, 0))
            }
            _ => None,
        };
        if let Some((reference, kind, sequence)) = pair {
            let Some(Material::Controller(p)) = records.get(reference) else {
                return Err(refuse());
            };
            p.verify("controller_cas", &self.physical.controller)?;
            let v = &p.body;
            if v.kind != kind
                || v.sequence != sequence
                || v.origin_digest != o.digest()?
                || v.enrollment_digest != e.digest()?
                || v.policy_digest != e.policy.digest()?
                || v.checked_at != at
                || !crate::grant_reference::valid_reference(&v.mechanical_digest)
                || v.mechanical_header.profile != crate::kube_drain::PROFILE
                || v.mechanical_header.signer_id != self.physical.controller.id
                || !self
                    .physical
                    .controller
                    .keys
                    .contains_key(&v.mechanical_header.key_id)
            {
                return Err(refuse());
            }
            let expected_kind = if kind == ControlKind::ClosedAbsence {
                "closed_no_dispatch"
            } else {
                "controller_state"
            };
            if v.mechanical_header.kind != expected_kind {
                return Err(refuse());
            }
            if kind == ControlKind::Send {
                let a = v.native_authority.as_ref().ok_or_else(refuse)?;
                if a.checked_at > at
                    || at - a.checked_at > e.maximum_authorization_to_send_ms as i64
                    || a.native_dispatch_digest != o.original.native_dispatch_digest
                    || a.family.registration_digest != self.selection.registration.digest()?
                    || a.family.child_id != self.selection.child_id
                    || a.family.lane != "forward"
                {
                    return Err(refuse());
                }
            } else if v.native_authority.is_some() {
                return Err(refuse());
            }
            if matches!(
                kind,
                ControlKind::Accepted | ControlKind::Pending | ControlKind::Send
            ) {
                if crate::managed_drain_journal::add(at, e.clock_uncertainty_ms)? >= before.deadline
                {
                    return Err(refuse());
                }
                let reservation = if kind == ControlKind::Send {
                    let key = before.pending_proof.as_ref().ok_or_else(refuse)?;
                    let Some(Material::Controller(previous)) = records.get(key) else {
                        return Err(refuse());
                    };
                    if previous.body.kind != ControlKind::Pending
                        || previous.body.sequence != sequence
                        || previous.body.mechanical_digest != v.mechanical_digest
                        || at < previous.body.checked_at
                        || at - previous.body.checked_at > e.maximum_authorization_to_send_ms as i64
                        || json!(previous.body.sql) != json!(v.sql)
                    {
                        return Err(refuse());
                    }
                    previous
                        .body
                        .query_slot_digest
                        .as_deref()
                        .ok_or_else(refuse)?
                } else {
                    before
                        .pending
                        .as_ref()
                        .ok_or_else(refuse)?
                        .reservation_digest
                        .as_str()
                };
                if v.query_slot_digest.as_deref() != Some(reservation) {
                    return Err(refuse());
                }
                let (_, sql_grant) = self.validate_origin(o)?;
                let sql_digest = self
                    .selection
                    .registration
                    .composition
                    .as_ref()
                    .ok_or_else(refuse)?
                    .node(&e.current_sql.forward_child_id)?
                    .forward()?
                    .lineage
                    .grants
                    .verify_retained(o.forward_signed_grant.as_bytes())?
                    .digest;
                v.sql.as_ref().ok_or_else(refuse)?.validate_current(
                    e,
                    o,
                    reservation,
                    at,
                    &sql_grant,
                    &sql_digest,
                )?;
            } else if v.sql.is_some() || v.query_slot_digest.is_some() {
                return Err(refuse());
            }
        }
        Ok(None)
    }
}
#[derive(Clone)]
pub struct Store {
    pub(crate) ledger: EtcdLedger,
    pub context: Arc<Context>,
}
pub struct Loaded {
    pub origin: Origin,
    pub events: Vec<Event>,
    pub materials: BTreeMap<String, Material>,
    pub head_raw: String,
    pub origin_raw: String,
    pub marker_raw: String,
}
impl Loaded {
    pub fn head(&self) -> &Event {
        self.events
            .last()
            .expect("validated nonempty managed history")
    }
    pub fn state(&self) -> &Core {
        &self.head().after
    }
}
pub struct Prepared {
    pub compare: Vec<Value>,
    pub writes: Vec<Value>,
    pub event: Event,
}
impl Store {
    pub fn new(l: EtcdLedger) -> Result<Self> {
        let context = Arc::new(Context::from_ledger(&l)?);
        Ok(Self { ledger: l, context })
    }
    pub(crate) async fn load(&self) -> Result<Option<Loaded>> {
        let base = self.context.base();
        let prefix = format!("{base}/events/");
        let end = format!("{base}/events0");
        let records = format!("{base}/records/");
        let record_end = format!("{base}/records0");
        let read=self.ledger.txn(vec![],vec![get(&format!("{base}/origin")),get(&format!("{base}/head")),get(&self.context.marker()),
   json!({"request_range":{"key":STANDARD.encode(&prefix),"range_end":STANDARD.encode(&end),"limit":(MAX_EVENTS+1).to_string()}}),
   json!({"request_range":{"key":STANDARD.encode(&records),"range_end":STANDARD.encode(&record_end),"limit":"513"}})],vec![]).await?;
        if !read.succeeded || read.responses.len() != 5 {
            return Err(refuse());
        }
        let marker = range_kv(&read.responses[2])?.ok_or_else(refuse)?;
        if marker.value != record(&self.context.physical)?.as_bytes() {
            return Err(refuse());
        }
        let origin = range_kv(&read.responses[0])?;
        let head = range_kv(&read.responses[1])?;
        let decode_range =
            |i: usize, prefix: &str, limit: usize| -> Result<Vec<(String, Vec<u8>)>> {
                let range = read.responses[i]["response_range"]
                    .as_object()
                    .ok_or_else(refuse)?;
                if range.get("more").and_then(Value::as_bool) == Some(true) {
                    return Err(refuse());
                }
                let entries = match range.get("kvs") {
                    None => &[][..],
                    Some(Value::Array(a)) => a.as_slice(),
                    _ => return Err(refuse()),
                };
                if entries.len() > limit {
                    return Err(refuse());
                }
                let mut out = Vec::new();
                let mut size = 0;
                for entry in entries {
                    let key = STANDARD
                        .decode(entry["key"].as_str().ok_or_else(refuse)?)
                        .map_err(|_| refuse())?;
                    let key = String::from_utf8(key).map_err(|_| refuse())?;
                    let suffix = key.strip_prefix(prefix).ok_or_else(refuse)?.to_owned();
                    let data = STANDARD
                        .decode(entry["value"].as_str().ok_or_else(refuse)?)
                        .map_err(|_| refuse())?;
                    size += data.len();
                    if size > MAX_SOURCE_BYTES {
                        return Err(refuse());
                    }
                    out.push((suffix, data));
                }
                Ok(out)
            };
        let rows = decode_range(3, &prefix, MAX_EVENTS)?;
        let data = decode_range(4, &records, 512)?;
        let Some(origin) = origin else {
            if head.is_some() || !rows.is_empty() || !data.is_empty() {
                return Err(refuse());
            }
            return Ok(None);
        };
        let head = head.ok_or_else(refuse)?;
        let origin_raw = String::from_utf8(origin.value).map_err(|_| refuse())?;
        let o: Origin = serde_json::from_value(strict_value(origin_raw.as_bytes())?)?;
        self.context.validate_origin(&o)?;
        let mut materials = BTreeMap::new();
        for (key, raw) in data {
            let m: Material = serde_json::from_value(strict_value(&raw)?)?;
            if key != m.digest()? || materials.insert(key, m).is_some() {
                return Err(refuse());
            }
        }
        let mut events = Vec::new();
        let mut state = Core::initial(&self.context.enrollment, &o)?;
        let mut used = BTreeSet::new();
        for (index, (name, raw)) in rows.into_iter().enumerate() {
            let e: Event = serde_json::from_value(strict_value(&raw)?)?;
            e.bound()?;
            if name != format!("{:04}", index + 1) {
                return Err(refuse());
            }
            let view = self
                .context
                .validate_material(&o, &state, &e.change, e.at, &materials)?;
            if let Change::ControllerAccepted { proof_digest }
            | Change::ControllerPending { proof_digest, .. }
            | Change::SendChecked { proof_digest, .. }
            | Change::ClosedNoEffect { proof_digest }
            | Change::ClosedAbsence { proof_digest } = &e.change
            {
                let Some(Material::Controller(proof)) = materials.get(proof_digest) else {
                    return Err(refuse());
                };
                if Some(&proof.body.operating_head_digest) != e.previous_digest.as_ref() {
                    return Err(refuse());
                }
            }
            let expected = Event::new(
                events.last(),
                &state,
                &self.context.enrollment,
                &o,
                e.at,
                e.change.clone(),
                view.as_ref(),
            )?;
            if e != expected {
                return Err(refuse());
            }
            match &e.change {
                Change::Observed {
                    aggregate_digest, ..
                } => {
                    used.insert(aggregate_digest.clone());
                }
                Change::ControllerAccepted { proof_digest }
                | Change::ControllerPending { proof_digest, .. }
                | Change::SendChecked { proof_digest, .. }
                | Change::ClosedNoEffect { proof_digest }
                | Change::ClosedAbsence { proof_digest } => {
                    used.insert(proof_digest.clone());
                }
                Change::DeliveryAcknowledged {
                    acknowledgement_digest,
                    ..
                } => {
                    used.insert(acknowledgement_digest.clone());
                }
                _ => (),
            };
            state = e.after.clone();
            events.push(e);
        }
        let last = events.last().ok_or_else(refuse)?;
        let head_raw = String::from_utf8(head.value).map_err(|_| refuse())?;
        if head_raw != record(last)? || used != materials.keys().cloned().collect() {
            return Err(refuse());
        }
        Ok(Some(Loaded {
            origin: o,
            events,
            materials,
            head_raw,
            origin_raw,
            marker_raw: String::from_utf8(marker.value).map_err(|_| refuse())?,
        }))
    }
    pub(crate) fn prepare(
        &self,
        loaded: &Loaded,
        at: i64,
        change: Change,
        material: Option<Material>,
    ) -> Result<Prepared> {
        let base = self.context.base();
        let mut materials = loaded.materials.clone();
        let mut compare = vec![
            value_eq(&self.context.marker(), &loaded.marker_raw),
            value_eq(&format!("{base}/origin"), &loaded.origin_raw),
            value_eq(&format!("{base}/head"), &loaded.head_raw),
        ];
        let mut writes = Vec::new();
        if let Some(m) = material {
            let key = m.digest()?;
            let expected = match &change {
                Change::Observed {
                    aggregate_digest, ..
                } => aggregate_digest,
                Change::ControllerAccepted { proof_digest }
                | Change::ControllerPending { proof_digest, .. }
                | Change::SendChecked { proof_digest, .. }
                | Change::ClosedNoEffect { proof_digest }
                | Change::ClosedAbsence { proof_digest } => proof_digest,
                Change::DeliveryAcknowledged {
                    acknowledgement_digest,
                    ..
                } => acknowledgement_digest,
                _ => return Err(refuse()),
            };
            if &key != expected {
                return Err(refuse());
            }
            let path = format!("{base}/records/{key}");
            let raw = record(&m)?;
            if let Some(old) = materials.get(&key) {
                if record(old)? != raw {
                    return Err(refuse());
                }
                compare.push(value_eq(&path, &raw));
            } else {
                compare.push(version_zero(&path));
                writes.push(put(&path, &raw));
                materials.insert(key, m);
            }
        }
        let view = self.context.validate_material(
            &loaded.origin,
            loaded.state(),
            &change,
            at,
            &materials,
        )?;
        if let Change::ControllerAccepted { proof_digest }
        | Change::ControllerPending { proof_digest, .. }
        | Change::SendChecked { proof_digest, .. }
        | Change::ClosedNoEffect { proof_digest }
        | Change::ClosedAbsence { proof_digest } = &change
        {
            let Some(Material::Controller(proof)) = materials.get(proof_digest) else {
                return Err(refuse());
            };
            if proof.body.operating_head_digest != loaded.head().digest()? {
                return Err(refuse());
            }
        }
        let event = Event::new(
            Some(loaded.head()),
            loaded.state(),
            &self.context.enrollment,
            &loaded.origin,
            at,
            change,
            view.as_ref(),
        )?;
        let path = format!("{base}/events/{:04}", event.sequence);
        compare.push(version_zero(&path));
        writes.push(put(&path, &record(&event)?));
        writes.push(put(&format!("{base}/head"), &record(&event)?));
        Ok(Prepared {
            compare,
            writes,
            event,
        })
    }
    pub(crate) async fn apply(
        &self,
        loaded: &Loaded,
        at: i64,
        change: Change,
        material: Option<Material>,
    ) -> Result<Event> {
        let p = self.prepare(loaded, at, change, material)?;
        if !self
            .ledger
            .txn(p.compare, p.writes, vec![])
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(p.event)
    }
    pub(crate) async fn tick(&self, at: i64) -> Result<Option<Loaded>> {
        for _ in 0..3 {
            let Some(s) = self.load().await? else {
                return Ok(None);
            };
            if !s.state().due(at) {
                return Ok(Some(s));
            }
            let p = self.prepare(&s, at, Change::Escalated, None)?;
            if self
                .ledger
                .txn(p.compare, p.writes, vec![])
                .await?
                .succeeded
            {
                return self.load().await;
            }
        }
        Err(refuse())
    }
}
pub(crate) async fn dispatch_anchor(
    l: &EtcdLedger,
    g: &Grant,
    gd: &str,
    attempt: &str,
    at: i64,
) -> Result<(Vec<Value>, Vec<Value>)> {
    if g.action.id != crate::managed_drain::ACTION {
        return Ok((vec![], vec![]));
    }
    let store = Store::new(l.clone())?;
    let c = &store.context;
    let r = &c.selection.registration;
    let n = r
        .composition
        .as_ref()
        .ok_or_else(refuse)?
        .node(&c.selection.child_id)?;
    let current = l
        .recovery_snapshot(&Candidate {
            grant: g.clone(),
            attempt_id: attempt.into(),
        })
        .await?;
    current.context.validate(g, gd)?;
    let e = &c.enrollment;
    let sql_node = r
        .composition
        .as_ref()
        .ok_or_else(refuse)?
        .node(&e.current_sql.forward_child_id)?;
    let sql_issue_key = format!("{}/issuance/{}", l.namespace(), sql_node.operation_key);
    let sql_raw = l.read_key(&sql_issue_key).await?.ok_or_else(refuse)?;
    let sql_record: IssuanceRecord = serde_json::from_value(strict_value(&sql_raw)?)?;
    let sql_grant = sql_node
        .forward()?
        .lineage
        .grants
        .verify_retained(sql_record.signed_grant.as_bytes())?;
    let sql_ledger = crate::family_saga_runtime::child_ledger(l, r, &sql_node.child_id, false)?;
    let sql_attempt = sql_ledger
        .read_key(&sql_ledger.nonce(&sql_grant.grant))
        .await?
        .ok_or_else(refuse)?;
    let sql_attempt = String::from_utf8(sql_attempt).map_err(|_| refuse())?;
    let sql_snapshot = sql_ledger
        .recovery_snapshot(&Candidate {
            grant: sql_grant.grant.clone(),
            attempt_id: sql_attempt.clone(),
        })
        .await?;
    if sql_snapshot.attempt.status != "committed"
        || sql_record.grant_digest != sql_grant.digest
        || sql_record.issuance_key != sql_node.operation_key
    {
        return Err(refuse());
    }
    let receipt = sql_snapshot.head.as_ref().ok_or_else(refuse)?;
    let signed = crate::schema::verify_record(
        receipt.signed_receipt.as_bytes(),
        "receipt",
        &sql_node.forward()?.lineage.outcome_keys,
    )?;
    if signed.payload["status"] != "committed"
        || signed.payload["grant_digest"] != sql_grant.digest
        || signed.payload["attempt_id"] != sql_attempt
    {
        return Err(refuse());
    }
    let journal = json!({"profile":crate::recovery::PROFILE,"attempt_id":attempt,"root_id":g.root_id,"grant_digest":gd,"phase":"dispatch_authorized","event_time":at});
    let physical = &c.physical.contract;
    let origin = Origin {
        original: Original {
            profile: crate::physical_operations::PROFILE.into(),
            enrollment_digest: e.digest()?,
            policy_digest: e.policy.digest()?,
            family_registration_digest: r.digest()?,
            child_id: n.child_id.clone(),
            operation_key: n.operation_key.clone(),
            root_id: g.root_id.clone(),
            grant_digest: gd.into(),
            attempt_id: attempt.into(),
            contract_digest: physical.digest()?,
            resource: physical.resource()?,
            realm_uid: physical.cluster_uid.clone(),
            node_uid: physical.node.uid.clone(),
            dispatched_at: at,
            native_dispatch_digest: digest("kube-drain-native-dispatch", &journal)?,
        },
        signed_grant: current.context.signed_grant,
        forward_signed_grant: sql_record.signed_grant,
        forward_attempt_id: sql_attempt.clone(),
        grant_expires_at: g.expires_at,
    };
    c.validate_origin(&origin)?;
    let initial = Core::initial(e, &origin)?;
    let event = Event::new(None, &initial, e, &origin, at, Change::Dispatched, None)?;
    let base = c.base();
    let marker_raw = record(&c.physical)?;
    let mut compare = vec![
        value_eq(&c.marker(), &marker_raw),
        version_zero(&format!("{base}/origin")),
        version_zero(&format!("{base}/head")),
        version_zero(&format!("{base}/events/0001")),
        value_eq(&context_key(l, g, attempt), &current.context_raw),
        value_eq(
            &sql_issue_key,
            std::str::from_utf8(&sql_raw).map_err(|_| refuse())?,
        ),
        value_eq(&sql_ledger.nonce(&sql_grant.grant), &sql_attempt),
        value_eq(
            &sql_ledger.attempt(&sql_grant.grant, &sql_attempt),
            &record(&sql_snapshot.attempt)?,
        ),
    ];
    if let Some(head) = sql_snapshot.head_raw {
        compare.push(value_eq(
            &format!(
                "{}/receipt-head",
                sql_ledger.attempt(&sql_grant.grant, &sql_attempt)
            ),
            &head,
        ));
    }
    Ok((
        compare,
        vec![
            put(&format!("{base}/origin"), &record(&origin)?),
            put(&format!("{base}/head"), &record(&event)?),
            put(&format!("{base}/events/0001"), &record(&event)?),
        ],
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedQuery {
    pub origin: Origin,
    pub slot: crate::managed_drain_journal::Slot,
}
#[derive(Clone)]
pub struct ReservedDelivery {
    pub origin: Origin,
    pub incident: crate::managed_drain_journal::Incident,
    pub slot: crate::managed_drain_journal::DeliverySlot,
}
impl Store {
    pub async fn status(&self) -> Result<Option<Core>> {
        Ok(self.load().await?.map(|s| s.state().clone()))
    }
    /// This reserves the shared bounded observation cycle durably before I/O.
    /// Controller mutation authorization is a separate current native CAS.
    pub async fn reserve_query(
        &self,
        kind: crate::managed_drain_journal::QueryKind,
        at: i64,
    ) -> Result<ReservedQuery> {
        for _ in 0..3 {
            let s = self.tick(at).await?.ok_or_else(refuse)?;
            let number = s.state().before_queries + s.state().after_queries + 1;
            let prepared = self.prepare(
                &s,
                at,
                Change::QueryReserved {
                    query_kind: kind.clone(),
                    number,
                },
                None,
            )?;
            let slot = prepared
                .event
                .after
                .pending
                .as_ref()
                .ok_or_else(refuse)?
                .clone();
            if self
                .ledger
                .txn(prepared.compare, prepared.writes, vec![])
                .await?
                .succeeded
            {
                return Ok(ReservedQuery {
                    origin: s.origin,
                    slot,
                });
            }
        }
        Err(refuse())
    }
    pub async fn unavailable(&self, query: &ReservedQuery, at: i64, reason: &str) -> Result<()> {
        let s = self.tick(at).await?.ok_or_else(refuse)?;
        if s.origin != query.origin || s.state().pending.as_ref() != Some(&query.slot) {
            return Err(refuse());
        }
        self.apply(
            &s,
            at,
            Change::QueryUnavailable {
                number: query.slot.number,
                reason: reason.into(),
            },
            None,
        )
        .await?;
        Ok(())
    }
    pub async fn observe(
        &self,
        query: &ReservedQuery,
        at: i64,
        bundle: crate::family_saga::AggregateBundle,
    ) -> Result<()> {
        let s = self.tick(at).await?.ok_or_else(refuse)?;
        if s.origin != query.origin || s.state().pending.as_ref() != Some(&query.slot) {
            return Err(refuse());
        }
        let material = Material::Aggregate(Box::new(bundle));
        let digest = material.digest()?;
        self.apply(
            &s,
            at,
            Change::Observed {
                number: query.slot.number,
                aggregate_digest: digest,
            },
            Some(material),
        )
        .await?;
        Ok(())
    }
    pub async fn expire_query(&self, at: i64) -> Result<bool> {
        let Some(s) = self.tick(at).await? else {
            return Ok(false);
        };
        let Some(q) = s.state().pending.as_ref() else {
            return Ok(false);
        };
        if at < q.expires_at {
            return Ok(false);
        }
        self.apply(
            &s,
            at,
            Change::QueryUnavailable {
                number: q.number,
                reason: "interrupted".into(),
            },
            None,
        )
        .await?;
        Ok(true)
    }
    pub async fn escalate(&self, at: i64) -> Result<Option<Core>> {
        Ok(self.tick(at).await?.map(|s| s.state().clone()))
    }
    /// Reserve the stable owned outbox before contacting the incident sink.
    pub async fn reserve_delivery(&self, at: i64) -> Result<Option<ReservedDelivery>> {
        for _ in 0..3 {
            let Some(s) = self.tick(at).await? else {
                return Ok(None);
            };
            let Some(i) = s.state().incident.as_ref() else {
                return Ok(None);
            };
            if i.acknowledgement_digest.is_some()
                || i.attempts
                    >= self
                        .context
                        .enrollment
                        .policy
                        .incident_sink
                        .maximum_delivery_attempts
                || i.pending.is_some()
                || at < i.next_allowed_at
            {
                return Ok(None);
            }
            let p = self.prepare(
                &s,
                at,
                Change::DeliveryReserved {
                    number: i.attempts + 1,
                },
                None,
            )?;
            let incident = p.event.after.incident.clone().ok_or_else(refuse)?;
            let slot = incident.pending.clone().ok_or_else(refuse)?;
            if self
                .ledger
                .txn(p.compare, p.writes, vec![])
                .await?
                .succeeded
            {
                return Ok(Some(ReservedDelivery {
                    origin: s.origin,
                    incident,
                    slot,
                }));
            }
        }
        Err(refuse())
    }
    pub async fn expire_delivery(&self, at: i64) -> Result<bool> {
        let Some(s) = self.tick(at).await? else {
            return Ok(false);
        };
        let Some(q) = s.state().incident.as_ref().and_then(|i| i.pending.as_ref()) else {
            return Ok(false);
        };
        if at < q.expires_at {
            return Ok(false);
        }
        self.apply(
            &s,
            at,
            Change::DeliveryFailed {
                number: q.number,
                reason: "interrupted".into(),
            },
            None,
        )
        .await?;
        Ok(true)
    }
    fn match_delivery(&self, s: &Loaded, reserved: &ReservedDelivery) -> Result<()> {
        let i = s.state().incident.as_ref().ok_or_else(refuse)?;
        if s.origin != reserved.origin
            || i.id != reserved.incident.id
            || i.event_digest != reserved.incident.event_digest
            || i.pending.as_ref() != Some(&reserved.slot)
        {
            return Err(refuse());
        }
        Ok(())
    }
    pub async fn delivery_failed(&self, q: &ReservedDelivery, at: i64, reason: &str) -> Result<()> {
        let s = self.tick(at).await?.ok_or_else(refuse)?;
        self.match_delivery(&s, q)?;
        self.apply(
            &s,
            at,
            Change::DeliveryFailed {
                number: q.slot.number,
                reason: reason.into(),
            },
            None,
        )
        .await?;
        Ok(())
    }
    pub async fn delivery_acknowledged(
        &self,
        q: &ReservedDelivery,
        at: i64,
        ack: Ack,
    ) -> Result<()> {
        let s = self.tick(at).await?.ok_or_else(refuse)?;
        self.match_delivery(&s, q)?;
        self.apply(
            &s,
            at,
            Change::DeliveryAcknowledged {
                number: q.slot.number,
                acknowledgement_digest: ack.digest()?,
            },
            Some(Material::Acknowledgement(ack)),
        )
        .await?;
        Ok(())
    }
}
