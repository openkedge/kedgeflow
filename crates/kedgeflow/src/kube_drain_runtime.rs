//! Native original acceptance and per-step authority CAS for Level C drain.
use crate::{
    clock::Clock,
    contracts::{Grant, GrantVerifier, digest, strict_value},
    error::{Error, Result},
    family::{Access, Selection},
    governance::EnforcementScope,
    kube_drain::{Contract, PROFILE},
    kube_drain_api::Api,
    kube_drain_journal::{Accepted, Authority, Closed, Mutation, Pending, Response, State, Step},
    kube_drain_proof::{NoDispatch, Signed, Trust},
    ledger::{EtcdLedger, expected_root, put, record, value_eq, version_zero},
    recovery::{Candidate, context_key, journal_key},
    target_token::{TargetTokenVerifier, TokenBinding},
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::sync::Arc;
fn refuse() -> Error {
    Error::Refused("native Kubernetes drain authority or original operation refused".into())
}
pub(crate) fn base(l: &EtcdLedger, op: &str) -> String {
    format!("{}/family/drain/{op}", l.namespace())
}
pub struct Controller {
    ledger: EtcdLedger,
    selection: Selection,
    trust: Trust,
    api: Arc<Api>,
    grants: GrantVerifier,
    tokens: TargetTokenVerifier,
    gateway_workload: String,
    target_audience: String,
    target_scope: String,
    key_id: String,
    key: SigningKey,
    clock: Arc<dyn Clock>,
    operating: Option<crate::managed_drain_runtime::Guard>,
}
impl Controller {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger: EtcdLedger,
        trust: Trust,
        api: Arc<Api>,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        gateway_workload: String,
        target_audience: String,
        target_scope: String,
        key_id: String,
        key: SigningKey,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        Self::construct(
            ledger,
            trust,
            api,
            grants,
            tokens,
            gateway_workload,
            target_audience,
            target_scope,
            key_id,
            key,
            clock,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new_managed(
        ledger: EtcdLedger,
        trust: Trust,
        api: Arc<Api>,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        gateway_workload: String,
        target_audience: String,
        target_scope: String,
        key_id: String,
        key: SigningKey,
        clock: Arc<dyn Clock>,
        sql: Arc<dyn crate::current_reservation_client::Querier>,
    ) -> Result<Self> {
        Self::construct(
            ledger,
            trust,
            api,
            grants,
            tokens,
            gateway_workload,
            target_audience,
            target_scope,
            key_id,
            key,
            clock,
            Some(sql),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn construct(
        ledger: EtcdLedger,
        trust: Trust,
        api: Arc<Api>,
        grants: GrantVerifier,
        tokens: TargetTokenVerifier,
        gateway_workload: String,
        target_audience: String,
        target_scope: String,
        key_id: String,
        key: SigningKey,
        clock: Arc<dyn Clock>,
        sql: Option<Arc<dyn crate::current_reservation_client::Querier>>,
    ) -> Result<Self> {
        trust.validate()?;
        if trust.operating.is_some() != sql.is_some() {
            return Err(refuse());
        }
        if let Some(e) = &trust.operating
            && (e.target_audience != target_audience || e.target_scope != target_scope)
        {
            return Err(refuse());
        }
        let Some(access) = &ledger.family else {
            return Err(refuse());
        };
        let Access::Child(selection) = access.as_ref() else {
            return Err(refuse());
        };
        let node = selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&selection.child_id)?;
        if node.physical.as_ref() != Some(&trust)
            || selection.registration.namespace != ledger.namespace()
            || crate::control_config::keys(&trust.controller.keys)?.get(&key_id)
                != Some(&key.verifying_key())
            || gateway_workload.is_empty()
            || target_scope.is_empty()
        {
            return Err(refuse());
        }
        crate::grant_reference::fixed_https(&target_audience)?;
        let native = node.forward()?;
        if native.lineage.grants.keys != grants.keys
            || native.lineage.grants.audience != grants.audience
        {
            return Err(refuse());
        }
        let operating = match sql {
            Some(sql) => Some(crate::managed_drain_runtime::Guard::new(
                crate::managed_drain_store::Store::new(ledger.clone())?,
                sql,
                clock.clone(),
            )?),
            None => None,
        };
        Ok(Self {
            operating,
            selection: selection.clone(),
            ledger,
            trust,
            api,
            grants,
            tokens,
            gateway_workload,
            target_audience,
            target_scope,
            key_id,
            key,
            clock,
        })
    }
    pub fn contract(&self) -> &Contract {
        &self.trust.contract
    }
    pub fn operation_key(&self) -> Result<&str> {
        Ok(&self
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&self.selection.child_id)?
            .operation_key)
    }
    fn key(&self, suffix: &str) -> Result<String> {
        Ok(format!(
            "{}/{}",
            base(&self.ledger, self.operation_key()?),
            suffix
        ))
    }
    async fn marker(&self) -> Result<Vec<Value>> {
        let key = self.key("contract")?;
        let value = record(&self.trust)?;
        if self.ledger.read_key(&key).await?.as_deref() != Some(value.as_bytes()) {
            return Err(refuse());
        }
        Ok(vec![value_eq(&key, &value)])
    }
    fn grant(&self, raw: &str) -> Result<crate::contracts::VerifiedGrant> {
        let v = self.grants.verify_retained(raw.as_bytes())?;
        let c = self.contract();
        self.selection
            .registration
            .child(&self.selection.child_id)?
            .reservation
            .grant(&v.grant)?;
        if v.grant.action.id != self.trust.action()
            || v.grant.action.version != self.trust.version()
            || v.grant.resources != [c.resource()?]
            || v.grant.adapter_contract != self.trust.adapter()
        {
            return Err(refuse());
        }
        Ok(v)
    }
    pub async fn state(&self) -> Result<Option<Signed<State>>> {
        let values = self
            .ledger
            .read_keys(&[self.key("contract")?, self.key("state")?])
            .await?;
        if values[0].as_deref() != Some(record(&self.trust)?.as_bytes()) {
            return Err(refuse());
        }
        let Some(raw) = values[1].as_ref() else {
            return Ok(None);
        };
        if raw.len() > crate::kube_drain_journal::MAX_STATE {
            return Err(refuse());
        }
        let state: Signed<State> = serde_json::from_value(strict_value(raw)?)?;
        state.verify("controller_state", &self.trust.controller)?;
        if record(&state)?.as_bytes() != raw.as_slice() {
            return Err(refuse());
        }
        let g = self.grant(&state.body.accepted.signed_grant)?;
        if g.digest != state.body.accepted.grant_digest {
            return Err(refuse());
        }
        state.body.validate(self.contract(), &g.grant)?;
        Ok(Some(state))
    }
    async fn native(&self, g: &Grant, gd: &str, attempt: &str) -> Result<(Vec<Value>, Authority)> {
        let mut compares = self.marker().await?;
        let candidate = Candidate {
            grant: g.clone(),
            attempt_id: attempt.into(),
        };
        let s = self.ledger.recovery_snapshot(&candidate).await?;
        if s.attempt.grant_digest != gd
            || !["dispatch_authorized", "committed", "unknown"].contains(&s.outbox.as_str())
        {
            return Err(refuse());
        }
        let dispatch_key = journal_key(&self.ledger, g, attempt, "dispatch_authorized");
        let raw = self
            .ledger
            .read_key(&dispatch_key)
            .await?
            .ok_or_else(refuse)?;
        let dispatch = strict_value(&raw)?;
        crate::recovery::validate(&dispatch)?;
        if dispatch["phase"] != "dispatch_authorized"
            || dispatch["attempt_id"] != attempt
            || dispatch["grant_digest"] != gd
            || dispatch["root_id"] != g.root_id
        {
            return Err(refuse());
        }
        let mut root = expected_root(g);
        root.status = "claimed".into();
        compares.extend([
            value_eq(&self.ledger.root(g), &record(&root)?),
            value_eq(&self.ledger.grant_key(g), gd),
            value_eq(&self.ledger.nonce(g), attempt),
            value_eq(&self.ledger.attempt(g, attempt), &record(&s.attempt)?),
            value_eq(&self.ledger.outbox(g, attempt), &s.outbox),
            value_eq(&context_key(&self.ledger, g, attempt), &s.context_raw),
            value_eq(
                &dispatch_key,
                std::str::from_utf8(&raw).map_err(|_| refuse())?,
            ),
        ]);
        let gate = self
            .ledger
            .reservation_gate_for(&g.conflict_domain, true)
            .await?
            .ok_or_else(refuse)?;
        if !gate.state.active {
            return Err(refuse());
        }
        // The gate just validated the actual head and last event against this
        // reservation state, and compares both exact bytes in our eventual CAS.
        // Re-reading the whole prefix only to recover the same last digest adds
        // latency without another invariant. Full prefix export/replay is kept
        // in the independent audit; every native() call still reads a fresh gate.
        let reservation_head = gate.history_head.as_ref().ok_or_else(refuse)?.clone();
        compares.extend(gate.compare);
        let control = self
            .ledger
            .control_check(
                &EnforcementScope::grant(g)?,
                &g.policy,
                g.ownership_epoch,
                Some(&g.root_id),
                Some(&g.gid),
            )
            .await?;
        compares.extend(control.compare);
        let control_state = control.state.ok_or_else(refuse)?;
        Ok((
            compares,
            Authority {
                checked_at: control_state.checked_at,
                control: control_state,
                family: control.family.ok_or_else(refuse)?,
                native_dispatch_digest: digest("kube-drain-native-dispatch", &dispatch)?,
                reservation_head,
            },
        ))
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn accept(
        &self,
        signed_grant: String,
        attempt_id: String,
        parameters: Value,
        token: &str,
    ) -> Result<Signed<State>> {
        let v = self.grant(&signed_grant)?;
        let g = &v.grant;
        let c = self.contract();
        let now = self.clock.now_ms();
        self.grants.verify(signed_grant.as_bytes(), now)?;
        if parameters != json!({"node":c.node.name,"expected_version":c.generation})
            || digest("parameters", &parameters)? != g.parameters_digest
        {
            return Err(Error::Refused(
                "drain acceptance exact parameters refused".into(),
            ));
        }
        let claims = self.tokens.verify(
            token,
            &TokenBinding {
                grant_digest: v.digest.clone(),
                root_id: g.root_id.clone(),
                attempt_id: attempt_id.clone(),
                gateway_workload: self.gateway_workload.clone(),
                audience: self.target_audience.clone(),
                scope: self.target_scope.clone(),
                max_expires_at: g.expires_at,
            },
            now,
        )?;
        if let Some(s) = self.state().await? {
            if s.body.accepted.signed_grant != signed_grant
                || s.body.accepted.attempt_id != attempt_id
                || s.body.accepted.permit_id != claims.permit_id
            {
                return Err(refuse());
            }
            return Ok(s);
        }
        let n = self
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&self.selection.child_id)?;
        let trust = n.forward()?;
        let auth = self
            .ledger
            .export_authorization(self.operation_key()?)
            .await?;
        crate::lineage::verify_authorization(&auth, &trust.lineage)?;
        if auth.issuance.grant_digest != v.digest {
            return Err(refuse());
        }
        let descriptor = crate::schema::verify_record(
            auth.packet.descriptor.as_bytes(),
            "ctd",
            &trust.lineage.admission.registry_keys,
        )?;
        if descriptor.payload["parameter_schema"] != self.trust.schema()? {
            return Err(refuse());
        }
        let permit_key = format!("{}/credential-permit", self.ledger.attempt(g, &attempt_id));
        let permit_raw = self
            .ledger
            .read_key(&permit_key)
            .await?
            .ok_or_else(refuse)?;
        let permit = strict_value(&permit_raw)?;
        crate::broker_authorization::validate_permit(&permit)?;
        if permit["permit_id"] != claims.permit_id
            || permit["grant_digest"] != v.digest
            || permit["attempt_id"] != attempt_id
            || permit["root_id"] != g.root_id
            || permit["gateway_workload"] != self.gateway_workload
            || permit["target_audience"] != self.target_audience
            || permit["target_scope"] != self.target_scope
        {
            return Err(Error::Refused(
                "drain acceptance original credential permit binding refused".into(),
            ));
        }
        let admission_checked_at = self.clock.now_ms();
        let managed_query = if let Some(guard) = &self.operating {
            Some(
                guard
                    .reserve(crate::managed_drain_journal::QueryKind::Accept)
                    .await?,
            )
        } else {
            None
        };
        if let Some(q) = &managed_query
            && (q.origin.original.grant_digest != v.digest
                || q.origin.original.attempt_id != attempt_id)
        {
            return Err(refuse());
        }
        let initial = self.api.inventory(c).await?;
        initial.availability(c)?;
        let inventory_checked_at = self.clock.now_ms();
        let current_sql = match (&self.operating, &managed_query) {
            (Some(guard), Some(q)) => Some(guard.current_sql(q).await?),
            _ => None,
        };
        let source_checked_at = self.clock.now_ms();
        let (mut compare, authority) = Box::pin(self.native(g, &v.digest, &attempt_id))
            .await
            .map_err(|e| match e {
                Error::Refused(message) => Error::Refused(format!(
                    "drain acceptance native authority refused: {message}"
                )),
                other => other,
            })?;
        compare.extend([
            value_eq(
                &permit_key,
                std::str::from_utf8(&permit_raw).map_err(|_| refuse())?,
            ),
            version_zero(&self.key("state")?),
            version_zero(&self.key("gate")?),
        ]);
        let accepted_at = self.clock.now_ms();
        if accepted_at >= g.expires_at || accepted_at >= claims.exp * 1000 {
            return Err(Error::Refused(format!(
                "drain acceptance protected-clock expiry refused: grant_remaining={}ms; token_remaining={}ms; admission={}ms; reserve_inventory={}ms; source={}ms; native={}ms",
                g.expires_at.saturating_sub(accepted_at),
                (claims.exp * 1000).saturating_sub(accepted_at),
                admission_checked_at.saturating_sub(now),
                inventory_checked_at.saturating_sub(admission_checked_at),
                source_checked_at.saturating_sub(inventory_checked_at),
                accepted_at.saturating_sub(source_checked_at)
            )));
        }
        let deferred_until = accepted_at
            .checked_add(c.maximum_deferred_ms as i64)
            .ok_or_else(refuse)?
            .min(self.selection.registration.expires_at);
        let state = State {
            accepted: Accepted {
                profile: PROFILE.into(),
                contract_digest: c.digest()?,
                signed_grant,
                grant_digest: v.digest,
                attempt_id,
                permit_id: claims.permit_id,
                accepted_at,
                deferred_until,
                initial,
                authority,
            },
            steps: vec![],
            closed: None,
        };
        state.validate(c, g)?;
        let signed = Signed::sign(
            "controller_state",
            state,
            &self.trust.controller,
            &self.key_id,
            &self.key,
        )?;
        let mut writes = vec![put(&self.key("state")?, &record(&signed)?)];
        if let (Some(guard), Some(q), Some(sql)) = (&self.operating, &managed_query, current_sql) {
            let p = guard
                .prepare_control(
                    q,
                    &signed,
                    sql,
                    crate::managed_drain_evidence::ControlKind::Accepted,
                    accepted_at,
                    &self.key_id,
                    &self.key,
                )
                .await?
                .0;
            compare.extend(p.compare);
            writes.extend(p.writes);
        }
        if !self.ledger.txn(compare, writes, vec![]).await?.succeeded {
            return Err(Error::Refused(
                "drain acceptance native expected-head comparison raced".into(),
            ));
        }
        Ok(signed)
    }
}
impl Controller {
    /// One newly authorized API request at most. A retained Pending/unknown
    /// returns its original state and cannot reach the mutation client again.
    pub async fn advance(&self) -> Result<Signed<State>> {
        let old = self.state().await?.ok_or_else(refuse)?;
        let c = self.contract();
        if old.body.closed.is_some()
            || old.body.steps.last().is_some_and(|s| {
                s.response.as_ref().is_none_or(|r| {
                    r.http_status == 0
                        || !(200..300).contains(&r.http_status) && r.http_status != 429
                })
            })
        {
            return Ok(old);
        }
        let v = self.grant(&old.body.accepted.signed_grant)?;
        let managed_query = if let Some(guard) = &self.operating {
            guard.validate_state(&old).await?;
            Some(
                guard
                    .reserve(crate::managed_drain_journal::QueryKind::Advance)
                    .await?,
            )
        } else {
            None
        };
        let inventory = self.api.inventory(c).await?;
        inventory.availability(c)?;
        let operation = old.body.accepted.operation()?;
        if old.body.physical_status(c, &inventory)? == "observed_completed" {
            if let (Some(guard), Some(q)) = (&self.operating, &managed_query) {
                guard.no_action(q).await?;
            }
            return Ok(old);
        }
        let (mutation, path, request, patch) = if old.body.steps.is_empty() {
            (
                Mutation::Cordon,
                format!("/api/v1/nodes/{}", c.node.name),
                crate::kube_drain_api::cordon_request(c, inventory.target(c)?, &operation)?,
                true,
            )
        } else {
            let pod=inventory.target_pods.iter().filter(|p|!inventory.ignored(c,p)).find(|p|old.body.accepted.initial.target_pods.iter().any(|original|original.object==p.object) && !old.body.steps.iter().any(|s|matches!(&s.pending.mutation,Mutation::Evict{original_uid} if original_uid==&p.object.object.uid) && s.response.as_ref().is_none_or(|r|r.http_status!=429)));
            let Some(pod) = pod else {
                if let (Some(guard), Some(q)) = (&self.operating, &managed_query) {
                    guard.no_action(q).await?;
                }
                return Ok(old);
            };
            (
                Mutation::Evict {
                    original_uid: pod.object.object.uid.clone(),
                },
                format!(
                    "/api/v1/namespaces/{}/pods/{}/eviction",
                    pod.object.namespace, pod.object.object.name
                ),
                crate::kube_drain_api::eviction_request(c, pod)?,
                false,
            )
        };
        let current_sql = match (&self.operating, &managed_query) {
            (Some(guard), Some(q)) => Some(guard.current_sql(q).await?),
            _ => None,
        };
        let (mut compare, authority) =
            Box::pin(self.native(&v.grant, &v.digest, &old.body.accepted.attempt_id)).await?;
        let authorized_at = self.clock.now_ms();
        if authorized_at < old.body.accepted.accepted_at
            || authorized_at >= old.body.accepted.deferred_until
        {
            return Err(refuse());
        }
        let mut next = old.body.clone();
        next.steps.push(Step {
            pending: Pending {
                sequence: next.steps.len() as u64 + 1,
                mutation,
                inventory,
                authority,
                authorized_at,
                path: path.clone(),
                request: request.clone(),
            },
            response: None,
        });
        next.validate(c, &v.grant)?;
        compare.extend([
            value_eq(&self.key("state")?, &record(&old)?),
            version_zero(&self.key("gate")?),
        ]);
        let pending = Signed::sign(
            "controller_state",
            next,
            &self.trust.controller,
            &self.key_id,
            &self.key,
        )?;
        let mut writes = vec![put(&self.key("state")?, &record(&pending)?)];
        let mut pending_check = None;
        if let (Some(guard), Some(q), Some(sql)) = (&self.operating, &managed_query, current_sql) {
            let (p, verified) = guard
                .prepare_control(
                    q,
                    &pending,
                    sql,
                    crate::managed_drain_evidence::ControlKind::Pending,
                    authorized_at,
                    &self.key_id,
                    &self.key,
                )
                .await?;
            pending_check = verified;
            compare.extend(p.compare);
            writes.extend(p.writes);
        }
        if !self.ledger.txn(compare, writes, vec![]).await?.succeeded {
            return Err(refuse());
        }
        // No retry wrapper. A crash here leaves exactly the durable original
        // Pending record, regardless of whether Kubernetes received the bytes.
        if let Some(guard) = &self.operating {
            let (native_compare, authority) =
                Box::pin(self.native(&v.grant, &v.digest, &old.body.accepted.attempt_id)).await?;
            let mut compares = native_compare.clone();
            let send_at = self.clock.now_ms();
            let (p, check) = guard
                .prepare_send(
                    &pending,
                    pending_check.as_ref().ok_or_else(refuse)?,
                    authority,
                    send_at,
                    &self.key_id,
                    &self.key,
                )
                .await?;
            compares.extend(p.compare);
            compares.push(value_eq(&self.key("state")?, &record(&pending)?));
            compares.push(version_zero(&self.key("gate")?));
            if !self.ledger.txn(compares, p.writes, vec![]).await?.succeeded {
                return Err(refuse());
            }
            guard.before_io(&pending, &check, native_compare).await?;
        }
        let result = self.api.mutate(&path, &request, patch).await;
        let response = match result {
            Ok((status, body)) => Response {
                http_status: status,
                body_digest: Some(digest("kube-drain-api-response", &body)?),
                recorded_at: self.clock.now_ms(),
            },
            Err(_) => Response {
                http_status: 0,
                body_digest: None,
                recorded_at: self.clock.now_ms(),
            },
        };
        let mut finished = pending.body.clone();
        finished.steps.last_mut().ok_or_else(refuse)?.response = Some(response);
        finished.validate(c, &v.grant)?;
        let signed = Signed::sign(
            "controller_state",
            finished,
            &self.trust.controller,
            &self.key_id,
            &self.key,
        )?;
        // Historical result retention remains possible after stop/expiry. It
        // cannot create another Pending request or reopen current authority.
        if !self
            .ledger
            .txn(
                vec![value_eq(&self.key("state")?, &record(&pending)?)],
                vec![put(&self.key("state")?, &record(&signed)?)],
                vec![],
            )
            .await?
            .succeeded
        {
            return Err(Error::Unknown(
                "original API result retention lost; query only".into(),
            ));
        }
        Ok(signed)
    }
    async fn closed_boundary(&self) -> Result<(Vec<Value>, String, String)> {
        let r = &self.selection.registration;
        let family_key = format!("{}/family/state", self.ledger.namespace());
        let family_raw = self
            .ledger
            .read_key(&family_key)
            .await?
            .ok_or_else(refuse)?;
        let f: crate::family::State = serde_json::from_value(strict_value(&family_raw)?)?;
        f.verify(r)?;
        let (p, _, mut compare) = crate::family_saga_runtime::retained(&self.ledger, r).await?;
        if f.active && p.phase == crate::family_saga::Phase::Forward {
            return Err(refuse());
        }
        compare.push(value_eq(
            &family_key,
            std::str::from_utf8(&family_raw).map_err(|_| refuse())?,
        ));
        compare.extend(self.marker().await?);
        Ok((compare, f.head, p.head))
    }
    /// Positively close acceptance while the global forward boundary is already
    /// permanently closed. A late accept compares both phase and this gate.
    pub async fn close_absent(
        &self,
        signed_grant: &str,
        attempt: &str,
    ) -> Result<Signed<NoDispatch>> {
        let v = self.grant(signed_grant)?;
        let candidate = Candidate {
            grant: v.grant,
            attempt_id: attempt.into(),
        };
        let snapshot = self.ledger.recovery_snapshot(&candidate).await?;
        if snapshot.attempt.grant_digest != v.digest {
            return Err(refuse());
        }
        let (mut compare, family_head, phase_head) = self.closed_boundary().await?;
        if let Some(raw) = self.ledger.read_key(&self.key("gate")?).await? {
            let old: Signed<NoDispatch> = serde_json::from_value(strict_value(&raw)?)?;
            old.verify("closed_no_dispatch", &self.trust.controller)?;
            if old.body.grant_digest != v.digest
                || old.body.attempt_id != attempt
                || old.body.contract_digest != self.contract().digest()?
            {
                return Err(refuse());
            }
            return Ok(old);
        }
        let proof = NoDispatch {
            profile: PROFILE.into(),
            contract_digest: self.contract().digest()?,
            operation_key: self.operation_key()?.into(),
            grant_digest: v.digest,
            attempt_id: attempt.into(),
            closed_at: self.clock.now_ms(),
            family_head,
            phase_head,
        };
        let signed = Signed::sign(
            "closed_no_dispatch",
            proof,
            &self.trust.controller,
            &self.key_id,
            &self.key,
        )?;
        compare.extend([
            version_zero(&self.key("state")?),
            version_zero(&self.key("gate")?),
        ]);
        let mut writes = vec![put(&self.key("gate")?, &record(&signed)?)];
        if let Some(guard) = &self.operating {
            let p = guard
                .prepare_absent(&signed, signed.body.closed_at, &self.key_id, &self.key)
                .await?;
            compare.extend(p.compare);
            writes.extend(p.writes);
        }
        if !self.ledger.txn(compare, writes, vec![]).await?.succeeded {
            return Err(refuse());
        }
        Ok(signed)
    }
    /// An accepted operation is no-effect only if its step gate closes before
    /// any Pending mutation has ever been authorized. It was still accepted.
    pub async fn close_unstarted(&self) -> Result<Signed<State>> {
        let old = self.state().await?.ok_or_else(refuse)?;
        if !old.body.steps.is_empty() {
            return Err(refuse());
        }
        if old.body.closed.is_some() {
            return Ok(old);
        }
        let (mut compare, family_head, phase_head) = self.closed_boundary().await?;
        let mut next = old.body.clone();
        next.closed = Some(Closed {
            closed_at: self.clock.now_ms(),
            family_head,
            phase_head,
        });
        let g = self.grant(&next.accepted.signed_grant)?;
        next.validate(self.contract(), &g.grant)?;
        let signed = Signed::sign(
            "controller_state",
            next,
            &self.trust.controller,
            &self.key_id,
            &self.key,
        )?;
        compare.push(value_eq(&self.key("state")?, &record(&old)?));
        let mut writes = vec![put(&self.key("state")?, &record(&signed)?)];
        if let Some(guard) = &self.operating {
            let at = signed.body.closed.as_ref().ok_or_else(refuse)?.closed_at;
            let p = guard
                .prepare_closed(&signed, at, &self.key_id, &self.key)
                .await?;
            compare.extend(p.compare);
            writes.extend(p.writes);
        }
        if !self.ledger.txn(compare, writes, vec![]).await?.succeeded {
            return Err(refuse());
        }
        Ok(signed)
    }
}

impl Controller {
    pub fn managed(&self) -> bool {
        self.operating.is_some()
    }
    pub fn acceptance_profile(&self) -> &str {
        if self.managed() {
            crate::managed_drain::PROFILE
        } else {
            crate::kube_drain::PROFILE
        }
    }
    pub async fn managed_tick(&self) -> Result<()> {
        if let Some(guard) = &self.operating {
            guard.tick().await?;
        }
        Ok(())
    }
    pub async fn scheduled_advance(&self) -> Result<()> {
        if let Some(guard) = &self.operating {
            guard.tick().await?;
            if !guard.may_advance().await? {
                return Ok(());
            }
        }
        if self.state().await?.is_some() {
            self.advance().await?;
        }
        Ok(())
    }
}

impl Controller {
    pub async fn acceptance_result(&self, state: Signed<State>) -> Result<Value> {
        match &self.operating {
            Some(guard) => Ok(json!(guard.acceptance(&state).await?)),
            None => Ok(json!(state)),
        }
    }
}
