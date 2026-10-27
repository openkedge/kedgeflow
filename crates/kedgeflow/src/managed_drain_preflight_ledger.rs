//! Native bounded pre-admission source claims and exact original SQL joins.
use super::managed_drain_store::Store;
use crate::{
    contracts::{Grant, strict_value},
    error::{Error, Result},
    ledger::{IssuanceRecord, get, put, range_kv, record, value_eq, version_zero},
    managed_drain_journal::Origin,
    recovery::Candidate,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
fn refuse() -> Error {
    Error::Refused("native original SQL/preflight source history refused".into())
}

impl Store {
    pub(crate) async fn preflight_history(
        &self,
    ) -> Result<Vec<crate::managed_drain_preflight::Claim>> {
        use crate::managed_drain_preflight::{Claim, MAX_OBSERVATIONS};
        let base = self.context.base();
        let prefix = format!("{base}/preflight/events/");
        let end = format!("{base}/preflight/events0");
        let read=self.ledger.txn(vec![],vec![get(&format!("{base}/preflight/head")),json!({"request_range":{"key":STANDARD.encode(&prefix),"range_end":STANDARD.encode(&end),"limit":(MAX_OBSERVATIONS+1).to_string()}})],vec![]).await?;
        if !read.succeeded
            || read.responses.len() != 2
            || read.responses[1]["response_range"]["more"].as_bool() == Some(true)
        {
            return Err(refuse());
        }
        let head = range_kv(&read.responses[0])?;
        let rows = match read.responses[1]["response_range"].get("kvs") {
            None => &[][..],
            Some(Value::Array(v)) => v.as_slice(),
            _ => return Err(refuse()),
        };
        if rows.len() > MAX_OBSERVATIONS {
            return Err(refuse());
        }
        let mut claims: Vec<Claim> = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let raw = STANDARD
                .decode(row["value"].as_str().ok_or_else(refuse)?)
                .map_err(|_| refuse())?;
            let key = STANDARD
                .decode(row["key"].as_str().ok_or_else(refuse)?)
                .map_err(|_| refuse())?;
            let claim: Claim = serde_json::from_value(strict_value(&raw)?)?;
            claim.validate(&self.context)?;
            if raw.len() > 1 << 20
                || record(&claim)?.as_bytes() != raw
                || key != format!("{prefix}{:04}", index + 1).as_bytes()
                || claim.sequence != index as u64 + 1
                || claim.previous_digest != claims.last().map(Claim::digest).transpose()?
                || claims.iter().any(|old| {
                    old.proposal_digest == claim.proposal_digest
                        || old.claimed_at > claim.claimed_at
                })
            {
                return Err(refuse());
            }
            claims.push(claim);
        }
        match (head, claims.last()) {
            (None, None) => (),
            (Some(head), Some(last)) if head.value == record(last)?.as_bytes() => (),
            _ => return Err(refuse()),
        }
        Ok(claims)
    }
    async fn preflight_boundary(&self, at: i64) -> Result<Vec<Value>> {
        let c = &self.context;
        let r = &c.selection.registration;
        if at < r.valid_from || at >= r.expires_at {
            return Err(refuse());
        }
        let family_key = format!("{}/family/state", self.ledger.namespace());
        let raw = self
            .ledger
            .read_key(&family_key)
            .await?
            .ok_or_else(refuse)?;
        let family: crate::family::State = serde_json::from_value(strict_value(&raw)?)?;
        family.verify(r)?;
        let (phase, _, mut compare) = crate::family_saga_runtime::retained(&self.ledger, r).await?;
        if !family.active || phase.phase != crate::family_saga::Phase::Forward {
            return Err(refuse());
        }
        compare.push(value_eq(
            &family_key,
            std::str::from_utf8(&raw).map_err(|_| refuse())?,
        ));
        compare.push(value_eq(&c.marker(), &record(&c.physical)?));
        compare.push(version_zero(&format!("{}/origin", c.base())));
        compare.push(version_zero(&format!(
            "{}/issuance/{}",
            self.ledger.namespace(),
            c.enrollment.operation_key
        )));
        Ok(compare)
    }
    async fn current_forward(
        &self,
    ) -> Result<(crate::managed_drain_preflight::Forward, Vec<Value>)> {
        use crate::managed_drain_preflight::Forward;
        let c = &self.context;
        let r = &c.selection.registration;
        let e = &c.enrollment;
        let n = r
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&e.current_sql.forward_child_id)?;
        let key = format!("{}/issuance/{}", self.ledger.namespace(), n.operation_key);
        let raw = self.ledger.read_key(&key).await?.ok_or_else(refuse)?;
        let issue: IssuanceRecord = serde_json::from_value(strict_value(&raw)?)?;
        let verified = n
            .forward()?
            .lineage
            .grants
            .verify_retained(issue.signed_grant.as_bytes())?;
        let sql = crate::family_saga_runtime::child_ledger(&self.ledger, r, &n.child_id, false)?;
        let attempt_raw = sql
            .read_key(&sql.nonce(&verified.grant))
            .await?
            .ok_or_else(refuse)?;
        let attempt = String::from_utf8(attempt_raw).map_err(|_| refuse())?;
        let snapshot = sql
            .recovery_snapshot(&Candidate {
                grant: verified.grant.clone(),
                attempt_id: attempt.clone(),
            })
            .await?;
        snapshot
            .context
            .validate(&verified.grant, &verified.digest)?;
        let head = snapshot.head.as_ref().ok_or_else(refuse)?;
        let receipt = crate::schema::verify_record(
            head.signed_receipt.as_bytes(),
            "receipt",
            &n.forward()?.lineage.outcome_keys,
        )?;
        let forward = Forward {
            signed_grant: issue.signed_grant,
            grant_digest: verified.digest.clone(),
            attempt_id: attempt.clone(),
        };
        c.forward_grant(&forward)?;
        if snapshot.attempt.status != "committed"
            || issue.grant_digest != verified.digest
            || issue.issuance_key != n.operation_key
            || receipt.payload["status"] != "committed"
            || receipt.payload["root_id"] != verified.grant.root_id
            || receipt.payload["grant_digest"] != verified.digest
            || receipt.payload["attempt_id"] != attempt
        {
            return Err(refuse());
        }
        let compare = vec![
            value_eq(&key, std::str::from_utf8(&raw).map_err(|_| refuse())?),
            value_eq(&sql.nonce(&verified.grant), &attempt),
            value_eq(
                &sql.attempt(&verified.grant, &attempt),
                &record(&snapshot.attempt)?,
            ),
            value_eq(
                &format!("{}/receipt-head", sql.attempt(&verified.grant, &attempt)),
                snapshot.head_raw.as_deref().ok_or_else(refuse)?,
            ),
        ];
        Ok((forward, compare))
    }
    pub async fn claim_admission_sql(
        &self,
        q: &crate::managed_drain_preflight::Request,
        at: i64,
    ) -> Result<crate::managed_drain_preflight::Claim> {
        use crate::managed_drain_preflight::{Claim, MAX_OBSERVATIONS};
        let (_, pd) = self.context.admission_proposal(q, at)?;
        let claims = self.preflight_history().await?;
        if claims.len() >= MAX_OBSERVATIONS || claims.iter().any(|c| c.proposal_digest == pd) {
            return Err(refuse());
        }
        let mut compare = self.preflight_boundary(at).await?;
        let (forward, sql_compare) = self.current_forward().await?;
        compare.extend(sql_compare);
        let r = &self.context.selection.registration;
        let family_key = format!("{}/family/state", self.ledger.namespace());
        // Retain the exact family/phase heads already compared by the boundary.
        let family_raw = self
            .ledger
            .read_key(&family_key)
            .await?
            .ok_or_else(refuse)?;
        let family: crate::family::State = serde_json::from_value(strict_value(&family_raw)?)?;
        family.verify(r)?;
        let (phase, _, phase_compare) =
            crate::family_saga_runtime::retained(&self.ledger, r).await?;
        compare.extend(phase_compare);
        compare.push(value_eq(
            &family_key,
            std::str::from_utf8(&family_raw).map_err(|_| refuse())?,
        ));
        let c = Claim {
            profile: crate::current_reservation::PROFILE.into(),
            sequence: claims.len() as u64 + 1,
            previous_digest: claims.last().map(Claim::digest).transpose()?,
            enrollment_digest: self.context.enrollment.digest()?,
            registration_digest: r.digest()?,
            proposal_digest: pd,
            forward,
            requested_at: q.requested_at,
            claimed_at: at,
            expires_at: crate::managed_drain_journal::add(
                at,
                self.context.enrollment.current_sql.maximum_age_ms,
            )?
            .min(r.expires_at),
            family_head: family.head,
            phase_head: phase.head,
        };
        c.validate(&self.context)?;
        let raw = record(&c)?;
        if raw.len() > 1 << 20 {
            return Err(refuse());
        }
        let base = format!("{}/preflight", self.context.base());
        let head = format!("{base}/head");
        let path = format!("{base}/events/{:04}", c.sequence);
        compare.push(match claims.last() {
            Some(last) => value_eq(&head, &record(last)?),
            None => version_zero(&head),
        });
        compare.push(version_zero(&path));
        if !self
            .ledger
            .txn(compare, vec![put(&path, &raw), put(&head, &raw)], vec![])
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(c)
    }
    pub async fn retain_admission_sql(
        &self,
        statement: &crate::managed_drain_preflight::Statement,
        at: i64,
    ) -> Result<()> {
        statement.validate_admission(&self.context, at)?;
        let c = &statement.body.claim;
        let claims = self.preflight_history().await?;
        if claims.get(c.sequence as usize - 1) != Some(c) {
            return Err(refuse());
        }
        let mut compare = self.preflight_boundary(at).await?;
        let (forward, sql_compare) = self.current_forward().await?;
        if forward != c.forward {
            return Err(refuse());
        }
        compare.extend(sql_compare);
        let base = format!("{}/preflight", self.context.base());
        compare.push(value_eq(
            &format!("{base}/events/{:04}", c.sequence),
            &record(c)?,
        ));
        let path = format!("{base}/observations/{}", c.digest()?);
        compare.push(version_zero(&path));
        let raw = record(statement)?;
        if raw.len() > 65536 {
            return Err(refuse());
        }
        if !self
            .ledger
            .txn(compare, vec![put(&path, &raw)], vec![])
            .await?
            .succeeded
        {
            return Err(refuse());
        }
        Ok(())
    }
}

impl Store {
    pub async fn admission_sql_cached(
        &self,
        q: &crate::managed_drain_preflight::Request,
        at: i64,
    ) -> Result<Option<crate::managed_drain_preflight::Statement>> {
        let (_, pd) = self.context.admission_proposal(q, at)?;
        let claims = self.preflight_history().await?;
        let Some(claim) = claims.iter().find(|claim| claim.proposal_digest == pd) else {
            return Ok(None);
        };
        let path = format!(
            "{}/preflight/observations/{}",
            self.context.base(),
            claim.digest()?
        );
        let Some(raw) = self.ledger.read_key(&path).await? else {
            return Err(refuse());
        };
        if raw.len() > 65536 {
            return Err(refuse());
        }
        let statement: crate::managed_drain_preflight::Statement =
            serde_json::from_value(strict_value(&raw)?)?;
        statement.validate_admission(&self.context, at)?;
        if &statement.body.claim != claim || record(&statement)?.as_bytes() != raw {
            return Err(refuse());
        }
        let mut compare = self.preflight_boundary(at).await?;
        compare.push(value_eq(
            &path,
            std::str::from_utf8(&raw).map_err(|_| refuse())?,
        ));
        if !self.ledger.txn(compare, vec![], vec![]).await?.succeeded {
            return Err(refuse());
        }
        Ok(Some(statement))
    }
}

impl Store {
    pub(crate) async fn admission_dispatch_proof(
        &self,
        g: &Grant,
        o: &Origin,
    ) -> Result<Vec<Value>> {
        Ok(self.admission_source(g, o).await?.1)
    }
    pub(crate) async fn admission_source(
        &self,
        g: &Grant,
        o: &Origin,
    ) -> Result<(crate::managed_drain_preflight::Evidence, Vec<Value>)> {
        let n = self
            .context
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&self.context.selection.child_id)?;
        let authorization = self.ledger.export_authorization(&n.operation_key).await?;
        crate::lineage::verify_authorization(&authorization, &n.forward()?.lineage)?;
        if authorization.issuance.grant_digest != o.original.grant_digest {
            return Err(refuse());
        }
        let r = &self.context.enrollment.current_sql;
        let keys = crate::control_config::keys(&r.provider.keys)?;
        let mut selected = None;
        for raw in &authorization.packet.witnesses {
            let Ok(envelope) = crate::schema::verify_record(raw.as_bytes(), "evidence", &keys)
            else {
                continue;
            };
            let p = &envelope.payload;
            if p["provider_id"] == r.provider.id
                && p["proposal_digest"] == g.proposal_digest
                && p["provider_version"] == "2.0"
                && p["question_ref"] == json!(crate::current_reservation::question(r)?)
                && p["result_schema"] == json!(crate::current_reservation::schema_reference()?)
                && selected.replace(envelope).is_some()
            {
                return Err(refuse());
            }
        }
        let evidence = selected.ok_or_else(refuse)?;
        let expected = evidence.payload["result"]["observation_digest"]
            .as_str()
            .ok_or_else(refuse)?;
        if !crate::grant_reference::valid_reference(expected) {
            return Err(refuse());
        }
        let claims = self.preflight_history().await?;
        let claim = claims
            .iter()
            .find(|claim| claim.proposal_digest == g.proposal_digest)
            .ok_or_else(refuse)?;
        let path = format!(
            "{}/preflight/observations/{}",
            self.context.base(),
            claim.digest()?
        );
        let raw = self.ledger.read_key(&path).await?.ok_or_else(refuse)?;
        if raw.len() > 65536 {
            return Err(refuse());
        }
        let statement: crate::managed_drain_preflight::Statement =
            serde_json::from_value(strict_value(&raw)?)?;
        statement.validate_admission(&self.context, g.issued_at)?;
        let proposal: crate::contracts::Envelope =
            serde_json::from_value(strict_value(authorization.packet.proposal.as_bytes())?)?;
        crate::managed_drain_preflight::Evidence {
            profile: crate::current_reservation::PROFILE.into(),
            statement: statement.clone(),
            evidence: evidence.clone(),
        }
        .validate(&self.context, &proposal, g.issued_at)?;
        let forward = crate::managed_drain_preflight::Forward {
            signed_grant: o.forward_signed_grant.clone(),
            grant_digest: claim.forward.grant_digest.clone(),
            attempt_id: o.forward_attempt_id.clone(),
        };
        self.context.forward_grant(&forward)?;
        if statement.digest()? != expected
            || record(&statement)?.as_bytes() != raw
            || &statement.body.claim != claim
            || claim.forward != forward
            || evidence.payload["expires_at"] != statement.body.expires_at
            || evidence.payload["observed_at"] != statement.body.until
        {
            return Err(refuse());
        }
        Ok((
            crate::managed_drain_preflight::Evidence {
                profile: crate::current_reservation::PROFILE.into(),
                statement,
                evidence,
            },
            vec![
                value_eq(&path, std::str::from_utf8(&raw).map_err(|_| refuse())?),
                value_eq(
                    &format!(
                        "{}/preflight/events/{:04}",
                        self.context.base(),
                        claim.sequence
                    ),
                    &record(claim)?,
                ),
            ],
        ))
    }
}
