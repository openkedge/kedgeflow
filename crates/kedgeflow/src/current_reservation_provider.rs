//! Fixed read-only SQL observation. Native one-use reservation precedes I/O;
//! storage identity/head and original reservation are checked again before reply.
use crate::{
    clock::Clock,
    contracts::strict_value,
    current_reservation::{
        Observation, PROFILE, Query, Registration, Signed, StorageHead, Witness,
    },
    error::{Error, Result},
    managed_drain_store::Store,
    postgres_compensation::{BarrierQuery, CurrentReservationReader},
    postgres_custody::{Material, Root},
};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
fn refuse() -> Error {
    Error::Refused("current SQL source identity/head/reservation refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadRecord {
    pub profile: String,
    pub registration_digest: String,
    pub current_digest: String,
    pub minimum_sequence: u64,
    pub head: Signed<StorageHead>,
}
impl HeadRecord {
    pub fn validate(&self, r: &Registration, at: i64) -> Result<()> {
        r.validate()?;
        self.head.validate_head(r, at)?;
        if self.profile != PROFILE
            || self.registration_digest != r.digest()?
            || self.minimum_sequence == 0
            || self.minimum_sequence > self.head.body.sequence
            || self.current_digest != self.head.digest()?
        {
            return Err(refuse());
        }
        Ok(())
    }
}
#[async_trait]
pub trait HeadSource: Send + Sync {
    async fn current(&self, r: &Registration, at: i64) -> Result<Signed<StorageHead>>;
}
pub struct FileHead {
    root: Root,
    path: PathBuf,
    last: Mutex<Option<(u64, String)>>,
}
impl FileHead {
    pub fn new(material_root: &Path, path: PathBuf) -> Result<Self> {
        Ok(Self {
            root: Root::open(material_root)?,
            path,
            last: Mutex::new(None),
        })
    }
    fn read(&self, r: &Registration, at: i64) -> Result<Signed<StorageHead>> {
        // Both the latest digest and durable minimum are protected outside SQL.
        // SQL rollback cannot legitimately rewrite this file. Its owner and
        // latest-head publication on restart remain a deployment trust boundary.
        let raw = self.root.read(&self.path, Material::Public, 65536)?;
        let record: HeadRecord = serde_json::from_value(strict_value(&raw)?)?;
        record.validate(r, at)?;
        let pair = (record.head.body.sequence, record.current_digest);
        let mut last = self.last.lock().map_err(|_| refuse())?;
        if last
            .as_ref()
            .is_some_and(|old| pair.0 < old.0 || pair.0 == old.0 && pair.1 != old.1)
        {
            return Err(refuse());
        }
        *last = Some(pair);
        Ok(record.head)
    }
}
#[async_trait]
impl HeadSource for FileHead {
    async fn current(&self, r: &Registration, at: i64) -> Result<Signed<StorageHead>> {
        self.read(r, at)
    }
}
pub struct Provider {
    store: Store,
    reader: CurrentReservationReader,
    heads: Arc<dyn HeadSource>,
    clock: Arc<dyn Clock>,
    key_id: String,
    key: SigningKey,
}
impl Provider {
    pub fn new(
        store: Store,
        reader: CurrentReservationReader,
        heads: Arc<dyn HeadSource>,
        clock: Arc<dyn Clock>,
        key_id: String,
        key: SigningKey,
    ) -> Result<Self> {
        store.context.physical.validate()?;
        if crate::control_config::keys(&store.context.enrollment.current_sql.provider.keys)?
            .get(&key_id)
            != Some(&key.verifying_key())
        {
            return Err(refuse());
        }
        Ok(Self {
            store,
            reader,
            heads,
            clock,
            key_id,
            key,
        })
    }
    pub fn enrollment(&self) -> &crate::managed_drain::Enrollment {
        &self.store.context.enrollment
    }
    pub async fn query(&self, q: &Query) -> Result<Witness> {
        let timeout = Duration::from_millis(self.enrollment().current_sql.request_timeout_ms);
        tokio::time::timeout(timeout, self.observe(q))
            .await
            .map_err(|_| {
                Error::Unavailable(
                    "current SQL source deadline elapsed; original source claim stays consumed"
                        .into(),
                )
            })?
    }
    async fn observe(&self, q: &Query) -> Result<Witness> {
        let e = self.enrollment();
        let r = &e.current_sql;
        let claim = self.store.claim_current_sql(q, self.clock.now_ms()).await?;
        self.store
            .current_sql_claim(q, &claim, self.clock.now_ms())
            .await?;
        let head = self.heads.current(r, self.clock.now_ms()).await?;
        let from = self.clock.now_ms();
        let (_, sql_grant) = self.store.context.validate_origin(&q.origin)?;
        let sql_digest = e_sql_digest(&self.store, q)?;
        let sql_query = BarrierQuery {
            tenant: r.tenant.clone(),
            contract_digest: r.compensation_contract_digest.clone(),
            forward_attempt_id: q.origin.forward_attempt_id.clone(),
            forward_grant_digest: sql_digest.clone(),
            forward_root_id: sql_grant.root_id.clone(),
        };
        let sql = self
            .reader
            .current(&sql_query, &r.storage.identity)
            .await?
            .ok_or_else(refuse)?;
        let latest = self.heads.current(r, self.clock.now_ms()).await?;
        if head.digest()? != latest.digest()? {
            return Err(refuse());
        }
        self.store
            .current_sql_claim(q, &claim, self.clock.now_ms())
            .await?;
        let until = self.clock.now_ms();
        let expires_at = crate::managed_drain_journal::add(from, r.maximum_age_ms)?
            .min(latest.body.expires_at)
            .min(claim.expires_at);
        let witness = Signed::sign(
            "reservation_observation",
            Observation {
                requested_at: q.requested_at,
                query_digest: q.digest()?,
                enrollment_digest: e.digest()?,
                origin_digest: q.origin.digest()?,
                reservation_digest: q.reservation_digest.clone(),
                source_claim: claim,
                storage_head: latest,
                sql,
                from,
                until,
                expires_at,
            },
            &r.provider,
            &self.key_id,
            &self.key,
        )?;
        witness.validate_current(
            e,
            &q.origin,
            &q.reservation_digest,
            self.clock.now_ms(),
            &sql_grant,
            &sql_digest,
        )?;
        Ok(witness)
    }
}
fn e_sql_digest(store: &Store, q: &Query) -> Result<String> {
    let e = &store.context.enrollment;
    Ok(store
        .context
        .selection
        .registration
        .composition
        .as_ref()
        .ok_or_else(refuse)?
        .node(&e.current_sql.forward_child_id)?
        .forward()?
        .lineage
        .grants
        .verify_retained(q.origin.forward_signed_grant.as_bytes())?
        .digest)
}

impl Provider {
    pub async fn admission(
        &self,
        q: &crate::managed_drain_preflight::Request,
    ) -> Result<crate::managed_drain_preflight::Evidence> {
        tokio::time::timeout(
            Duration::from_millis(self.enrollment().current_sql.request_timeout_ms),
            self.admission_observe(q),
        )
        .await
        .map_err(|_| {
            Error::Unavailable(
                "current SQL admission observation deadline elapsed; preflight remains consumed"
                    .into(),
            )
        })?
    }
    async fn admission_observe(
        &self,
        q: &crate::managed_drain_preflight::Request,
    ) -> Result<crate::managed_drain_preflight::Evidence> {
        use crate::managed_drain_preflight::Observation;
        let at = self.clock.now_ms();
        let e = self.enrollment();
        let r = &e.current_sql;
        let (proposal, _) = self.store.context.admission_proposal(q, at)?;
        if let Some(statement) = self.store.admission_sql_cached(q, at).await? {
            return self.admission_evidence(proposal, statement);
        }
        let claim = self
            .store
            .claim_admission_sql(q, self.clock.now_ms())
            .await?;
        let head = self.heads.current(r, self.clock.now_ms()).await?;
        let from = self.clock.now_ms();
        let sql_grant = self.store.context.forward_grant(&claim.forward)?;
        let sql_query = BarrierQuery {
            tenant: r.tenant.clone(),
            contract_digest: r.compensation_contract_digest.clone(),
            forward_attempt_id: claim.forward.attempt_id.clone(),
            forward_grant_digest: claim.forward.grant_digest.clone(),
            forward_root_id: sql_grant.root_id.clone(),
        };
        let sql = self
            .reader
            .current(&sql_query, &r.storage.identity)
            .await?
            .ok_or_else(refuse)?;
        let latest = self.heads.current(r, self.clock.now_ms()).await?;
        if latest.digest()? != head.digest()? {
            return Err(refuse());
        }
        let until = self.clock.now_ms();
        let proposal_expiry = proposal.payload["delegation"]["expires_at"]
            .as_i64()
            .ok_or_else(refuse)?;
        let expires_at = crate::managed_drain_journal::add(from, r.maximum_age_ms)?
            .min(claim.expires_at)
            .min(latest.body.expires_at)
            .min(proposal_expiry);
        let statement = Signed::sign(
            "admission_reservation_observation",
            Observation {
                claim,
                storage_head: latest,
                sql,
                from,
                until,
                expires_at,
            },
            &r.provider,
            &self.key_id,
            &self.key,
        )?;
        self.store
            .retain_admission_sql(&statement, self.clock.now_ms())
            .await?;
        self.admission_evidence(proposal, statement)
    }
    fn admission_evidence(
        &self,
        proposal: crate::contracts::Envelope,
        statement: crate::managed_drain_preflight::Statement,
    ) -> Result<crate::managed_drain_preflight::Evidence> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::Signer;
        statement.validate_admission(&self.store.context, self.clock.now_ms())?;
        let payload = crate::managed_drain_preflight::evidence_payload(
            &self.store.context,
            &proposal,
            &statement,
        )?;
        let mut envelope = crate::contracts::Envelope {
            profile: crate::contracts::PROFILE.into(),
            kind: "evidence".into(),
            schema: "https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Evidence".into(),
            key_id: self.key_id.clone(),
            payload,
            signature: String::new(),
        };
        envelope.signature = URL_SAFE_NO_PAD.encode(
            self.key
                .sign(&crate::contracts::signature_input(&envelope)?)
                .to_bytes(),
        );
        let raw = crate::contracts::canonical(&serde_json::json!(envelope))?;
        crate::schema::verify_record(
            &raw,
            "evidence",
            &crate::control_config::keys(&self.enrollment().current_sql.provider.keys)?,
        )?;
        Ok(crate::managed_drain_preflight::Evidence {
            profile: PROFILE.into(),
            statement,
            evidence: envelope,
        })
    }
}
