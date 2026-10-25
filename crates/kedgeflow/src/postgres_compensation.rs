//! Conditional restoration of a protected one-row SQL snapshot. No generic SQL,
//! restore values, retries or connection pins are supplied by requests.
use crate::{
    contracts::{Resource, strict_value},
    error::{Error, Result},
    postgres_action::Status,
    postgres_store::UnixDatabase,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tokio_postgres::{Client, Config, NoTls, config::SslMode};
pub const PROFILE: &str = "KF-POSTGRES-COMPENSATION-0.1-draft";
pub const MIGRATION: &str = include_str!("../../../migrations/postgres/0002-compensation.sql");
fn refused() -> Error {
    Error::Refused("protected PostgreSQL compensation refused".into())
}
fn unavailable() -> Error {
    Error::Unavailable("protected PostgreSQL compensation unavailable".into())
}
pub fn validate(v: &Value) -> Result<()> {
    static PIN: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let pin = PIN.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/postgres-compensation-v0.1.schema.json"
            ))
            .expect("local SQL inverse schema"),
        )
        .expect("valid local schema")
    });
    if !pin.is_valid(v) {
        return Err(refused());
    }
    Ok(())
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    if raw.len() > 32 * 1024 {
        return Err(refused());
    }
    let v = strict_value(raw)?;
    validate(&v)?;
    Ok(serde_json::from_value(v)?)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchRequest {
    pub profile: String,
    pub action: String,
    pub tenant: String,
    pub conflict_domain: String,
    pub attempt_id: String,
    pub grant_digest: String,
    pub root_id: String,
    pub resource: Resource,
    pub expected_version: u64,
    pub fence: u64,
    pub gateway_workload: String,
    pub expires_at: u64,
    pub contract_digest: String,
    pub forward_root_id: String,
    pub forward_grant_digest: String,
    pub forward_attempt_id: String,
    pub restore_state_digest: String,
}
impl DispatchRequest {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        decode(raw)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub profile: String,
    pub request: DispatchRequest,
    pub status: Status,
    pub post_version: Option<u64>,
}
impl Outcome {
    pub fn verify(raw: &[u8], expected: &DispatchRequest) -> Result<Self> {
        validate(&serde_json::to_value(expected)?)?;
        let result: Self = decode(raw)?;
        if &result.request != expected
            || match result.status {
                Status::Committed => {
                    result.post_version != expected.expected_version.checked_add(1)
                }
                Status::GuardRejected => result.post_version.is_some(),
            }
        {
            return Err(refused());
        }
        Ok(result)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BarrierQuery {
    pub tenant: String,
    pub contract_digest: String,
    pub forward_attempt_id: String,
    pub forward_grant_digest: String,
    pub forward_root_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BarrierObservation {
    pub contract_digest: String,
    pub forward_outcome: crate::postgres_action::Outcome,
    pub resource: Resource,
    pub observed_version: u64,
    pub restore_state_digest: String,
}
#[async_trait]
pub trait CompensationStore: Send + Sync {
    async fn apply(&self, q: &DispatchRequest) -> Result<Outcome>;
    async fn lookup(&self, tenant: &str, attempt: &str) -> Result<Option<Outcome>>;
    async fn barrier(&self, q: &BarrierQuery) -> Result<Option<BarrierObservation>>;
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub connection: UnixDatabase,
    pub barrier_user: String,
}
pub struct PostgresCompensationStore {
    config: Database,
    peer_uid: Option<u32>,
}
struct Connection {
    client: Client,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}
const APPLY: &str = "kf_compensation.apply(jsonb)";
const LOOKUP: &str = "kf_compensation.lookup(text,text)";
const BARRIER: &str = "kf_compensation.barrier(text,text,text,text,text)";
impl PostgresCompensationStore {
    pub fn new(config: Database) -> Result<Self> {
        config.connection.validate()?;
        let mut probe = config.connection.clone();
        probe.query_user = config.barrier_user.clone();
        probe.validate()?;
        if config.barrier_user == config.connection.query_user {
            return Err(refused());
        }
        Ok(Self {
            config,
            peer_uid: None,
        })
    }
    pub fn with_peer_uid(mut self, uid: u32) -> Result<Self> {
        if uid == 0 || !cfg!(unix) {
            return Err(refused());
        }
        self.peer_uid = Some(uid);
        Ok(self)
    }
    async fn connect(&self, own: &str) -> Result<Connection> {
        let pin = &self.config.connection;
        let user = match own {
            APPLY => &pin.executor_user,
            LOOKUP => &pin.query_user,
            BARRIER => &self.config.barrier_user,
            _ => return Err(refused()),
        };
        let mut cfg = Config::new();
        cfg.host_path(&pin.socket_directory).port(pin.port).dbname(&pin.database).user(user)
            .ssl_mode(SslMode::Disable).connect_timeout(Duration::from_secs(2))
            .options("-c search_path=pg_catalog -c statement_timeout=3000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=3000");
        let (client, task) = if let Some(uid) = self.peer_uid {
            #[cfg(unix)]
            {
                let (c, d) = tokio::time::timeout(Duration::from_secs(2), async {
                    let stream =
                        crate::postgres_socket::connect(&pin.socket_directory, pin.port, uid)
                            .await?;
                    cfg.connect_raw(stream, NoTls)
                        .await
                        .map_err(|_| unavailable())
                })
                .await
                .map_err(|_| unavailable())??;
                (
                    c,
                    tokio::spawn(async move {
                        let _ = d.await;
                    }),
                )
            }
            #[cfg(not(unix))]
            {
                let _ = uid;
                return Err(refused());
            }
        } else {
            let (c, d) = cfg.connect(NoTls).await.map_err(|_| unavailable())?;
            (
                c,
                tokio::spawn(async move {
                    let _ = d.await;
                }),
            )
        };
        let c = Connection { client, task };
        // Every connection observes standalone role and table/column/function
        // scope. Owner/administrator custody and future ACL changes remain trusted.
        let row=c.client.query_one("SELECT current_user::text,session_user::text, \
            (SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication FROM pg_catalog.pg_roles WHERE rolname=current_user), \
            EXISTS(SELECT FROM pg_catalog.pg_roles WHERE oid<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND pg_catalog.pg_has_role(current_user,oid,'MEMBER')), \
            (SELECT datdba=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) FROM pg_catalog.pg_database WHERE datname=current_database()) OR pg_catalog.has_database_privilege(current_user,current_database(),'CREATE')",&[]).await.map_err(|_|unavailable())?;
        if row.get::<_, String>(0) != *user
            || row.get::<_, String>(1) != *user
            || (2..5).any(|i| row.get::<_, bool>(i))
        {
            return Err(refused());
        }
        for schema in ["kf_reservation", "kf_compensation"] {
            let row=c.client.query_one("SELECT pg_catalog.has_schema_privilege(current_user,$1,'CREATE'),pg_catalog.has_schema_privilege(current_user,$1,'USAGE WITH GRANT OPTION')",&[&schema]).await.map_err(|_|unavailable())?;
            if row.get::<_, bool>(0) || row.get::<_, bool>(1) {
                return Err(refused());
            }
        }
        for table in [
            "kf_reservation.resource",
            "kf_reservation.attempt",
            "kf_compensation.snapshot",
            "kf_compensation.attempt",
        ] {
            let row=c.client.query_one("SELECT pg_catalog.has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'),pg_catalog.has_any_column_privilege(current_user,$1,'SELECT,INSERT,UPDATE,REFERENCES')",&[&table]).await.map_err(|_|unavailable())?;
            if row.get::<_, bool>(0) || row.get::<_, bool>(1) {
                return Err(refused());
            }
        }
        for function in [
            APPLY,
            LOOKUP,
            BARRIER,
            "kf_compensation.capture(jsonb)",
            "kf_compensation.valid_request(jsonb)",
            "kf_reservation.apply(jsonb)",
            "kf_reservation.lookup(text,text)",
            "kf_reservation.valid_request(jsonb)",
        ] {
            let row=c.client.query_one("SELECT pg_catalog.has_function_privilege(current_user,$1,'EXECUTE'),pg_catalog.has_function_privilege(current_user,$1,'EXECUTE WITH GRANT OPTION')",&[&function]).await.map_err(|_|unavailable())?;
            if row.get::<_, bool>(0) != (function == own) || row.get::<_, bool>(1) {
                return Err(refused());
            }
        }
        let row = c
            .client
            .query_one(
                "SELECT pg_catalog.has_schema_privilege(current_user,'kf_compensation','USAGE')",
                &[],
            )
            .await
            .map_err(|_| unavailable())?;
        if !row.get::<_, bool>(0) {
            return Err(refused());
        }
        Ok(c)
    }
    pub async fn check_database(&self) -> Result<()> {
        for f in [APPLY, LOOKUP, BARRIER] {
            drop(self.connect(f).await?);
        }
        Ok(())
    }
}
#[async_trait]
impl CompensationStore for PostgresCompensationStore {
    async fn apply(&self, q: &DispatchRequest) -> Result<Outcome> {
        let v = serde_json::to_value(q)?;
        validate(&v)?;
        let mut c = self.connect(APPLY).await?;
        let tx = c.client.transaction().await.map_err(|_| unavailable())?;
        let row = tx
            .query_one("SELECT kf_compensation.apply($1::jsonb)", &[&v])
            .await
            .map_err(|_| Error::Unknown("SQL inverse effect unavailable".into()))?;
        let result: Value = row.get(0);
        let out = Outcome::verify(&serde_json::to_vec(&result)?, q)?;
        tx.commit()
            .await
            .map_err(|_| Error::Unknown("SQL inverse COMMIT acknowledgement unavailable".into()))?;
        Ok(out)
    }
    async fn lookup(&self, tenant: &str, attempt: &str) -> Result<Option<Outcome>> {
        let c = self.connect(LOOKUP).await?;
        let row = c
            .client
            .query_one(
                "SELECT kf_compensation.lookup($1::text,$2::text)",
                &[&tenant, &attempt],
            )
            .await
            .map_err(|_| unavailable())?;
        let Some(v): Option<Value> = row.get(0) else {
            return Ok(None);
        };
        let out: Outcome = decode(&serde_json::to_vec(&v)?)?;
        Outcome::verify(&serde_json::to_vec(&out)?, &out.request)?;
        if out.request.tenant != tenant || out.request.attempt_id != attempt {
            return Err(refused());
        }
        Ok(Some(out))
    }
    async fn barrier(&self, q: &BarrierQuery) -> Result<Option<BarrierObservation>> {
        validate(&serde_json::to_value(q)?)?;
        let mut c = self.connect(BARRIER).await?;
        let tx = c.client.transaction().await.map_err(|_| unavailable())?;
        let result = barrier_read(&tx, q).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(result)
    }
}

async fn barrier_read(
    tx: &tokio_postgres::Transaction<'_>,
    q: &BarrierQuery,
) -> Result<Option<BarrierObservation>> {
    let row = tx
        .query_one(
            "SELECT kf_compensation.barrier($1::text,$2::text,$3::text,$4::text,$5::text)",
            &[
                &q.tenant,
                &q.contract_digest,
                &q.forward_attempt_id,
                &q.forward_grant_digest,
                &q.forward_root_id,
            ],
        )
        .await
        .map_err(|_| unavailable())?;
    let Some(v): Option<Value> = row.get(0) else {
        return Ok(None);
    };
    let result: BarrierObservation = serde_json::from_value(v)?;
    let f = &result.forward_outcome;
    crate::postgres_action::Outcome::verify(&serde_json::to_vec(f)?, &f.request)?;
    if f.status != Status::Committed
        || result.contract_digest != q.contract_digest
        || f.request.tenant != q.tenant
        || f.request.attempt_id != q.forward_attempt_id
        || f.request.grant_digest != q.forward_grant_digest
        || f.request.root_id != q.forward_root_id
        || f.request.resource != result.resource
        || f.post_version != Some(result.observed_version)
        || result.restore_state_digest.len() != 64
    {
        return Err(refused());
    }
    Ok(Some(result))
}

async fn storage_identity<C: tokio_postgres::GenericClient + Sync>(
    client: &C,
) -> Result<crate::current_reservation::StorageIdentity> {
    let row = client.query_one(
        "SELECT current_database()::text, (SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname=current_database()), (extract(epoch FROM pg_catalog.pg_postmaster_start_time())*1000000)::bigint",
        &[],
    ).await.map_err(|_| unavailable())?;
    let identity = crate::current_reservation::StorageIdentity {
        database: row.get(0),
        database_oid: u64::try_from(row.get::<_, i64>(1)).map_err(|_| refused())?,
        postmaster_started_at_us: u64::try_from(row.get::<_, i64>(2)).map_err(|_| refused())?,
    };
    identity.validate()?;
    Ok(identity)
}

/// Source service capability exposing only the standalone barrier role. It has
/// no apply/restore or original-effect lookup method. SQL/admin/OS custody and
/// permission changes remain separately trusted as for the existing SQL stores.
pub struct CurrentReservationReader {
    store: PostgresCompensationStore,
}
impl CurrentReservationReader {
    pub fn new(config: Database) -> Result<Self> {
        Ok(Self {
            store: PostgresCompensationStore::new(config)?,
        })
    }
    pub fn with_peer_uid(mut self, uid: u32) -> Result<Self> {
        self.store = self.store.with_peer_uid(uid)?;
        Ok(self)
    }
    pub async fn identity(&self) -> Result<crate::current_reservation::StorageIdentity> {
        let c = self.store.connect(BARRIER).await?;
        storage_identity(&c.client).await
    }
    pub async fn current(
        &self,
        q: &BarrierQuery,
        expected: &crate::current_reservation::StorageIdentity,
    ) -> Result<Option<BarrierObservation>> {
        expected.validate()?;
        validate(&serde_json::to_value(q)?)?;
        let mut c = self.store.connect(BARRIER).await?;
        let tx = c.client.transaction().await.map_err(|_| unavailable())?;
        if storage_identity(&tx).await? != *expected {
            return Err(refused());
        }
        // The immutable function holds the original row FOR SHARE in this
        // transaction. This is a query with locks, not a read-only SQL transaction.
        let observation = barrier_read(&tx, q).await?;
        if storage_identity(&tx).await? != *expected {
            return Err(refused());
        }
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(observation)
    }
}
