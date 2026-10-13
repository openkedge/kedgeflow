//! Fixed local Unix-socket PostgreSQL operations. No SQL/routing from requests,
//! no automatic retry and no terminal reply before COMMIT acknowledgement.
use crate::{
    error::{Error, Result},
    postgres_action::{DispatchRequest, Outcome},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};
use tokio_postgres::{Client, Config, IsolationLevel, NoTls, config::SslMode};

#[async_trait]
pub trait ReservationStore: Send + Sync {
    async fn apply(&self, request: &DispatchRequest) -> Result<Outcome>;
    async fn lookup(&self, tenant: &str, attempt: &str) -> Result<Option<Outcome>>;
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixDatabase {
    pub socket_directory: PathBuf,
    pub port: u16,
    pub database: String,
    pub executor_user: String,
    pub query_user: String,
}
impl UnixDatabase {
    pub fn validate(&self) -> Result<()> {
        let identifier = |s: &str| {
            !s.is_empty()
                && s.len() <= 63
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        };
        if !self.socket_directory.is_absolute()
            || self.port == 0
            || !identifier(&self.database)
            || !identifier(&self.executor_user)
            || !identifier(&self.query_user)
            || self.executor_user == self.query_user
        {
            return Err(Error::Invalid(
                "invalid protected Unix database pins".into(),
            ));
        }
        Ok(())
    }
}

pub const ENROLLMENT_PROFILE: &str = "KF-POSTGRES-ENROLLMENT-0.1-draft";
#[derive(Debug, Serialize)]
pub struct EnrollmentReport {
    pub profile: String,
    pub operation: String,
    pub database: String,
    pub executor_user: String,
    pub query_user: String,
    pub status: String,
}

pub struct PostgresStore {
    config: UnixDatabase,
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
fn unavailable() -> Error {
    Error::Unavailable("protected PostgreSQL operation unavailable".into())
}
impl PostgresStore {
    pub fn new(config: UnixDatabase) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }
    async fn connect(&self, query: bool) -> Result<Connection> {
        let user = if query {
            &self.config.query_user
        } else {
            &self.config.executor_user
        };
        let mut config = Config::new();
        config
            .host_path(&self.config.socket_directory)
            .port(self.config.port)
            .user(user)
            .dbname(&self.config.database)
            .ssl_mode(SslMode::Disable)
            .connect_timeout(Duration::from_secs(2))
            .options("-c search_path=pg_catalog -c statement_timeout=3000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=3000");
        let (client, driver) = config.connect(NoTls).await.map_err(|_| unavailable())?;
        let task = tokio::spawn(async move {
            let _ = driver.await;
        });
        let connection = Connection { client, task };
        // Effective table checks omit column-only grants; standalone roles also
        // must not acquire privileges via SET ROLE, even with NOINHERIT. Recheck
        // every new connection. Protected administrator/function custody remains
        // trusted; this catalog observation does not lock future ACL changes.
        let own = if query {
            "kf_reservation.lookup(text,text)"
        } else {
            "kf_reservation.apply(jsonb)"
        };
        let other = if query {
            "kf_reservation.apply(jsonb)"
        } else {
            "kf_reservation.lookup(text,text)"
        };
        let row=connection.client.query_one(
            "SELECT current_user::text, session_user::text, \
             (SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication \
              FROM pg_catalog.pg_roles WHERE rolname=current_user), \
             EXISTS(SELECT FROM pg_catalog.pg_roles WHERE oid<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) \
                    AND pg_catalog.pg_has_role(current_user,oid,'MEMBER')), \
             (SELECT datdba=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) FROM pg_catalog.pg_database WHERE datname=current_database()) \
               OR pg_catalog.has_database_privilege(current_user,current_database(),'CREATE'), \
             pg_catalog.has_schema_privilege(current_user,'kf_reservation','CREATE'), \
             pg_catalog.has_table_privilege(current_user,'kf_reservation.resource','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'), \
             pg_catalog.has_table_privilege(current_user,'kf_reservation.attempt','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'), \
             pg_catalog.has_any_column_privilege(current_user,'kf_reservation.resource','SELECT,INSERT,UPDATE,REFERENCES'), \
             pg_catalog.has_any_column_privilege(current_user,'kf_reservation.attempt','SELECT,INSERT,UPDATE,REFERENCES'), \
             pg_catalog.has_function_privilege(current_user,$1,'EXECUTE'), \
             pg_catalog.has_schema_privilege(current_user,'kf_reservation','USAGE'), \
             pg_catalog.has_function_privilege(current_user,$2,'EXECUTE'), \
             pg_catalog.has_function_privilege(current_user,$2,'EXECUTE WITH GRANT OPTION'), \
             pg_catalog.has_schema_privilege(current_user,'kf_reservation','USAGE WITH GRANT OPTION')",
            &[&other,&own],
        ).await.map_err(|_|unavailable())?;
        if row.get::<_, String>(0) != *user
            || row.get::<_, String>(1) != *user
            || (2..=10).any(|n| row.get::<_, bool>(n))
            || !row.get::<_, bool>(11)
            || !row.get::<_, bool>(12)
            || row.get::<_, bool>(13)
            || row.get::<_, bool>(14)
        {
            return Err(Error::Refused(
                "PostgreSQL role exceeds or lacks fixed function scope".into(),
            ));
        }
        Ok(connection)
    }
    /// Active read-only catalog observation for the two configured logins.
    /// No listener, resource reads, function execution or enrollment changes.
    pub async fn check_database(&self) -> Result<EnrollmentReport> {
        drop(self.connect(false).await?);
        drop(self.connect(true).await?);
        Ok(EnrollmentReport {
            profile: ENROLLMENT_PROFILE.into(),
            operation: "check_database".into(),
            database: self.config.database.clone(),
            executor_user: self.config.executor_user.clone(),
            query_user: self.config.query_user.clone(),
            status: "passed".into(),
        })
    }
}

#[async_trait]
impl ReservationStore for PostgresStore {
    async fn apply(&self, request: &DispatchRequest) -> Result<Outcome> {
        let value = serde_json::to_value(request)?;
        crate::postgres_action::validate(&value)?;
        let mut connection = self.connect(false).await?;
        let transaction = connection
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .read_only(false)
            .start()
            .await
            .map_err(|_| unavailable())?;
        let result = transaction
            .query_one("SELECT kf_reservation.apply($1::jsonb)", &[&value])
            .await
            .map_err(|_| Error::Unknown("SQL effect or commit unavailable".into()))?;
        let outcome: Value = result.get(0);
        let checked = Outcome::verify(&serde_json::to_vec(&outcome)?, request)?;
        transaction
            .commit()
            .await
            .map_err(|_| Error::Unknown("SQL commit acknowledgement unavailable".into()))?;
        Ok(checked)
    }
    async fn lookup(&self, tenant: &str, attempt: &str) -> Result<Option<Outcome>> {
        let connection = self.connect(true).await?;
        let row = connection
            .client
            .query_one(
                "SELECT kf_reservation.lookup($1::text,$2::text)",
                &[&tenant, &attempt],
            )
            .await
            .map_err(|_| unavailable())?;
        let Some(value): Option<Value> = row.get(0) else {
            return Ok(None);
        };
        crate::postgres_action::validate(&value)?;
        let outcome: Outcome = serde_json::from_value(value)?;
        Outcome::verify(&serde_json::to_vec(&outcome)?, &outcome.request)?;
        if outcome.request.tenant != tenant || outcome.request.attempt_id != attempt {
            return Err(Error::Unknown("uncorrelated PostgreSQL lookup".into()));
        }
        Ok(Some(outcome))
    }
}
