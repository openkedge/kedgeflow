//! RFC 0027: actual catalog/capability negatives in private fixture databases.
use super::*;
use kedgeflow::error::Error;
struct Enrollment {
    root: tokio_postgres::Client,
    admin: tokio_postgres::Client,
    config: UnixDatabase,
    owner: String,
    roles: Vec<String>,
}
impl Enrollment {
    async fn connect(config: &UnixDatabase, user: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::Config::new()
            .host_path(&config.socket_directory)
            .port(config.port)
            .dbname(&config.database)
            .user(user)
            .connect(tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }
    async fn new() -> Option<Self> {
        let socket = match std::env::var("KF_POSTGRES_TEST_SOCKET") {
            Ok(p) => p,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_POSTGRES").as_deref(), Ok("1"));
                eprintln!("SKIP SQL enrollment: disposable database absent");
                return None;
            }
        };
        let id = format!("enr_{:x}", rand::random::<u64>());
        let owner = std::env::var("KF_POSTGRES_TEST_USER").unwrap();
        let mut config = UnixDatabase {
            socket_directory: socket.into(),
            port: 5432,
            database: "postgres".into(),
            executor_user: format!("{id}_exec"),
            query_user: format!("{id}_query"),
        };
        let root = Self::connect(&config, &owner).await;
        root.batch_execute(&format!("CREATE DATABASE {id};"))
            .await
            .unwrap();
        root.batch_execute(&format!(
            "CREATE ROLE {} LOGIN; CREATE ROLE {} LOGIN;",
            config.executor_user, config.query_user
        ))
        .await
        .unwrap();
        config.database = id;
        let admin = Self::connect(&config, &owner).await;
        admin
            .batch_execute(include_str!(
                "../../../../migrations/postgres/0001-reservation.sql"
            ))
            .await
            .unwrap();
        admin.batch_execute(&format!("GRANT USAGE ON SCHEMA kf_reservation TO {},{}; GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO {}; GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO {}; INSERT INTO kf_reservation.resource VALUES ('enrollment','reservations','slot','incarnation-1',1,0,'free',true);",config.executor_user,config.query_user,config.executor_user,config.query_user)).await.unwrap();
        let roles = vec![config.executor_user.clone(), config.query_user.clone()];
        let h = Self {
            root,
            admin,
            config,
            owner,
            roles,
        };
        assert_eq!(h.store().check_database().await.unwrap().status, "passed");
        Some(h)
    }
    fn store(&self) -> PostgresStore {
        PostgresStore::new(self.config.clone()).unwrap()
    }
    fn request(&self) -> DispatchRequest {
        DispatchRequest {
            profile: kedgeflow::postgres_action::PROFILE.into(),
            action: kedgeflow::postgres_action::ACTION.into(),
            tenant: "enrollment".into(),
            conflict_domain: "reservations".into(),
            attempt_id: "enrollment-attempt".into(),
            grant_digest: "ab".repeat(32),
            root_id: "enrollment-root".into(),
            resource: kedgeflow::contracts::Resource {
                id: "slot".into(),
                incarnation: "incarnation-1".into(),
            },
            expected_version: 1,
            fence: 1,
            reservation: "booking".into(),
            gateway_workload: GATEWAY.into(),
            expires_at: (SystemClock.now_ms() + 120000) as u64,
        }
    }
    async fn unchanged(&self) {
        let row=self.admin.query_one("SELECT version,last_fence,reservation,(SELECT count(*) FROM kf_reservation.attempt) FROM kf_reservation.resource",&[]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 1);
        assert_eq!(row.get::<_, i64>(1), 0);
        assert_eq!(row.get::<_, String>(2), "free");
        assert_eq!(row.get::<_, i64>(3), 0);
    }
    async fn refused(&self, query: bool) {
        assert!(self.store().check_database().await.is_err());
        let result = if query {
            self.store()
                .lookup("enrollment", "enrollment-attempt")
                .await
                .map(|_| ())
        } else {
            self.store().apply(&self.request()).await.map(|_| ())
        };
        assert!(
            matches!(result, Err(Error::Refused(_)) | Err(Error::Unavailable(_))),
            "{result:?}"
        );
        self.unchanged().await;
    }
    async fn extra_role(&mut self, suffix: &str) -> String {
        let role = format!("{}_{}", self.config.database, suffix);
        self.admin
            .batch_execute(&format!("CREATE ROLE {role} NOLOGIN;"))
            .await
            .unwrap();
        self.roles.push(role.clone());
        role
    }
    async fn finish(self) {
        self.unchanged().await;
        assert_eq!(
            self.store().check_database().await.unwrap().status,
            "passed"
        );
        let result = self.store().apply(&self.request()).await.unwrap();
        assert_eq!(result.post_version, Some(2));
        assert_eq!(
            self.store()
                .lookup("enrollment", "enrollment-attempt")
                .await
                .unwrap(),
            Some(result)
        );
        drop(self.admin);
        self.root
            .batch_execute(&format!(
                "DROP DATABASE {} WITH (FORCE);",
                self.config.database
            ))
            .await
            .unwrap();
        for role in self.roles {
            self.root
                .batch_execute(&format!("DROP ROLE \"{role}\";"))
                .await
                .unwrap();
        }
    }
}
#[tokio::test]
async fn enrollment_rejects_actual_column_write_and_historical_read_bypasses() {
    let Some(h) = Enrollment::new().await else {
        return;
    };
    for (query, privilege, table, probe) in [
        (
            false,
            "UPDATE(reservation)",
            "resource",
            "UPDATE kf_reservation.resource SET reservation='bypass'",
        ),
        (
            false,
            "INSERT(tenant,attempt_id,root_id,grant_digest,request,outcome)",
            "attempt",
            "INSERT INTO kf_reservation.attempt VALUES ('x','x','x','x','{}','{}')",
        ),
        (
            true,
            "SELECT(outcome)",
            "attempt",
            "SELECT outcome FROM kf_reservation.attempt",
        ),
        (
            true,
            "REFERENCES(tenant,attempt_id)",
            "attempt",
            "CREATE TABLE public.enrollment_reference(tenant text,attempt_id text, FOREIGN KEY(tenant,attempt_id) REFERENCES kf_reservation.attempt(tenant,attempt_id))",
        ),
    ] {
        let role = if query {
            &h.config.query_user
        } else {
            &h.config.executor_user
        };
        h.admin
            .batch_execute(&format!(
                "GRANT {privilege} ON kf_reservation.{table} TO {role};"
            ))
            .await
            .unwrap();
        if privilege.starts_with("REFERENCES") {
            // The private database's public schema provides a separate test
            // DDL surface. PostgreSQL forbids temp-to-permanent foreign keys.
            h.admin
                .batch_execute(&format!("GRANT CREATE ON SCHEMA public TO {role};"))
                .await
                .unwrap();
        }
        let row=h.admin.query_one("SELECT pg_catalog.has_table_privilege($1::text,$2::text,$3::text), pg_catalog.has_any_column_privilege($1::text,$2::text,$3::text)",&[role,&format!("kf_reservation.{table}"),&privilege.split('(').next().unwrap()]).await.unwrap();
        assert!(!row.get::<_, bool>(0));
        assert!(row.get::<_, bool>(1));
        let client = Enrollment::connect(&h.config, role).await;
        client
            .batch_execute(&format!("BEGIN; {probe}; ROLLBACK;"))
            .await
            .unwrap();
        drop(client);
        if privilege.starts_with("REFERENCES") {
            h.admin
                .batch_execute(&format!("REVOKE CREATE ON SCHEMA public FROM {role};"))
                .await
                .unwrap();
        }
        h.refused(query).await;
        h.admin
            .batch_execute(&format!(
                "REVOKE {privilege} ON kf_reservation.{table} FROM {role};"
            ))
            .await
            .unwrap();
        assert!(h.store().check_database().await.is_ok());
        println!(
            "SQL enrollment PASS: column {privilege}; old table-wide predicate false, effective column right true, preflight/runtime refused with unchanged resource/attempts"
        );
    }
    h.finish().await;
}
#[tokio::test]
async fn enrollment_rejects_noinherit_and_transitive_set_role_bypass() {
    let Some(mut h) = Enrollment::new().await else {
        return;
    };
    let elevated = h.extra_role("elevated").await;
    let bridge = h.extra_role("bridge").await;
    h.admin.batch_execute(&format!("GRANT USAGE ON SCHEMA kf_reservation TO {elevated}; GRANT UPDATE(reservation) ON kf_reservation.resource TO {elevated}; GRANT {elevated} TO {bridge} WITH INHERIT FALSE, SET TRUE;")).await.unwrap();
    for parent in [&elevated, &bridge] {
        h.admin
            .batch_execute(&format!(
                "GRANT {parent} TO {} WITH INHERIT FALSE, SET TRUE;",
                h.config.executor_user
            ))
            .await
            .unwrap();
        let client = Enrollment::connect(&h.config, &h.config.executor_user).await;
        let row=client.query_one("SELECT current_user=session_user,pg_catalog.has_any_column_privilege(current_user,'kf_reservation.resource','UPDATE'),pg_catalog.pg_has_role(current_user,$1::text,'SET')",&[&elevated]).await.unwrap();
        assert!(row.get::<_, bool>(0));
        assert!(!row.get::<_, bool>(1));
        assert!(row.get::<_, bool>(2));
        client.batch_execute(&format!("BEGIN; SET LOCAL ROLE {elevated}; UPDATE kf_reservation.resource SET reservation='bypass'; ROLLBACK;")).await.unwrap();
        drop(client);
        h.refused(false).await;
        h.admin
            .batch_execute(&format!("REVOKE {parent} FROM {};", h.config.executor_user))
            .await
            .unwrap();
        println!(
            "SQL enrollment PASS: NOINHERIT membership via {parent}; real SET ROLE bypass available, preflight/runtime refused"
        );
    }
    // This bounded profile also refuses non-settable memberships, rather than
    // qualifying future membership-option/administrative changes.
    h.admin
        .batch_execute(&format!(
            "GRANT {bridge} TO {} WITH INHERIT FALSE, SET FALSE;",
            h.config.executor_user
        ))
        .await
        .unwrap();
    h.refused(false).await;
    h.admin
        .batch_execute(&format!("REVOKE {bridge} FROM {};", h.config.executor_user))
        .await
        .unwrap();
    h.finish().await;
}
#[tokio::test]
async fn enrollment_rejects_public_admin_owner_and_missing_function_rights() {
    let Some(h) = Enrollment::new().await else {
        return;
    };
    for flag in [
        "REPLICATION",
        "CREATEDB",
        "CREATEROLE",
        "BYPASSRLS",
        "SUPERUSER",
    ] {
        h.admin
            .batch_execute(&format!("ALTER ROLE {} {flag};", h.config.executor_user))
            .await
            .unwrap();
        h.refused(false).await;
        h.admin
            .batch_execute(&format!("ALTER ROLE {} NO{flag};", h.config.executor_user))
            .await
            .unwrap();
    }
    for (privilege, object) in [
        ("EXECUTE", "FUNCTION kf_reservation.apply(jsonb)"),
        ("USAGE", "SCHEMA kf_reservation"),
    ] {
        h.admin
            .batch_execute(&format!(
                "GRANT {privilege} ON {object} TO {} WITH GRANT OPTION;",
                h.config.executor_user
            ))
            .await
            .unwrap();
        let client = Enrollment::connect(&h.config, &h.config.executor_user).await;
        client
            .batch_execute(&format!(
                "BEGIN; GRANT {privilege} ON {object} TO {}; ROLLBACK;",
                h.config.query_user
            ))
            .await
            .unwrap();
        drop(client);
        h.refused(false).await;
        h.admin
            .batch_execute(&format!(
                "REVOKE GRANT OPTION FOR {privilege} ON {object} FROM {};",
                h.config.executor_user
            ))
            .await
            .unwrap();
        assert!(h.store().check_database().await.is_ok());
        println!(
            "SQL enrollment PASS: {privilege} GRANT OPTION enables real delegation; preflight/runtime refuse without mutation"
        );
    }
    let upper = format!("{}_UPPER", h.config.database);
    h.admin.batch_execute(&format!("CREATE ROLE \"{upper}\" LOGIN; GRANT USAGE ON SCHEMA kf_reservation TO \"{upper}\"; GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO \"{upper}\";")).await.unwrap();
    let mut case_config = h.config.clone();
    case_config.executor_user = upper.clone();
    assert_eq!(
        PostgresStore::new(case_config)
            .unwrap()
            .check_database()
            .await
            .unwrap()
            .executor_user,
        upper
    );
    h.admin
        .batch_execute(&format!(
            "DROP OWNED BY \"{upper}\"; DROP ROLE \"{upper}\";"
        ))
        .await
        .unwrap();
    let owner = format!("\"{}\"", h.owner.replace('"', "\"\""));
    h.admin
        .batch_execute(&format!(
            "ALTER DATABASE {} OWNER TO {};",
            h.config.database, h.config.executor_user
        ))
        .await
        .unwrap();
    h.refused(false).await;
    h.admin
        .batch_execute(&format!(
            "ALTER DATABASE {} OWNER TO {owner};",
            h.config.database
        ))
        .await
        .unwrap();
    for (query, grant, revoke) in [
        (
            false,
            format!(
                "GRANT CREATE ON DATABASE {} TO {}",
                h.config.database, h.config.executor_user
            ),
            format!(
                "REVOKE CREATE ON DATABASE {} FROM {}",
                h.config.database, h.config.executor_user
            ),
        ),
        (
            false,
            "GRANT UPDATE ON kf_reservation.resource TO PUBLIC".into(),
            "REVOKE UPDATE ON kf_reservation.resource FROM PUBLIC".into(),
        ),
        (
            true,
            "GRANT SELECT(outcome) ON kf_reservation.attempt TO PUBLIC".into(),
            "REVOKE SELECT(outcome) ON kf_reservation.attempt FROM PUBLIC".into(),
        ),
        (
            false,
            format!(
                "GRANT CREATE ON SCHEMA kf_reservation TO {}",
                h.config.executor_user
            ),
            format!(
                "REVOKE CREATE ON SCHEMA kf_reservation FROM {}",
                h.config.executor_user
            ),
        ),
        (
            false,
            format!(
                "GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO {}",
                h.config.executor_user
            ),
            format!(
                "REVOKE EXECUTE ON FUNCTION kf_reservation.lookup(text,text) FROM {}",
                h.config.executor_user
            ),
        ),
        (
            false,
            format!(
                "REVOKE EXECUTE ON FUNCTION kf_reservation.apply(jsonb) FROM {}",
                h.config.executor_user
            ),
            format!(
                "GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO {}",
                h.config.executor_user
            ),
        ),
        (
            true,
            format!(
                "REVOKE EXECUTE ON FUNCTION kf_reservation.lookup(text,text) FROM {}",
                h.config.query_user
            ),
            format!(
                "GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO {}",
                h.config.query_user
            ),
        ),
        (
            true,
            format!(
                "REVOKE USAGE ON SCHEMA kf_reservation FROM {}",
                h.config.query_user
            ),
            format!(
                "GRANT USAGE ON SCHEMA kf_reservation TO {}",
                h.config.query_user
            ),
        ),
    ] {
        h.admin.batch_execute(&grant).await.unwrap();
        h.refused(query).await;
        h.admin.batch_execute(&revoke).await.unwrap();
        assert!(h.store().check_database().await.is_ok());
    }
    println!(
        "SQL enrollment PASS: PUBLIC table/column rights, admin/replication flags, database owner/CREATE, schema CREATE, crossed/missing function/USAGE grants refused without mutation"
    );
    h.finish().await;
}
