#![cfg(unix)]
//! Actual peer SQL source primitives. No managed physical execution claim.
use kedgeflow::{
    clock::{Clock, SystemClock},
    contracts::{Resource, digest},
    current_reservation::StorageIdentity,
    postgres_action::{self as pg, DispatchRequest},
    postgres_compensation::{BarrierQuery, CurrentReservationReader, Database},
    postgres_store::{PostgresStore, ReservationStore, UnixDatabase},
};
use serde_json::{Value, json};
use std::path::PathBuf;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Ready {
    _serial: tokio::sync::MutexGuard<'static, ()>,
    admin: tokio_postgres::Client,
    owner: String,
    config: UnixDatabase,
    reader: CurrentReservationReader,
    q: BarrierQuery,
    original: DispatchRequest,
}
async fn connect(config: &UnixDatabase, owner: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::Config::new()
        .host_path(&config.socket_directory)
        .port(config.port)
        .dbname(&config.database)
        .user(owner)
        .connect(tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}
fn reader(config: &UnixDatabase, role: &str) -> CurrentReservationReader {
    CurrentReservationReader::new(Database {
        connection: UnixDatabase {
            executor_user: "kf_inverse_executor".into(),
            query_user: "kf_inverse_reader".into(),
            ..config.clone()
        },
        barrier_user: role.into(),
    })
    .unwrap()
    .with_peer_uid(rustix::process::geteuid().as_raw())
    .unwrap()
}
async fn initialize(admin: &tokio_postgres::Client) {
    admin.batch_execute(pg::MIGRATION).await.unwrap();
    admin
        .batch_execute(kedgeflow::postgres_compensation::MIGRATION)
        .await
        .unwrap();
    admin.batch_execute("GRANT USAGE ON SCHEMA kf_reservation TO kf_executor,kf_reader,kf_inverse_executor,kf_inverse_reader,kf_inverse_barrier; GRANT EXECUTE ON FUNCTION kf_reservation.apply(jsonb) TO kf_executor; GRANT EXECUTE ON FUNCTION kf_reservation.lookup(text,text) TO kf_reader; GRANT USAGE ON SCHEMA kf_compensation TO kf_inverse_executor,kf_inverse_reader,kf_inverse_barrier; GRANT EXECUTE ON FUNCTION kf_compensation.apply(jsonb) TO kf_inverse_executor; GRANT EXECUTE ON FUNCTION kf_compensation.lookup(text,text) TO kf_inverse_reader; GRANT EXECUTE ON FUNCTION kf_compensation.barrier(text,text,text,text,text) TO kf_inverse_barrier;").await.unwrap();
}
impl Ready {
    async fn new() -> Option<Self> {
        let serial = SERIAL.lock().await;
        let socket = match std::env::var("KF_POSTGRES_TEST_SOCKET") {
            Ok(v) => v,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_POSTGRES").as_deref(), Ok("1"));
                eprintln!("SKIP current SQL source: disposable peer database absent");
                return None;
            }
        };
        assert_eq!(
            std::env::var("KF_POSTGRES_TEST_PEER").as_deref(),
            Ok("1"),
            "current SQL source cases require the disposable --peer runner"
        );
        let owner = std::env::var("KF_POSTGRES_TEST_USER").unwrap();
        let mut config = UnixDatabase {
            socket_directory: std::fs::canonicalize(socket).unwrap(),
            port: 5432,
            database: "postgres".into(),
            executor_user: "kf_executor".into(),
            query_user: "kf_reader".into(),
        };
        let root = connect(&config, &owner).await;
        let name = format!("current_{:x}", rand::random::<u64>());
        root.batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        config.database = name;
        let admin = connect(&config, &owner).await;
        initialize(&admin).await;
        let resource = Resource {
            id: "reservation".into(),
            incarnation: "db-1".into(),
        };
        admin.execute("INSERT INTO kf_reservation.resource VALUES ('current-tests','reservations',$1,$2,1,0,'free',true)",&[&resource.id,&resource.incarnation]).await.unwrap();
        let contract = digest("current-test-contract", &json!(config.database)).unwrap();
        let restore = digest(
            "postgres-restore-state",
            &json!({"resource":resource,"reservation":"free"}),
        )
        .unwrap();
        let capture = json!({"tenant":"current-tests","conflict_domain":"reservations","resource":resource,"baseline_version":1,"contract_digest":contract,"restore_state_digest":restore});
        admin
            .query_one("SELECT kf_compensation.capture($1::jsonb)", &[&capture])
            .await
            .unwrap();
        let original = DispatchRequest {
            profile: pg::PROFILE.into(),
            action: pg::ACTION.into(),
            tenant: "current-tests".into(),
            conflict_domain: "reservations".into(),
            attempt_id: "forward".into(),
            grant_digest: "a".repeat(64),
            root_id: "root-forward".into(),
            resource,
            expected_version: 1,
            fence: 1,
            reservation: "held".into(),
            gateway_workload: "spiffe://test/gateway".into(),
            expires_at: (SystemClock.now_ms() + 5000) as u64,
        };
        let out = PostgresStore::new(config.clone())
            .unwrap()
            .with_peer_uid(rustix::process::geteuid().as_raw())
            .unwrap()
            .apply(&original)
            .await
            .unwrap();
        assert_eq!(out.status, pg::Status::Committed);
        let q = BarrierQuery {
            tenant: original.tenant.clone(),
            contract_digest: contract,
            forward_attempt_id: original.attempt_id.clone(),
            forward_grant_digest: original.grant_digest.clone(),
            forward_root_id: original.root_id.clone(),
        };
        let reader = reader(&config, "kf_inverse_barrier");
        Some(Self {
            _serial: serial,
            admin,
            owner,
            config,
            reader,
            q,
            original,
        })
    }
    async fn identity(&self) -> StorageIdentity {
        self.reader.identity().await.unwrap()
    }
}
#[tokio::test]
async fn current_sql_actual_peer_identity_and_original_reservation_survive_request_expiry_as_read_only()
 {
    let Some(f) = Ready::new().await else { return };
    let identity = f.identity().await;
    assert_eq!(identity.database, f.config.database);
    assert!(identity.postmaster_started_at_us / 1000 <= SystemClock.now_ms() as u64);
    let old = f.reader.current(&f.q, &identity).await.unwrap().unwrap();
    assert_eq!(old.forward_outcome.request, f.original);
    assert_eq!(old.observed_version, 2);
    let delay = (f.original.expires_at as i64 - SystemClock.now_ms() + 10).max(0) as u64;
    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    assert!(SystemClock.now_ms() as u64 >= f.original.expires_at);
    assert!(f.reader.current(&f.q, &identity).await.unwrap().is_some());
    let row=f.admin.query_one("SELECT version,last_fence,reservation,(SELECT count(*) FROM kf_reservation.attempt),(SELECT count(*) FROM kf_compensation.attempt) FROM kf_reservation.resource",&[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, String>(2),
            row.get::<_, i64>(3),
            row.get::<_, i64>(4)
        ),
        (2, 1, "held".into(), 1, 0)
    );
}
#[tokio::test]
async fn current_sql_actual_peer_refuses_identity_role_acl_and_changed_current_row() {
    let Some(f) = Ready::new().await else { return };
    let identity = f.identity().await;
    assert!(reader(&f.config, "kf_reader").identity().await.is_err());
    f.admin
        .batch_execute("GRANT UPDATE ON kf_reservation.resource TO kf_inverse_barrier")
        .await
        .unwrap();
    let denied = f.reader.current(&f.q, &identity).await.is_err();
    f.admin
        .batch_execute("REVOKE UPDATE ON kf_reservation.resource FROM kf_inverse_barrier")
        .await
        .unwrap();
    assert!(denied);
    for update in [
        "version=3",
        "last_fence=2",
        "reservation='other'",
        "incarnation='recreated'",
        "active=false",
        "conflict_domain='other'",
    ] {
        f.admin
            .batch_execute(&format!("UPDATE kf_reservation.resource SET {update}"))
            .await
            .unwrap();
        assert!(
            f.reader.current(&f.q, &identity).await.unwrap().is_none(),
            "{update}"
        );
        f.admin.batch_execute("UPDATE kf_reservation.resource SET version=2,last_fence=1,reservation='held',incarnation='db-1',active=true,conflict_domain='reservations'").await.unwrap();
    }
    for field in [
        "forward_attempt_id",
        "forward_grant_digest",
        "forward_root_id",
        "contract_digest",
        "tenant",
    ] {
        let mut bad = json!(f.q);
        bad[field] = json!(if field.ends_with("digest") {
            "b".repeat(64)
        } else {
            "other".into()
        });
        let bad = serde_json::from_value(bad).unwrap();
        assert!(
            f.reader.current(&bad, &identity).await.unwrap().is_none(),
            "{field}"
        );
    }
    let mut wrong = identity.clone();
    wrong.database_oid += 1;
    assert!(f.reader.current(&f.q, &wrong).await.is_err());
    let mut wrong = identity;
    wrong.postmaster_started_at_us += 1;
    assert!(f.reader.current(&f.q, &wrong).await.is_err());
}
#[tokio::test]
async fn current_sql_actual_recreated_database_with_identical_original_rows_requires_fresh_identity()
 {
    let Some(f) = Ready::new().await else { return };
    let old = f.identity().await;
    let mut rows = Vec::new();
    for table in [
        "kf_reservation.resource",
        "kf_reservation.attempt",
        "kf_compensation.snapshot",
    ] {
        let v: Value = f
            .admin
            .query_one(&format!("SELECT to_jsonb(t) FROM {table} t"), &[])
            .await
            .unwrap()
            .get(0);
        rows.push((table, v));
    }
    let mut root_config = f.config.clone();
    root_config.database = "postgres".into();
    let root = connect(&root_config, &f.owner).await;
    root.batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", f.config.database))
        .await
        .unwrap();
    root.batch_execute(&format!("CREATE DATABASE {}", f.config.database))
        .await
        .unwrap();
    let admin = connect(&f.config, &f.owner).await;
    initialize(&admin).await;
    for (table, row) in rows {
        admin.execute(&format!("INSERT INTO {table} SELECT * FROM pg_catalog.jsonb_populate_record(NULL::{table},$1::jsonb)"),&[&row]).await.unwrap();
    }
    let new = f.reader.identity().await.unwrap();
    assert_eq!(old.database, new.database);
    assert_ne!(old.database_oid, new.database_oid);
    assert_eq!(old.postmaster_started_at_us, new.postmaster_started_at_us);
    assert!(f.reader.current(&f.q, &old).await.is_err());
    assert!(f.reader.current(&f.q, &new).await.unwrap().is_some());
}
#[tokio::test]
async fn current_sql_actual_owned_postmaster_restart_refuses_the_original_storage_lifetime() {
    let Some(f) = Ready::new().await else { return };
    let old = f.identity().await;
    let data: String = f
        .admin
        .query_one("SHOW data_directory", &[])
        .await
        .unwrap()
        .get(0);
    let data = std::fs::canonicalize(data).unwrap();
    let socket = std::fs::canonicalize(&f.config.socket_directory).unwrap();
    assert_eq!(data.parent(), Some(socket.as_path()));
    assert_eq!(data.file_name().unwrap(), "data");
    assert!(
        socket
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("kf-pg-")
    );
    let ctl = PathBuf::from(std::env::var("KF_POSTGRES_TEST_BINDIR").unwrap()).join("pg_ctl");
    assert!(ctl.is_absolute() && ctl.is_file());
    let restart_log = socket.join("current-source-restart.log");
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new(ctl)
            .arg("-D")
            .arg(data)
            .arg("-l")
            .arg(restart_log)
            .args(["-m", "fast", "-w", "-t", "10", "restart"])
            .output()
            .unwrap()
            .status
    })
    .await
    .unwrap();
    assert!(status.success());
    let new = f.reader.identity().await.unwrap();
    assert_eq!(new.database_oid, old.database_oid);
    assert_ne!(new.postmaster_started_at_us, old.postmaster_started_at_us);
    assert!(f.reader.current(&f.q, &old).await.is_err());
    assert!(f.reader.current(&f.q, &new).await.unwrap().is_some());
}

#[path = "support/current_reservation_fixture.rs"]
mod source_fixture;
fn head_record(
    r: &kedgeflow::current_reservation::Registration,
    sequence: u64,
) -> kedgeflow::current_reservation_provider::HeadRecord {
    use kedgeflow::current_reservation::{PROFILE, Signed, StorageHead};
    let head = Signed::sign(
        "storage_head",
        StorageHead {
            storage_id: r.storage.storage_id.clone(),
            generation: r.storage.generation,
            sequence,
            resource: r.resource.clone(),
            boundary_digest: digest("sql-storage-boundary", &json!(r.storage)).unwrap(),
            published_at: 1000,
            expires_at: 10000,
        },
        &r.storage.owner,
        "key",
        &ed25519_dalek::SigningKey::from_bytes(&[95; 32]),
    )
    .unwrap();
    kedgeflow::current_reservation_provider::HeadRecord {
        profile: PROFILE.into(),
        registration_digest: r.digest().unwrap(),
        current_digest: head.digest().unwrap(),
        minimum_sequence: sequence,
        head,
    }
}
#[tokio::test]
async fn current_sql_protected_head_checks_owner_current_digest_floor_and_process_monotonicity() {
    use kedgeflow::current_reservation_provider::{FileHead, HeadSource};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("head.json");
    let r = source_fixture::registration();
    let write = |record: &kedgeflow::current_reservation_provider::HeadRecord| {
        std::fs::write(&path, serde_json::to_vec(record).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    let first = head_record(&r, 1);
    write(&first);
    let source = FileHead::new(&root, path.clone()).unwrap();
    source.current(&r, 2000).await.unwrap();
    let second = head_record(&r, 2);
    write(&second);
    source.current(&r, 2000).await.unwrap();
    write(&first);
    assert!(source.current(&r, 2000).await.is_err());
    let mut changed = second.clone();
    changed.head.body.expires_at = 9000;
    changed.head = kedgeflow::current_reservation::Signed::sign(
        "storage_head",
        changed.head.body,
        &r.storage.owner,
        "key",
        &ed25519_dalek::SigningKey::from_bytes(&[95; 32]),
    )
    .unwrap();
    changed.current_digest = changed.head.digest().unwrap();
    write(&changed);
    assert!(source.current(&r, 2000).await.is_err());
    write(&second);
    assert!(source.current(&r, 10000).await.is_err());
    let mut bad = second.clone();
    bad.minimum_sequence = 3;
    write(&bad);
    assert!(
        FileHead::new(&root, path.clone())
            .unwrap()
            .current(&r, 2000)
            .await
            .is_err()
    );
    let mut bad = second.clone();
    bad.current_digest = "a".repeat(64);
    write(&bad);
    assert!(source.current(&r, 2000).await.is_err());
    let mut bad = second.clone();
    bad.head.signature.clear();
    write(&bad);
    assert!(source.current(&r, 2000).await.is_err());
    write(&second);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(source.current(&r, 2000).await.is_err());
}
#[test]
fn current_sql_v2_identity_and_managed_v11_do_not_reinterpret_the_prototype() {
    let r = source_fixture::registration();
    let mut old = json!(r);
    old["profile"] = json!("KF-CURRENT-SQL-RESERVATION-0.1-draft");
    let old: kedgeflow::current_reservation::Registration = serde_json::from_value(old).unwrap();
    assert!(old.validate().is_err());
    let mut absent = json!(r);
    absent["storage"]
        .as_object_mut()
        .unwrap()
        .remove("identity");
    assert!(
        serde_json::from_value::<kedgeflow::current_reservation::Registration>(absent).is_err()
    );
    for identity in [
        json!(null),
        json!({"database":"postgres","database_oid":0,"postmaster_started_at_us":1}),
        json!({"database":"postgres","database_oid":1,"postmaster_started_at_us":0}),
        json!({"database":"postgres","database_oid":1,"postmaster_started_at_us":1,"restore_allowed":true}),
    ] {
        let mut bad = json!(r);
        bad["storage"]["identity"] = identity;
        assert!(
            serde_json::from_value::<kedgeflow::current_reservation::Registration>(bad)
                .map_or(true, |r| r.validate().is_err())
        );
    }
    let schema =
        kedgeflow::managed_drain::parameter_schema(&"a".repeat(64), &"b".repeat(64), "node-1", 1)
            .unwrap();
    kedgeflow::managed_drain::validate_schema("1.1", &schema).unwrap();
    assert!(kedgeflow::managed_drain::validate_schema("1.0", &schema).is_err());
    let mut old = schema;
    old["$comment"] = json!(format!(
        "KF-MANAGED-KUBE-DRAIN-0.1-draft enrollment={} mechanical={}",
        "a".repeat(64),
        "b".repeat(64)
    ));
    assert!(kedgeflow::managed_drain::validate_schema("1.1", &old).is_err());
}
