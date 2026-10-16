//! Real stale pg_dump/pg_restore copy with native consumed authority kept outside SQL.
use super::*;
use kedgeflow::{
    error::{Error, Result},
    ledger::{AuthoritativeObservation, IssuanceRecord},
    postgres_compensation::{Database, Outcome, PostgresCompensationStore},
    postgres_store::UnixDatabase,
    recovery::{Candidate, ReceiptHead},
};

pub(super) struct Backup {
    path: PathBuf,
    bindir: PathBuf,
    source: UnixDatabase,
    sha256: String,
}
fn command(
    bindir: &Path,
    executable: &str,
    db: &UnixDatabase,
    role: &str,
) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(bindir.join(executable));
    c.env("PGHOST", &db.socket_directory)
        .env("PGPORT", db.port.to_string())
        .env("PGDATABASE", &db.database)
        .env("PGUSER", role)
        .env("PGCONNECT_TIMEOUT", "2")
        .kill_on_drop(true);
    c
}
async fn output(mut c: tokio::process::Command) -> std::process::Output {
    tokio::time::timeout(Duration::from_secs(30), c.output())
        .await
        .expect("bounded PostgreSQL tool timed out")
        .unwrap()
}
fn success(o: std::process::Output) -> Vec<u8> {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    o.stdout
}
impl Backup {
    pub(super) async fn capture(directory: &Path, source: &UnixDatabase) -> Self {
        let bindir = PathBuf::from(
            std::env::var("KF_POSTGRES_TEST_BINDIR")
                .expect("disposable runner pins pg_dump/pg_restore"),
        );
        let path = directory.join("before-inverse.dump");
        let mut c = command(
            &bindir,
            "pg_dump",
            source,
            &std::env::var("KF_POSTGRES_TEST_USER").unwrap(),
        );
        c.arg("-Fc")
            .arg("--schema=kf_reservation")
            .arg("--schema=kf_compensation")
            .arg("--file")
            .arg(&path);
        success(output(c).await);
        let sha256 = hex::encode(Sha256::digest(std::fs::read(&path).unwrap()));
        Self {
            path,
            bindir,
            source: source.clone(),
            sha256,
        }
    }
    async fn login(&self, db: &UnixDatabase, role: &str) -> std::process::Output {
        let mut c = command(&self.bindir, "psql", db, role);
        c.args([
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "SELECT current_user;",
        ]);
        output(c).await
    }
    async fn fenced(&self, db: &UnixDatabase) {
        for role in [
            "kf_executor",
            "kf_reader",
            "kf_inverse_executor",
            "kf_inverse_reader",
            "kf_inverse_barrier",
        ] {
            let o = self.login(db, role).await;
            assert!(!o.status.success());
            assert!(
                String::from_utf8_lossy(&o.stderr).contains("too many connections for database"),
                "{}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
    }
}
struct Query {
    store: Arc<PostgresCompensationStore>,
    tenant: String,
    calls: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl OutcomeQuerier for Query {
    async fn query(&self, attempt: &str) -> Result<AuthoritativeObservation> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let o = self
            .store
            .lookup(&self.tenant, attempt)
            .await?
            .ok_or_else(|| {
                Error::Unknown(
                    "original inverse missing from restored SQL; no absence proof".into(),
                )
            })?;
        Ok(AuthoritativeObservation {
            attempt_id: o.request.attempt_id,
            root_id: o.request.root_id,
            grant_digest: o.request.grant_digest,
            target_reference: "postgres/inverse/restored-copy".into(),
            status: match o.status {
                kedgeflow::postgres_action::Status::Committed => "committed",
                _ => "fenced_no_effect",
            }
            .into(),
        })
    }
}
// Test-only owner operations affect a fresh random database in the disposable
// cluster. No existing database, authority prefix or witness is restored.
pub(super) async fn rehearse(
    h: &SqlInverseReady,
    rec: &IssuanceRecord,
    c: &Candidate,
    external: &Outcome,
    retained: Option<&ReceiptHead>,
    backup: &Backup,
    gate: &RestoreGate,
) {
    let before = h.inverse.ledger.compensation_spend().await.unwrap();
    assert_eq!(
        before.state,
        if retained.is_some() {
            kedgeflow::coordination::ReservationState::Committed
        } else {
            kedgeflow::coordination::ReservationState::Unknown
        }
    );
    let budget = native::budget(&h.forward, &h.registration).await;
    let witness = gate.check(&h.inverse.ledger).await.unwrap();
    let name = format!("kf_inverse_restore_{:x}", rand::random::<u64>());
    let mut restored = backup.source.clone();
    restored.database = name.clone();
    h.admin
        .batch_execute(&format!("CREATE DATABASE {name} CONNECTION LIMIT 0"))
        .await
        .unwrap();
    backup.fenced(&restored).await;
    let mut restore = command(
        &backup.bindir,
        "pg_restore",
        &restored,
        &std::env::var("KF_POSTGRES_TEST_USER").unwrap(),
    );
    restore
        .arg("--exit-on-error")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg("--dbname")
        .arg(&name)
        .arg(&backup.path);
    success(output(restore).await);
    backup.fenced(&restored).await;
    let owner = super::super::super::super::sql_leaf::owner(&restored).await;
    owner.batch_execute(&format!("REVOKE ALL ON DATABASE {name} FROM PUBLIC; REVOKE ALL ON SCHEMA kf_reservation,kf_compensation FROM PUBLIC,kf_executor,kf_reader,kf_inverse_executor,kf_inverse_reader,kf_inverse_barrier; REVOKE ALL ON ALL TABLES IN SCHEMA kf_reservation,kf_compensation FROM PUBLIC,kf_executor,kf_reader,kf_inverse_executor,kf_inverse_reader,kf_inverse_barrier; REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kf_reservation,kf_compensation FROM PUBLIC,kf_executor,kf_reader,kf_inverse_executor,kf_inverse_reader,kf_inverse_barrier;")).await.unwrap();
    // Retain the original actual commit outside the stale SQL copy. Native
    // recovery never treats this unsigned test-owner file as a receipt source.
    assert_eq!(external.request.attempt_id, c.attempt_id);
    assert_eq!(external.request.root_id, c.grant.root_id);
    assert_eq!(external.request.grant_digest, rec.grant_digest);
    assert_eq!(
        external.status,
        kedgeflow::postgres_action::Status::Committed
    );
    let external_path = backup.path.with_extension("external-commit.json");
    std::fs::write(&external_path, serde_json::to_vec(external).unwrap()).unwrap();
    std::fs::set_permissions(&external_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let external_hash = hex::encode(Sha256::digest(std::fs::read(&external_path).unwrap()));
    let missing: Option<Value> = owner
        .query_one(
            "SELECT kf_compensation.lookup($1,$2)",
            &[&h.pin.tenant, &c.attempt_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(missing.is_none());
    let row=owner.query_one("SELECT version,last_fence,reservation,incarnation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 242);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, String>(2), "booking:pilot");
    assert_eq!(row.get::<_, String>(3), h.pin.resource.incarnation);
    let original: Value = owner
        .query_one(
            "SELECT kf_reservation.lookup($1,$2)",
            &[&h.pin.tenant, &external.request.forward_attempt_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(original["status"], "committed");
    let incarnation = format!("restored-{:x}", rand::random::<u64>());
    owner
        .execute(
            "UPDATE kf_reservation.resource SET incarnation=$1 WHERE tenant=$2 AND resource_id=$3",
            &[&incarnation, &h.pin.tenant, &h.pin.resource.id],
        )
        .await
        .unwrap();
    // Only the reader can connect after lifting the coarse database fence.
    // Old executor/barrier and forward roles stay denied; no service resumes.
    owner.batch_execute(&format!("GRANT CONNECT ON DATABASE {name} TO kf_inverse_reader; GRANT USAGE ON SCHEMA kf_reservation,kf_compensation TO kf_inverse_reader; GRANT EXECUTE ON FUNCTION kf_compensation.lookup(text,text) TO kf_inverse_reader; ALTER DATABASE {name} CONNECTION LIMIT -1;")).await.unwrap();
    assert_eq!(
        String::from_utf8(success(backup.login(&restored, "kf_inverse_reader").await))
            .unwrap()
            .trim(),
        "kf_inverse_reader"
    );
    for role in [
        "kf_executor",
        "kf_reader",
        "kf_inverse_executor",
        "kf_inverse_barrier",
    ] {
        let o = backup.login(&restored, role).await;
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("permission denied for database"));
    }
    let mut denied = command(&backup.bindir, "psql", &restored, "kf_inverse_reader");
    denied.args([
        "-X",
        "-qAt",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        "SELECT kf_compensation.apply('{}'::jsonb);",
    ]);
    let denied = output(denied).await;
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("permission denied for function apply"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    let store = Arc::new(
        PostgresCompensationStore::new(Database {
            connection: UnixDatabase {
                executor_user: "kf_inverse_executor".into(),
                query_user: "kf_inverse_reader".into(),
                ..restored.clone()
            },
            barrier_user: "kf_inverse_barrier".into(),
        })
        .unwrap(),
    );
    assert!(store.check_database().await.is_err());
    assert!(
        store
            .lookup(&h.pin.tenant, &c.attempt_id)
            .await
            .unwrap()
            .is_none()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = kedgeflow::recovery::RecoveryWorker::new(
        h.inverse.ledger.clone(),
        h.grants(),
        Arc::new(Query {
            store: store.clone(),
            tenant: h.pin.tenant.clone(),
            calls: calls.clone(),
        }),
        "key-19".into(),
        SigningKey::from_bytes(&[19; 32]),
        "spiffe://test/inverse-outcome".into(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let receipt = worker.recover(c).await.unwrap();
    if let Some(retained) = retained {
        assert_eq!(json!(receipt), json!(retained));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    } else {
        assert_eq!(receipt.state, "unknown");
        assert!(calls.load(Ordering::SeqCst) > 0);
    }
    assert_eq!(json!(worker.recover(c).await.unwrap()), json!(receipt));
    let after = h.inverse.ledger.compensation_spend().await.unwrap();
    assert_eq!(after, before);
    assert_eq!(native::budget(&h.forward, &h.registration).await, budget);
    assert_eq!(
        gate.check(&h.inverse.ledger).await.unwrap().enrollment,
        witness.enrollment
    );
    assert!(
        h.inverse
            .ledger
            .claim(&c.grant, &rec.grant_digest, "restore-replacement")
            .await
            .is_err()
    );
    assert!(
        h.inverse
            .ledger
            .authorize_dispatch(&c.grant, &rec.grant_digest, &c.attempt_id)
            .await
            .is_err()
    );
    let audit = Box::pin(super::super::lineage::export(h)).await.unwrap();
    let checked =
        kedgeflow::compensation_lineage::verify(&audit, &super::super::lineage::trust(h)).unwrap();
    assert_eq!(
        checked.status,
        if retained.is_some() {
            "compensated"
        } else {
            "unresolved"
        }
    );
    assert!(!checked.execution_authority);
    assert!(
        store
            .lookup(&h.pin.tenant, &c.attempt_id)
            .await
            .unwrap()
            .is_none()
    );
    let row=owner.query_one("SELECT version,last_fence,reservation,incarnation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 242);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, String>(2), "booking:pilot");
    assert_eq!(row.get::<_, String>(3), incarnation);
    assert_eq!(
        hex::encode(Sha256::digest(std::fs::read(&backup.path).unwrap())),
        backup.sha256
    );
    assert_eq!(
        hex::encode(Sha256::digest(std::fs::read(&external_path).unwrap())),
        external_hash
    );
    println!(
        "inverse SQL restore rehearsal: {}",
        json!({"status":"passed","restore_kind":"stale logical dump into new query-only database","backup_sha256":backup.sha256,"external_commit_sha256":external_hash,"original_root":c.grant.root_id,"original_grant":rec.grant_digest,"original_attempt":c.attempt_id,"original_sql_commit":external,"restored_original_lookup":null,"native_state":receipt.state,"receipt_digest":receipt.receipt_digest,"held_spend":after,"forward_budget_unchanged":true,"authority_consumption_tested":true,"witness_enrollment_retained":witness.enrollment,"application_connection_fence":"five original roles denied before/after restore; only inverse reader admitted later","old_executor_barrier_connections":"denied","reader_mutation":"denied","restored_incarnation":incarnation,"original_redispatches":0,"additional_mints_after_restore":0,"automatic_resume":false,"scope":"local same-host one-UID logical copy; historical evidence is not restored live state or physical/enterprise acceptance"})
    );
    drop(owner);
    drop(store);
    drop(worker);
    h.admin
        .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .await
        .unwrap();
}
