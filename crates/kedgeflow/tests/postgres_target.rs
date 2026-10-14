//! Generated identity/grant/permit fixtures; actual mTLS, native SQL roles and COMMIT.
#[path = "support/domain.rs"]
mod domain;
mod support;
use async_trait::async_trait;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    adapter::ResourceAdapter,
    broker::TargetCredential,
    broker_authorization::{ExchangePermit, PROFILE as PERMIT_PROFILE},
    clock::{Clock, SystemClock},
    contracts::{GrantVerifier, digest, sign_grant},
    error::Result,
    gateway::VerifiedCall,
    ledger::OutcomeQuerier,
    postgres_action::{DispatchRequest, Outcome},
    postgres_adapter::PostgresAdapter,
    postgres_config::PostgresTargetConfig,
    postgres_store::{PostgresStore, ReservationStore, UnixDatabase},
    postgres_target::{PROFILE, Registration, TargetService},
    recovery_config::HttpOutcomeQuerier,
    target_token::{ReferenceTokenMinter, TargetTokenMinter, TargetTokenVerifier},
    tls,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Notify;

const GATEWAY: &str = "spiffe://test/sql-gateway";
const QUERY: &str = "spiffe://test/sql-recovery";
const QUERY_TOKEN: &str = "generated-fixture-query-token-00000000000000000000000";
const ISSUER: &str = "https://broker.test/exchange";

struct HeldReply {
    real: Arc<PostgresStore>,
    committed: Notify,
    release: Notify,
}
#[async_trait]
impl ReservationStore for HeldReply {
    async fn apply(&self, q: &DispatchRequest) -> Result<Outcome> {
        let outcome = self.real.apply(q).await?;
        self.committed.notify_one();
        self.release.notified().await;
        Ok(outcome)
    }
    async fn lookup(&self, tenant: &str, id: &str) -> Result<Option<Outcome>> {
        self.real.lookup(tenant, id).await
    }
}
struct Harness {
    admin: tokio_postgres::Client,
    database: UnixDatabase,
    store: Arc<PostgresStore>,
    held: Option<Arc<HeldReply>>,
    call: VerifiedCall,
    registration: Registration,
    grants: GrantVerifier,
    credential: TargetCredential,
    pki: Vec<support::Pki>,
    url: String,
    query_url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort()
    }
}
impl Harness {
    async fn new(resource: &str, held: bool) -> Option<Self> {
        let socket = match std::env::var("KF_POSTGRES_TEST_SOCKET") {
            Ok(p) => p,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_POSTGRES").as_deref(), Ok("1"));
                eprintln!("SKIP native PostgreSQL: disposable test socket absent");
                return None;
            }
        };
        let mut config = tokio_postgres::Config::new();
        config
            .host_path(&socket)
            .port(5432)
            .dbname("postgres")
            .user(std::env::var("KF_POSTGRES_TEST_USER").unwrap());
        let (admin, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        admin.execute("INSERT INTO kf_reservation.resource VALUES ('native','reservations',$1,'incarnation-1',1,0,'free',true)", &[&resource]).await.unwrap();
        let database = UnixDatabase {
            socket_directory: socket.into(),
            port: 5432,
            database: "postgres".into(),
            executor_user: "kf_executor".into(),
            query_user: "kf_reader".into(),
        };
        let store = Arc::new(PostgresStore::new(database.clone()).unwrap());
        let (mut call, mut grants) = domain::call();
        let now = SystemClock.now_ms();
        let g = &mut call.grant;
        g.issued_at = now - 1000;
        g.valid_from = now - 1000;
        g.expires_at = now + 120000;
        g.audience = "https://gateway.test/mcp".into();
        g.gid = format!("grant-{resource}");
        g.conflict_domain = "reservations".into();
        g.root_id = format!("root-{resource}");
        g.nonce = format!("nonce-{resource}");
        g.fence = 10;
        g.resources[0].id = resource.into();
        g.resources[0].incarnation = "incarnation-1".into();
        g.action.id = "native:action:reservation-set".into();
        g.adapter_contract["guard_scope"] = json!([resource]);
        g.adapter_contract["commit_point"] =
            json!("PostgreSQL conditional reservation and outcome transaction");
        g.predicate_descriptor["clauses"][0]["resource"] = json!(g.resources[0]);
        call.request.params.arguments =
            json!({"resource_id":resource,"expected_version":1,"reservation":"booking-native"});
        g.parameters_digest = digest("parameters", &call.request.params.arguments).unwrap();
        call.attempt_id = format!("attempt-{resource}");
        call.signed_grant = sign_grant(g, "test-key", &SigningKey::from_bytes(&[6; 32])).unwrap();
        grants.audience = g.audience.clone();
        call.grant_digest = grants.verify(&call.signed_grant, now).unwrap().digest;
        let registration = Registration {
            tenant: "native".into(),
            conflict_domain: g.conflict_domain.clone(),
            action: g.action.clone(),
            resource: g.resources[0].clone(),
            adapter_contract: g.adapter_contract.clone(),
            predicate_id: g.predicate_descriptor["id"].as_str().unwrap().into(),
            predicate_version: "1.0".into(),
            gateway_workload: GATEWAY.into(),
            query_workload: QUERY.into(),
            target_audience: "https://sql-target.test/reservations".into(),
            target_scope: "reservation:write".into(),
        };
        // A generated permit is not an independently observed broker/etcd claim.
        let permit = ExchangePermit {
            profile: PERMIT_PROFILE.into(),
            permit_id: digest("synthetic-test-permit", &json!({"resource":resource})).unwrap(),
            registration_digest: "a".repeat(64),
            grant_digest: call.grant_digest.clone(),
            root_id: g.root_id.clone(),
            attempt_id: call.attempt_id.clone(),
            gateway_workload: GATEWAY.into(),
            target_audience: registration.target_audience.clone(),
            target_scope: registration.target_scope.clone(),
            authorized_at: now,
            expires_at: g.expires_at,
        };
        let token = ReferenceTokenMinter::new(
            ISSUER.into(),
            "target".into(),
            SigningKey::from_bytes(&[29; 32]),
        )
        .unwrap()
        .mint(&permit, now)
        .await
        .unwrap();
        let credential = TargetCredential {
            token,
            expires_at_ms: g.expires_at / 1000 * 1000,
            audience: registration.target_audience.clone(),
        };
        let pki = support::pki_for_workloads(&[GATEWAY, QUERY, "spiffe://test/sql-agent"]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("https://localhost:{}/dispatch", address.port());
        let query_url = format!("https://localhost:{}/query", address.port());
        let held = held.then(|| {
            Arc::new(HeldReply {
                real: store.clone(),
                committed: Notify::new(),
                release: Notify::new(),
            })
        });
        let backend: Arc<dyn ReservationStore> = match &held {
            Some(s) => s.clone(),
            None => store.clone(),
        };
        let service = TargetService::new(
            registration.clone(),
            grants.clone(),
            Self::tokens(),
            backend,
            Arc::new(SystemClock),
            &url,
            &query_url,
            QUERY_TOKEN,
        )
        .unwrap();
        let config = tls::server_config_pem(
            pki[0].server.as_bytes(),
            pki[0].server_key.as_bytes(),
            pki[0].ca.as_bytes(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, config, Arc::new(service).router())
                .await
                .unwrap()
        });
        Some(Self {
            admin,
            database,
            store,
            held,
            call,
            registration,
            grants,
            credential,
            pki,
            url,
            query_url,
            task,
        })
    }
    fn tokens() -> TargetTokenVerifier {
        TargetTokenVerifier::new(
            ISSUER.into(),
            BTreeMap::from([(
                "target".into(),
                SigningKey::from_bytes(&[29; 32]).verifying_key(),
            )]),
        )
        .unwrap()
    }
    fn client(&self, role: usize) -> tls::PinnedClient {
        let p = &self.pki[role];
        tls::pinned_client_pem(
            p.ca.as_bytes(),
            p.client.as_bytes(),
            p.client_key.as_bytes(),
            Duration::from_secs(10),
        )
        .unwrap()
    }
    fn body(&self) -> Value {
        json!({"profile":PROFILE,"operation":"dispatch","signed_grant":URL_SAFE_NO_PAD.encode(&self.call.signed_grant),"attempt_id":self.call.attempt_id,"parameters":self.call.request.params.arguments})
    }
    fn adapter(&self) -> PostgresAdapter {
        PostgresAdapter::new(
            &self.url,
            self.client(0),
            self.registration.clone(),
            self.grants.clone(),
            Self::tokens(),
            Arc::new(SystemClock),
        )
        .unwrap()
    }
    fn query(&self) -> HttpOutcomeQuerier {
        HttpOutcomeQuerier::new(
            self.client(1).client().clone(),
            &self.query_url,
            QUERY_TOKEN.into(),
        )
        .unwrap()
    }
    async fn state(&self) -> (i64, String) {
        let row=self.admin.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant='native' AND resource_id=$1", &[&self.registration.resource.id]).await.unwrap();
        (row.get(0), row.get(1))
    }
}

#[tokio::test]
async fn native_sql_commit_replay_and_independent_query() {
    let Some(h) = Harness::new("sql-positive", false).await else {
        return;
    };
    let result = h.adapter().dispatch(&h.call, &h.credential).await.unwrap();
    assert_eq!(result.status, "committed");
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let c = h.client(0);
        let url = h.url.clone();
        let token = h.credential.token.clone();
        let body = h.body();
        tasks.spawn(async move {
            c.client()
                .post(url)
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap()["status"], "committed")
    }
    assert_eq!(h.state().await, (2, "booking-native".into()));
    let observed = h.query().query(&h.call.attempt_id).await.unwrap();
    assert_eq!(observed.status, "committed");
    assert_eq!(observed.grant_digest, h.call.grant_digest);
    assert_eq!(observed.root_id, h.call.grant.root_id);
    assert!(h.query().query("missing-attempt").await.is_err());
    assert!(
        h.adapter()
            .read(&h.call.request, &h.call.identity)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_sql_guard_rejection_retains_no_effect_without_resource_mutation() {
    let Some(h) = Harness::new("sql-stale-version", false).await else {
        return;
    };
    // Trusted fixture writer changes the row after its signed version witness.
    h.admin
        .execute(
            "UPDATE kf_reservation.resource SET version=2 WHERE tenant='native' AND resource_id=$1",
            &[&h.registration.resource.id],
        )
        .await
        .unwrap();
    let outcome = h.adapter().dispatch(&h.call, &h.credential).await.unwrap();
    assert_eq!(outcome.status, "state_guard_violation");
    assert_eq!(
        h.query().query(&h.call.attempt_id).await.unwrap().status,
        "fenced_no_effect"
    );
    assert_eq!(h.state().await, (2, "free".into()));
}

#[tokio::test]
async fn native_sql_refuses_wrong_workloads_grants_parameters_and_credentials_before_write() {
    let Some(h) = Harness::new("sql-negative", false).await else {
        return;
    };
    for role in [1, 2] {
        let r = h
            .client(role)
            .client()
            .post(&h.url)
            .header("x-spiffe-id", GATEWAY)
            .bearer_auth(&h.credential.token)
            .json(&h.body())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }
    for token in ["subject-token-never-forwarded", "invalid.target.credential"] {
        assert!(
            !h.client(0)
                .client()
                .post(&h.url)
                .bearer_auth(token)
                .json(&h.body())
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
    }
    let segments: Vec<_> = h.credential.token.split('.').collect();
    let original: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
    for (field, value) in [
        ("aud", json!("https://other-target.test/")),
        ("scope", json!("reservation:admin")),
        ("root_id", json!("other-root")),
        ("gateway_workload", json!("spiffe://test/other-gateway")),
        ("iss", json!("https://other-broker.test/exchange")),
        ("exp", json!(1)),
    ] {
        let mut claims = original.clone();
        claims[field] = value;
        let input = format!(
            "{}.{}",
            segments[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let token = format!(
            "{}.{}",
            input,
            URL_SAFE_NO_PAD.encode(
                SigningKey::from_bytes(&[29; 32])
                    .sign(input.as_bytes())
                    .to_bytes()
            )
        );
        assert_eq!(
            h.client(0)
                .client()
                .post(&h.url)
                .bearer_auth(token)
                .json(&h.body())
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "{field}"
        );
    }
    let no_cert = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(h.pki[0].ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert!(
        no_cert
            .post(&h.url)
            .bearer_auth(&h.credential.token)
            .json(&h.body())
            .send()
            .await
            .is_err()
    );
    let mut wrong = h.body();
    wrong["parameters"]["reservation"] = json!("substituted");
    assert_eq!(
        h.client(0)
            .client()
            .post(&h.url)
            .bearer_auth(&h.credential.token)
            .json(&wrong)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    wrong = h.body();
    wrong["attempt_id"] = json!("other-attempt");
    assert_eq!(
        h.client(0)
            .client()
            .post(&h.url)
            .bearer_auth(&h.credential.token)
            .json(&wrong)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    wrong = h.body();
    wrong["sql"] = json!("DELETE FROM resource");
    assert_eq!(
        h.client(0)
            .client()
            .post(&h.url)
            .bearer_auth(&h.credential.token)
            .json(&wrong)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let r = h
        .client(0)
        .client()
        .post(&h.url)
        .header("origin", "https://browser.test")
        .bearer_auth(&h.credential.token)
        .json(&h.body())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert!(h.client(0).client().post(&h.query_url).bearer_auth(QUERY_TOKEN).json(&json!({"profile":kedgeflow::recovery::PROFILE,"operation":"query","attempt_id":h.call.attempt_id})).send().await.unwrap().status()==401);
    assert_eq!(h.state().await, (1, "free".into()));
    assert!(
        h.store
            .lookup("native", &h.call.attempt_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn native_sql_lost_client_reply_keeps_commit_and_query_without_dispatch() {
    let Some(h) = Harness::new("sql-disconnect", true).await else {
        return;
    };
    let client = h.client(0);
    let url = h.url.clone();
    let body = h.body();
    let token = h.credential.token.clone();
    let pending = tokio::spawn(async move {
        client
            .client()
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
    });
    let held = h.held.as_ref().unwrap();
    tokio::time::timeout(Duration::from_secs(5), held.committed.notified())
        .await
        .unwrap();
    pending.abort();
    let _ = pending.await;
    assert_eq!(
        h.query().query(&h.call.attempt_id).await.unwrap().status,
        "committed"
    );
    held.release.notify_one();
    assert_eq!(h.state().await, (2, "booking-native".into()));
}

#[tokio::test]
async fn native_sql_driver_refuses_owner_role_before_effect() {
    let Some(h) = Harness::new("sql-owner-role", false).await else {
        return;
    };
    let mut config = h.database.clone();
    config.executor_user = std::env::var("KF_POSTGRES_TEST_USER").unwrap();
    let store = PostgresStore::new(config).unwrap();
    let q = DispatchRequest {
        profile: kedgeflow::postgres_action::PROFILE.into(),
        action: kedgeflow::postgres_action::ACTION.into(),
        tenant: "native".into(),
        conflict_domain: h.registration.conflict_domain.clone(),
        attempt_id: h.call.attempt_id.clone(),
        grant_digest: h.call.grant_digest.clone(),
        root_id: h.call.grant.root_id.clone(),
        resource: h.registration.resource.clone(),
        expected_version: 1,
        fence: 10,
        reservation: "booking".into(),
        gateway_workload: GATEWAY.into(),
        expires_at: h.credential.expires_at_ms as u64,
    };
    assert!(matches!(
        store.apply(&q).await,
        Err(kedgeflow::error::Error::Refused(_))
    ));
    assert_eq!(h.state().await, (1, "free".into()));
}

#[tokio::test]
async fn shipping_sql_target_check_and_process_restart_preserve_commit() {
    let Some(mut h) = Harness::new("sql-check", false).await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    for (file, data) in [
        ("server.pem", &h.pki[0].server),
        ("key.pem", &h.pki[0].server_key),
        ("ca.pem", &h.pki[0].ca),
    ] {
        std::fs::write(p.join(file), data).unwrap()
    }
    std::fs::write(p.join("query.token"), QUERY_TOKEN).unwrap();
    let mut database = h.database.clone();
    database.socket_directory = p.join("absent-database");
    let mut config = PostgresTargetConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        dispatch_url: h.url.clone(),
        query_url: h.query_url.clone(),
        certificate: p.join("server.pem"),
        private_key: p.join("key.pem"),
        workload_ca: p.join("ca.pem"),
        database,
        gateway_audience: h.grants.audience.clone(),
        grant_keys: BTreeMap::from([(
            "test-key".into(),
            STANDARD.encode(SigningKey::from_bytes(&[6; 32]).verifying_key().as_bytes()),
        )]),
        token_issuer: ISSUER.into(),
        target_keys: BTreeMap::from([(
            "target".into(),
            STANDARD.encode(SigningKey::from_bytes(&[29; 32]).verifying_key().as_bytes()),
        )]),
        query_token_file: p.join("query.token"),
        registration: h.registration.clone(),
    };
    std::fs::write(p.join("config.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
        .arg("--config")
        .arg(p.join("config.json"))
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let active = |file: &std::path::Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
            .arg("--config")
            .arg(file)
            .arg("--check-database")
            .output()
            .unwrap()
    };
    assert!(!active(&p.join("config.json")).status.success());
    let conflict = std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
        .arg("--config")
        .arg(p.join("config.json"))
        .args(["--check", "--check-database"])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    config.database = h.database.clone();
    config.listen = format!(
        "127.0.0.1:{}",
        reqwest::Url::parse(&h.url).unwrap().port().unwrap()
    )
    .parse()
    .unwrap();
    // The original listener occupies this configured port. Successful active
    // preflight proves it neither binds that listener nor dispatches a probe.
    std::fs::write(p.join("config.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    let checked = active(&p.join("config.json"));
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let report: Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(
        report,
        json!({"profile":kedgeflow::postgres_store::ENROLLMENT_PROFILE,"operation":"check_database","database":"postgres","executor_user":"kf_executor","query_user":"kf_reader","status":"passed"})
    );
    config.database.query_user = std::env::var("KF_POSTGRES_TEST_USER").unwrap();
    std::fs::write(p.join("config.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!active(&p.join("config.json")).status.success());
    assert_eq!(h.admin.query_one("SELECT count(*) FROM kf_reservation.attempt WHERE tenant='native' AND attempt_id=$1",&[&h.call.attempt_id]).await.unwrap().get::<_,i64>(0),0);
    println!(
        "SQL enrollment PASS: shipping active preflight checks both roles with listener port occupied and no attempts; offline check accepts absent socket, active check refuses absent socket/admin query role and conflicting flags"
    );
    assert_eq!(h.state().await, (1, "free".into()));
    h.task.abort();
    let _ = (&mut h.task).await;
    config.database = h.database.clone();
    config.listen = format!(
        "127.0.0.1:{}",
        reqwest::Url::parse(&h.url).unwrap().port().unwrap()
    )
    .parse()
    .unwrap();
    std::fs::write(p.join("config.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    struct Shipping(std::process::Child);
    impl Drop for Shipping {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let start = || {
        Shipping(
            std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
                .arg("--config")
                .arg(p.join("config.json"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        )
    };
    async fn ready(h: &Harness, child: &mut Shipping, id: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "shipping target exited"
            );
            let result=h.client(1).client().post(&h.query_url).bearer_auth(QUERY_TOKEN)
                .json(&json!({"profile":kedgeflow::recovery::PROFILE,"operation":"query","attempt_id":id})).send().await;
            if result.is_ok_and(|r| r.status().is_success() || r.status() == 404) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "shipping target readiness timeout"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let mut child = start();
    ready(&h, &mut child, "unrecorded").await;
    assert_eq!(
        h.adapter()
            .dispatch(&h.call, &h.credential)
            .await
            .unwrap()
            .status,
        "committed"
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    drop(child);
    let mut child = start();
    ready(&h, &mut child, &h.call.attempt_id).await;
    assert_eq!(
        h.query().query(&h.call.attempt_id).await.unwrap().status,
        "committed"
    );
    assert_eq!(
        h.adapter()
            .dispatch(&h.call, &h.credential)
            .await
            .unwrap()
            .status,
        "committed"
    );
    assert_eq!(h.state().await, (2, "booking-native".into()));
}

#[path = "support/postgres_enrollment.rs"]
mod postgres_enrollment;

#[cfg(unix)]
#[path = "support/target_custody.rs"]
mod target_custody;
