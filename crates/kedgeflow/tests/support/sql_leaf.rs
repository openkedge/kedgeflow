//! Fresh signed control -> official SDK -> native broker -> SQL -> M4 query.
//! Generated identity and evidence are software fixtures, not enterprise acceptance.
use super::*;
#[path = "exchange_identity.rs"]
mod exchange;
use async_trait::async_trait;
use axum::{Router, routing::post};
use kedgeflow::{
    broker::{Rfc8693Broker, WorkloadAssertion},
    broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangePermit},
    broker_service::BrokerService,
    clock::{Clock, SystemClock},
    control::{ControlPermissions, ControlService},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    gateway::Gateway,
    postgres_action::{DispatchRequest, Outcome},
    postgres_adapter::PostgresAdapter,
    postgres_store::{PostgresStore, ReservationStore, UnixDatabase},
    postgres_target::{Registration, TargetService},
    recovery::{Candidate, RecoveryWorker},
    recovery_config::HttpOutcomeQuerier,
    target_token::{ReferenceTokenMinter, TargetTokenMinter, TargetTokenVerifier},
    tls,
};
use live_agent::{ClockedAuth, Provider, Running, Target};
use std::sync::atomic::AtomicUsize;
use tokio::sync::Mutex;
const QUERY_TOKEN: &str = "generated-sql-flow-query-only-000000000000000000000";
struct Assertion(String);
#[async_trait]
impl WorkloadAssertion for Assertion {
    async fn assertion(&self, workload: &str) -> Result<String> {
        assert_eq!(workload, "spiffe://test/agent");
        Ok(self.0.clone())
    }
}
struct Minter(ReferenceTokenMinter, AtomicUsize);
#[async_trait]
impl TargetTokenMinter for Minter {
    async fn mint(&self, permit: &ExchangePermit, now: i64) -> Result<String> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.mint(permit, now).await
    }
}
struct Store {
    real: PostgresStore,
    calls: AtomicUsize,
    lost_reply: bool,
}
#[async_trait]
impl ReservationStore for Store {
    async fn apply(&self, request: &DispatchRequest) -> Result<Outcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.real.apply(request).await?;
        if self.lost_reply {
            return Err(Error::Unknown("discarded reply after real COMMIT".into()));
        }
        Ok(result)
    }
    async fn lookup(&self, tenant: &str, attempt: &str) -> Result<Option<Outcome>> {
        self.real.lookup(tenant, attempt).await
    }
}
async fn owner(database: &UnixDatabase) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::Config::new()
        .host_path(&database.socket_directory)
        .port(database.port)
        .dbname(&database.database)
        .user(std::env::var("KF_POSTGRES_TEST_USER").unwrap())
        .connect(tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    client
}
async fn run(lost_reply: bool) {
    let socket = match std::env::var("KF_POSTGRES_TEST_SOCKET") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_POSTGRES").as_deref(), Ok("1"));
            eprintln!("SKIP SQL flow: PostgreSQL fixture absent");
            return;
        }
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !root
        .join("tests/sdk/node_modules/@modelcontextprotocol/client/package.json")
        .is_file()
    {
        assert_ne!(std::env::var("KF_REQUIRE_SDK").as_deref(), Ok("1"));
        eprintln!("SKIP SQL flow: SDK absent");
        return;
    }
    let now = SystemClock.now_ms();
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("https://{}/mcp", gateway_listener.local_addr().unwrap());
    let Some(h) = Harness::with_setup(Some(&gateway_url), now, |f| {
        f.sql();
        let resource = format!("sql-flow-{:x}", rand::random::<u64>());
        f.proposal["resources"][0]["id"] = json!(resource);
        f.proposal["parameters"]["resource_id"] = json!(resource);
        f.proposal["baseline_state"][0]["resource"]["id"] = json!(resource);
        f.evidence["state_scope"][0]["id"] = json!(resource);
        f.descriptor["adapter_contract"]["guard_scope"] = json!([resource]);
        f.descriptor["concurrency"]["predicate_descriptor"]["clauses"][0]["resource"]["id"] =
            json!(resource);
        f.repin_descriptor();
    })
    .await
    else {
        return;
    };
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let database = UnixDatabase {
        socket_directory: socket.into(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    };
    let db = owner(&database).await;
    let resource = &h.registration.scope.resource;
    db.execute("INSERT INTO kf_reservation.resource(tenant,conflict_domain,resource_id,incarnation,version,last_fence,reservation,active) VALUES($1,$2,$3,$4,241,0,'unreserved',true)",
        &[&h.f.trust.tenant,&h.registration.scope.conflict_domain,&resource.id,&resource.incarnation]).await.unwrap();
    let leaf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", leaf_listener.local_addr().unwrap());
    let admit = format!("{origin}/admit");
    let issue = format!("{origin}/issue");
    let status = format!("{origin}/status");
    let evidence_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evidence_url = format!(
        "https://{}/evidence",
        evidence_listener.local_addr().unwrap()
    );
    let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_url = format!("https://{}/exchange", broker_listener.local_addr().unwrap());
    let sql_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sql_origin = format!("https://{}", sql_listener.local_addr().unwrap());
    let sql_url = format!("{sql_origin}/dispatch");
    let query_url = format!("{sql_origin}/query");
    let auth = |url: &str| {
        DualAuthenticator::new(
            &h.f.identity.subject.iss,
            AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    };
    let grants = GrantVerifier {
        keys: keys(5),
        audience: gateway_url.clone(),
    };
    let service = Arc::new(
        ControlService::new(
            Arc::new(h.f.trust.clone()),
            AdmissionController::new(
                CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
                "key-6".into(),
                SigningKey::from_bytes(&[6; 32]),
            )
            .unwrap(),
            GrantAuthority::new(
                IssuanceVerifier {
                    tenant: h.f.trust.tenant.clone(),
                    admission_keys: keys(6),
                    grants: grants.clone(),
                },
                "key-5".into(),
                SigningKey::from_bytes(&[5; 32]),
            )
            .unwrap(),
            h.ledger.clone(),
            h.clock.clone(),
            auth(&admit),
            auth(&issue),
            ControlPermissions {
                subjects: vec![h.f.identity.subject.clone()],
                admission_scope: "kf.admit".into(),
                issuance_scope: "kf.issue".into(),
            },
        )
        .unwrap()
        .with_status(auth(&status), "kf.status".into())
        .unwrap(),
    );
    let mut tool = h.tool();
    tool.name = "postgres_reserve".into();
    tool.admission_endpoint = admit.clone();
    let registration = Registration {
        tenant: h.f.trust.tenant.clone(),
        conflict_domain: tool.conflict_domain.clone(),
        action: tool.action.clone().unwrap(),
        resource: resource.clone(),
        adapter_contract: tool.adapter_contract.clone(),
        predicate_id: tool.predicate_id.clone(),
        predicate_version: tool.predicate_version.clone(),
        gateway_workload: "spiffe://test/gateway".into(),
        query_workload: "spiffe://test/recovery".into(),
        target_audience: sql_url.clone(),
        target_scope: "reservation:write".into(),
    };
    let mut identity = exchange::Fixture::new();
    identity.snapshot.issuer = h.f.identity.subject.iss.clone();
    identity.snapshot.subject_audience = AUD.into();
    identity.snapshot.actor_audience = broker_url.clone();
    identity.snapshot.not_before = now;
    identity.snapshot.expires_at = now + 120000;
    identity.snapshot.subject_keys[0].kid = "key-7".into();
    identity.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    identity.snapshot.subject_keys[0].not_before = now;
    identity.snapshot.subject_keys[0].expires_at = now + 120000;
    identity.snapshot.actor_keys[0].not_before = now;
    identity.snapshot.actor_keys[0].expires_at = now + 120000;
    identity.snapshot.registrations[0].subject = h.f.identity.subject.clone();
    let scopes = "capacity.reserve kf.admit kf.issue kf.status kf.evidence";
    identity.snapshot.registrations[0].allowed_scopes =
        scopes.split_whitespace().map(String::from).collect();
    let actor = identity.actor_token(
        json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),
        json!({"sub":"spiffe://test/agent","aud":broker_url,"exp":now/1000+60,"iat":now/1000}),
    );
    let minter = Arc::new(Minter(
        ReferenceTokenMinter::new(
            broker_url.clone(),
            "key-29".into(),
            SigningKey::from_bytes(&[29; 32]),
        )
        .unwrap(),
        AtomicUsize::new(0),
    ));
    let tokens = || TargetTokenVerifier::new(broker_url.clone(), keys(29)).unwrap();
    let broker_service = Arc::new(
        BrokerService::new(
            BrokerAuthorizer::new(
                BrokerRegistration {
                    gateway_workload: registration.gateway_workload.clone(),
                    target_audience: sql_url.clone(),
                    target_scope: registration.target_scope.clone(),
                    max_lifetime_ms: 3000,
                    tool: tool.clone(),
                },
                grants.clone(),
                h.ledger.clone(),
                Arc::new(identity.provider()),
                h.clock.clone(),
            )
            .unwrap(),
            &broker_url,
            minter.clone(),
            tokens(),
            h.clock.clone(),
        )
        .unwrap(),
    );
    let sql_pki = support::pki_for_workloads(&[
        "spiffe://test/gateway",
        "spiffe://test/recovery",
        "spiffe://test/agent",
    ]);
    let pinned = |index: usize| {
        tls::pinned_client_pem(
            sql_pki[index].ca.as_bytes(),
            sql_pki[index].client.as_bytes(),
            sql_pki[index].client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    };
    let store = Arc::new(Store {
        real: PostgresStore::new(database).unwrap(),
        calls: AtomicUsize::new(0),
        lost_reply,
    });
    let target = Arc::new(
        TargetService::new(
            registration.clone(),
            grants.clone(),
            tokens(),
            store.clone(),
            h.clock.clone(),
            &sql_url,
            &query_url,
            QUERY_TOKEN,
        )
        .unwrap(),
    );
    let broker = Rfc8693Broker::new(
        &broker_url,
        sql_url.clone(),
        registration.target_scope.clone(),
        pinned(0),
        Arc::new(Assertion(actor)),
        h.clock.clone(),
        Duration::from_secs(5),
    )
    .unwrap();
    let adapter = PostgresAdapter::new(
        &sql_url,
        pinned(0),
        registration,
        grants.clone(),
        tokens(),
        h.clock.clone(),
    )
    .unwrap();
    let gateway = Arc::new(Gateway {
        verifier: grants.clone(),
        ledger: Arc::new(h.ledger.clone()),
        auth: Arc::new(ClockedAuth(auth(&gateway_url), h.clock.clone())),
        broker: Arc::new(broker),
        adapter: Arc::new(adapter),
        resolver: None,
        tools: BTreeMap::from([(tool.name.clone(), tool.clone())]),
        timeout: Duration::from_secs(5),
        clock: h.clock.clone(),
    });
    gateway.validate().unwrap();
    // This evidence source is a fixed signed software fixture. The target's real
    // SQL checks, not this provider's capacity labels, guard the actual update.
    let provider = Arc::new(Provider {
        auth: auth(&evidence_url),
        clock: h.clock.clone(),
        evidence: h.f.evidence.clone(),
        policy: h.f.trust.policy.clone(),
        descriptor_digest: h.f.trust.descriptor_digest.clone(),
        calls: AtomicUsize::new(0),
        baseline_calls: AtomicUsize::new(0),
        target: Arc::new(Target {
            calls: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            state: Mutex::new((241, 0, 3)),
        }),
        resource: resource.clone(),
    });
    let tls = |p: &support::Pki| {
        kedgeflow::tls::server_config_pem(
            p.server.as_bytes(),
            p.server_key.as_bytes(),
            p.ca.as_bytes(),
        )
        .unwrap()
    };
    let leaf_tls = tls(&h.agent_pki);
    let gateway_tls = leaf_tls.clone();
    let provider_tls = leaf_tls.clone();
    let sql_tls = tls(&sql_pki[0]);
    let broker_tls = sql_tls.clone();
    let endpoint = EndpointPolicy::new(&gateway_url).unwrap();
    let _gateway = Running(tokio::spawn(async move {
        kedgeflow::server::serve(gateway_listener, gateway_tls, gateway, endpoint)
            .await
            .unwrap();
    }));
    let _leaf = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(leaf_listener, leaf_tls, service.router())
            .await
            .unwrap();
    }));
    let provider_router = Router::new()
        .route("/evidence", post(live_agent::evidence))
        .with_state(provider.clone());
    let _provider = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(evidence_listener, provider_tls, provider_router)
            .await
            .unwrap();
    }));
    let _sql = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(sql_listener, sql_tls, target.router())
            .await
            .unwrap();
    }));
    let _broker = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(broker_listener, broker_tls, broker_service.router())
            .await
            .unwrap();
    }));
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("agent.json");
    let operations = directory.path().join("operations");
    let public = |n| json!({format!("key-{n}"):URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
    let token = |scopes: &str, time: i64| {
        jwt(
            json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
            json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":time/1000+60,"iat":time/1000,"scope":scopes,"cnf":{"jkt":jkt}}),
            7,
        )
    };
    let mut config = json!({"mode":"normal","now":now,"expectedState":if lost_reply {"unknown"} else {"committed"},"token":token(scopes,now),"storeDirectory":operations,"evidenceUrl":evidence_url,"tls":{"ca":h.agent_pki.ca,"cert":h.agent_pki.client,"key":h.agent_pki.client_key},"proposalTemplate":h.f.proposal,
        "config":{"gatewayUrl":gateway_url,"admissionUrl":admit,"issuanceUrl":issue,"statusUrl":status,"delegationAudience":AUD,"workloadId":"spiffe://test/agent","subject":h.f.identity.subject,"tenant":h.f.trust.tenant,"toolName":tool.name,"descriptor":String::from_utf8(fixture::signed("ctd",h.f.descriptor.clone(),2)).unwrap(),"descriptorDigest":h.f.trust.descriptor_digest,"registryKeys":public(2),"proposalKeys":public(1),"manifestKeys":public(3),"evidenceKeys":public(4),"admissionKeys":public(6),"issuerKeys":public(5),"proposalKeyId":"key-1","authorizationKey":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes())}});
    let run_node = || async {
        let output = tokio::time::timeout(
            Duration::from_secs(25),
            tokio::process::Command::new("node")
                .arg(root.join("tests/sdk/live-agent.mjs"))
                .arg(&file)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let first = run_node().await;
    let retained: Value = serde_json::from_slice(
        &std::fs::read(operations.join(format!(
            "{}.json",
            hex::encode(Sha256::digest(b"sdk:live-operation"))
        )))
        .unwrap(),
    )
    .unwrap();
    let issued = grants
        .verify(retained["grant"].as_str().unwrap().as_bytes(), now)
        .unwrap();
    let candidate = Candidate {
        grant: issued.grant,
        attempt_id: first["attempt_id"].as_str().unwrap().into(),
    };
    let query = HttpOutcomeQuerier::new(pinned(1).client().clone(), &query_url, QUERY_TOKEN.into())
        .unwrap();
    let recovery = RecoveryWorker::new(
        h.ledger.clone(),
        grants.clone(),
        Arc::new(query),
        "key-30".into(),
        SigningKey::from_bytes(&[30; 32]),
        "sql-query".into(),
        h.clock.clone(),
    )
    .unwrap();
    if lost_reply {
        assert_eq!(
            recovery.recover(&candidate).await.unwrap().state,
            "committed"
        );
    }
    let outcome = store
        .real
        .lookup(&h.f.trust.tenant, &candidate.attempt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.request.grant_digest, issued.digest);
    assert_eq!(outcome.request.root_id, candidate.grant.root_id);
    assert_eq!(outcome.request.fence, candidate.grant.fence);
    let row = db.query_one("SELECT version,last_fence,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.f.trust.tenant,&resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 242);
    assert_eq!(row.get::<_, i64>(1), candidate.grant.fence as i64);
    assert_eq!(row.get::<_, String>(2), "booking:pilot");
    h.revoke(RevocationTarget::Domain).await;
    h.clock.0.store(now + 61000, Ordering::SeqCst);
    config["mode"] = json!("resume");
    config["expectedState"] = json!("committed");
    config["now"] = json!(now + 61000);
    config["token"] = json!(token("kf.status", now + 61000));
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let resumed = run_node().await;
    assert_eq!(resumed["attempt_id"], first["attempt_id"]);
    assert_eq!(resumed["grant_digest"], first["grant_digest"]);
    assert_eq!(minter.1.load(Ordering::SeqCst), 1);
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.baseline_calls.load(Ordering::SeqCst), 1);
    println!(
        "SQL fresh leaf PASS: lost_target_reply={lost_reply}, one issuer root/fence, one native broker mint, one SQL commit, same attempt after revoked/expired Node restart"
    );
}
#[tokio::test]
async fn fresh_official_sdk_sql_leaf_commits_through_native_broker() {
    run(false).await;
}
#[tokio::test]
async fn lost_sql_target_reply_recovers_original_attempt_without_remint_or_redispatch() {
    run(true).await;
}
