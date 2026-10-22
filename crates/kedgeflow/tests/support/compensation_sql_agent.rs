//! Official SDK inverse composition with actual SQL and original query-only restart.
use super::*;
use crate::live_agent::{ClockedAuth, Running};
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use kedgeflow::{
    auth::WorkloadIdentity,
    broker::{Rfc8693Broker, WorkloadAssertion},
    broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangePermit},
    broker_service::BrokerService,
    clock::Clock,
    control::{ControlPermissions, ControlService},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    gateway::Gateway,
    postgres_compensation::CompensationStore,
    recovery::RecoveryWorker,
    target_token::{ReferenceTokenMinter, TargetTokenMinter, TargetTokenVerifier},
};
struct Actor(String);
#[async_trait::async_trait]
impl WorkloadAssertion for Actor {
    async fn assertion(&self, workload: &str) -> Result<String> {
        if workload != "spiffe://test/agent" {
            return Err(Error::Refused("actor scope".into()));
        }
        Ok(self.0.clone())
    }
}
struct Minter(ReferenceTokenMinter, AtomicUsize);
#[async_trait::async_trait]
impl TargetTokenMinter for Minter {
    async fn mint(&self, p: &ExchangePermit, now: i64) -> Result<String> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.mint(p, now).await
    }
}
struct EvidenceSource {
    auth: DualAuthenticator,
    clock: Arc<crate::TestClock>,
    connection: tokio_postgres::Client,
    template: Value,
    contract: Contract,
    policy: kedgeflow::contracts::Policy,
    descriptor_digest: String,
    calls: AtomicUsize,
    baselines: AtomicUsize,
    tenant: String,
}
async fn evidence(
    State(s): State<Arc<EvidenceSource>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let identity = s
        .auth
        .authenticate_at(&headers, &workload, s.clock.now_ms() / 1000)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if workload.as_str() != "spiffe://test/agent" || !identity.scopes.contains("kf.evidence") {
        return Err(StatusCode::FORBIDDEN);
    }
    let row=s.connection.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&s.tenant,&s.contract.inverse_scope.resource.id]).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
    let version: u64 = row
        .get::<_, i64>(0)
        .try_into()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let value: String = row.get(1);
    let state_digest = digest(
        "postgres-restore-state",
        &json!({"resource":s.contract.inverse_scope.resource,"reservation":value}),
    )
    .unwrap();
    if body["operation"] == "baseline" {
        let args: Parameters = serde_json::from_value(body["parameters"].clone())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if args.resource_id != s.contract.inverse_scope.resource.id
            || args.expected_version != version
            || args.restore_state_digest != s.contract.restore_state_digest
        {
            return Err(StatusCode::FORBIDDEN);
        }
        s.baselines.fetch_add(1, Ordering::SeqCst);
        return Ok(Json(
            json!({"resource":s.contract.inverse_scope.resource,"version":version.to_string(),"observed_at":s.clock.now_ms(),"expires_at":s.clock.now_ms()+60000,"state_digest":state_digest}),
        ));
    }
    let raw = body["proposal"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let proposal = kedgeflow::schema::verify_record(raw.as_bytes(), "proposal", &keys(1))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let pd = record_digest(&proposal).unwrap();
    if body["proposal_digest"] != pd
        || proposal.payload["action"]["digest"] != s.descriptor_digest
        || proposal.payload["parameters"]["expected_version"] != version
        || proposal.payload["subject"] != json!(identity.subject)
        || proposal.payload["baseline_state"][0]["state_digest"] != state_digest
    {
        return Err(StatusCode::FORBIDDEN);
    }
    s.calls.fetch_add(1, Ordering::SeqCst);
    let mut e = s.template.clone();
    e["proposal_digest"] = json!(pd);
    e["state_digest"] = json!(state_digest);
    e["observed_at"] = json!(s.clock.now_ms());
    e["expires_at"] = json!(s.clock.now_ms() + 30000);
    e["result"]["version"] = json!(version.to_string());
    let signed = String::from_utf8(fixture::signed("evidence", e.clone(), 4)).unwrap();
    let reference = json!({"id":e["wid"],"schema":"https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Evidence","digest":fixture::record_hash(signed.as_bytes())});
    let manifest = json!({"mid":"inverse-agent-manifest","proposal_digest":pd,"policy":s.policy,"witnesses":[{"witness":reference,"obligation_id":"capacity","execution_relevant":true,"expires_at":e["expires_at"]}],"assembled_at":s.clock.now_ms()});
    Ok(Json(
        json!({"manifest":String::from_utf8(fixture::signed("manifest",manifest,3)).unwrap(),"witnesses":[signed]}),
    ))
}
pub(super) struct Links {
    gateway_listener: tokio::net::TcpListener,
    leaf: tokio::net::TcpListener,
    evidence_listener: tokio::net::TcpListener,
    target_listener: tokio::net::TcpListener,
    broker_listener: tokio::net::TcpListener,
}
impl Links {
    pub(super) async fn new() -> Self {
        async fn bind() -> tokio::net::TcpListener {
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()
        }
        Self {
            gateway_listener: bind().await,
            leaf: bind().await,
            evidence_listener: bind().await,
            target_listener: bind().await,
            broker_listener: bind().await,
        }
    }
    pub(super) fn gateway_url(&self) -> String {
        format!(
            "https://{}/mcp",
            self.gateway_listener.local_addr().unwrap()
        )
    }
    pub(super) fn admit_url(&self) -> String {
        format!("https://{}/admit", self.leaf.local_addr().unwrap())
    }
    pub(super) fn dispatch_url(&self) -> String {
        format!(
            "https://{}/dispatch",
            self.target_listener.local_addr().unwrap()
        )
    }
}
pub(super) struct Serving {
    pub(super) config: Value,
    pub(super) query: Arc<dyn kedgeflow::ledger::OutcomeQuerier>,
    directory: tempfile::TempDir,
    minter: Arc<Minter>,
    source: Arc<EvidenceSource>,
    lost_store: Arc<LostSqlInverse>,
    _servers: Vec<Running>,
}
impl Serving {
    pub(super) fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.minter.1.load(Ordering::SeqCst),
            self.source.calls.load(Ordering::SeqCst),
            self.source.baselines.load(Ordering::SeqCst),
            self.lost_store.calls.load(Ordering::SeqCst),
        )
    }
}
pub(super) async fn serve(h: &SqlInverseReady, links: Links, lost: bool) -> Serving {
    let gateway_url = links.gateway_url();
    let Links {
        gateway_listener,
        leaf,
        evidence_listener,
        target_listener,
        broker_listener,
    } = links;
    let origin = format!("https://{}", leaf.local_addr().unwrap());
    let admit = format!("{origin}/admit");
    let issue_url = format!("{origin}/issue");
    let status_url = format!("{origin}/status");
    let evidence_url = format!(
        "https://{}/evidence",
        evidence_listener.local_addr().unwrap()
    );
    let origin = format!("https://{}", target_listener.local_addr().unwrap());
    let dispatch = format!("{origin}/dispatch");
    let query = format!("{origin}/query");
    let barrier = format!("{origin}/barrier");
    assert_eq!(h.pin.target_audience, dispatch);
    let broker_url = format!("https://{}/exchange", broker_listener.local_addr().unwrap());
    let auth = |url: &str| {
        DualAuthenticator::new(
            &h.inverse.f.identity.subject.iss,
            crate::AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    };
    let issuer = GrantAuthority::new(
        IssuanceVerifier {
            tenant: h.inverse.f.trust.tenant.clone(),
            admission_keys: keys(6),
            grants: h.grants(),
        },
        "key-5".into(),
        SigningKey::from_bytes(&[5; 32]),
    )
    .unwrap();
    let service = Arc::new(
        ControlService::new(
            Arc::new(h.inverse.f.trust.clone()),
            AdmissionController::new(
                CedarAdmissionPolicy::new(
                    h.inverse.definition.clone(),
                    h.inverse.f.trust.policy.clone(),
                )
                .unwrap(),
                "key-6".into(),
                SigningKey::from_bytes(&[6; 32]),
            )
            .unwrap(),
            issuer,
            h.inverse.ledger.clone(),
            h.inverse.clock.clone(),
            auth(&admit),
            auth(&issue_url),
            ControlPermissions {
                subjects: vec![h.inverse.f.identity.subject.clone()],
                admission_scope: "kf.admit".into(),
                issuance_scope: "kf.issue".into(),
            },
        )
        .unwrap()
        .with_status(auth(&status_url), "kf.status".into())
        .unwrap(),
    );
    let mut tool = h.inverse.tool();
    tool.admission_endpoint = admit.clone();
    let mut identities = crate::exchange::Fixture::new();
    identities.snapshot.issuer = h.inverse.f.identity.subject.iss.clone();
    identities.snapshot.subject_audience = crate::AUD.into();
    identities.snapshot.actor_audience = broker_url.clone();
    identities.snapshot.subject_keys[0].kid = "key-7".into();
    identities.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    identities.snapshot.registrations[0].subject = h.inverse.f.identity.subject.clone();
    let scopes = "capacity.reserve kf.admit kf.issue kf.status kf.evidence";
    identities.snapshot.registrations[0].allowed_scopes =
        scopes.split_whitespace().map(str::to_owned).collect();
    let actor = identities.actor_token(
        json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),
        json!({"sub":"spiffe://test/agent","aud":broker_url,"iat":NOW/1000,"exp":NOW/1000+60}),
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
    let broker = Arc::new(
        BrokerService::new(
            BrokerAuthorizer::new(
                BrokerRegistration {
                    gateway_workload: h.pin.gateway_workload.clone(),
                    target_audience: dispatch.clone(),
                    target_scope: h.pin.target_scope.clone(),
                    max_lifetime_ms: 3000,
                    tool: tool.clone(),
                },
                h.grants(),
                h.inverse.ledger.clone(),
                Arc::new(identities.provider()),
                h.inverse.clock.clone(),
            )
            .unwrap(),
            &broker_url,
            minter.clone(),
            tokens(),
            h.inverse.clock.clone(),
        )
        .unwrap(),
    );
    let pki = support::pki_for_workloads(&[
        "spiffe://test/gateway",
        "spiffe://test/recovery",
        "spiffe://test/barrier",
    ]);
    let client = |n: usize| {
        kedgeflow::tls::pinned_client_pem(
            pki[n].ca.as_bytes(),
            pki[n].client.as_bytes(),
            pki[n].client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    };
    let lost_store = Arc::new(LostSqlInverse {
        real: h.store.clone(),
        calls: AtomicUsize::new(0),
        queries: AtomicUsize::new(0),
    });
    let store: Arc<dyn CompensationStore> = if lost {
        lost_store.clone()
    } else {
        h.store.clone()
    };
    let target = Arc::new(
        kedgeflow::compensation_target_http::Service::new(
            h.target_trust(),
            h.grants(),
            tokens(),
            store,
            h.inverse.clock.clone(),
            [&dispatch, &query, &barrier],
            INVERSE_QUERY_TOKEN,
            INVERSE_BARRIER_TOKEN,
            "spiffe://test/barrier".into(),
            "key-17".into(),
            SigningKey::from_bytes(&[17; 32]),
            20000,
        )
        .unwrap(),
    );
    let adapter = kedgeflow::compensation_adapter::CompensationAdapter::new(
        &dispatch,
        client(0),
        h.target_trust(),
        h.grants(),
        tokens(),
        h.inverse.ledger.clone(),
        h.inverse.clock.clone(),
    )
    .unwrap();
    let gateway = Arc::new(Gateway {
        verifier: h.grants(),
        ledger: Arc::new(h.inverse.ledger.clone()),
        auth: Arc::new(ClockedAuth(auth(&gateway_url), h.inverse.clock.clone())),
        broker: Arc::new(
            Rfc8693Broker::new(
                &broker_url,
                dispatch.clone(),
                h.pin.target_scope.clone(),
                client(0),
                Arc::new(Actor(actor)),
                h.inverse.clock.clone(),
                Duration::from_secs(5),
            )
            .unwrap(),
        ),
        adapter: Arc::new(adapter),
        resolver: None,
        tools: BTreeMap::from([(tool.name.clone(), tool.clone())]),
        timeout: Duration::from_secs(5),
        clock: h.inverse.clock.clone(),
    });
    gateway.validate().unwrap();
    let connection = crate::sql_leaf::owner(&kedgeflow::postgres_store::UnixDatabase {
        socket_directory: std::env::var("KF_POSTGRES_TEST_SOCKET").unwrap().into(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    })
    .await;
    let source = Arc::new(EvidenceSource {
        auth: auth(&evidence_url),
        clock: h.inverse.clock.clone(),
        connection,
        template: h.inverse.f.evidence.clone(),
        contract: h.contract.clone(),
        policy: h.inverse.f.trust.policy.clone(),
        descriptor_digest: h.inverse.f.trust.descriptor_digest.clone(),
        calls: AtomicUsize::new(0),
        baselines: AtomicUsize::new(0),
        tenant: h.pin.tenant.clone(),
    });
    let tls = |p: &support::Pki| {
        kedgeflow::tls::server_config_pem(
            p.server.as_bytes(),
            p.server_key.as_bytes(),
            p.ca.as_bytes(),
        )
        .unwrap()
    };
    let leaf_tls = tls(&h.inverse.agent_pki);
    let gateway_tls = leaf_tls.clone();
    let provider_tls = leaf_tls.clone();
    let target_tls = tls(&pki[0]);
    let broker_tls = target_tls.clone();
    let endpoint = EndpointPolicy::new(&gateway_url).unwrap();
    let _gateway = Running(tokio::spawn(async move {
        kedgeflow::server::serve(gateway_listener, gateway_tls, gateway, endpoint)
            .await
            .unwrap();
    }));
    let _control = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(leaf, leaf_tls, service.router())
            .await
            .unwrap();
    }));
    let _target = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(target_listener, target_tls, target.router())
            .await
            .unwrap();
    }));
    let _broker = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(broker_listener, broker_tls, broker.router())
            .await
            .unwrap();
    }));
    let provider = source.clone();
    let _evidence = Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(
            evidence_listener,
            provider_tls,
            Router::new()
                .route("/evidence", post(evidence))
                .with_state(provider),
        )
        .await
        .unwrap();
    }));
    let public = |n| json!({format!("key-{n}"):URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.inverse.jwk).unwrap()));
    let token = |scope: &str, now: i64| {
        crate::jwt(
            json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
            json!({"iss":h.inverse.f.identity.subject.iss,"sub":h.inverse.f.identity.subject.sub,"aud":crate::AUD,"exp":now/1000+60,"iat":now/1000,"scope":scope,"cnf":{"jkt":jkt}}),
            7,
        )
    };
    let directory = tempfile::tempdir().unwrap();
    let original = h.qualifier.history().await.unwrap()[0]
        .proof
        .parameters
        .clone();
    let cfg = json!({"qid":h.inverse.f.proposal["qid"],"mode":"normal","now":h.inverse.clock.now_ms(),"token":token(scopes,h.inverse.clock.now_ms()),"expectedState":if lost{"unknown"}else{"committed"},"storeDirectory":directory.path().join("operations"),"evidenceUrl":evidence_url,"tls":{"ca":h.inverse.agent_pki.ca,"cert":h.inverse.agent_pki.client,"key":h.inverse.agent_pki.client_key},"proposalTemplate":h.inverse.f.proposal,
        "config":{"gatewayUrl":gateway_url,"admissionUrl":admit,"issuanceUrl":issue_url,"statusUrl":status_url,"delegationAudience":crate::AUD,"workloadId":"spiffe://test/agent","subject":h.inverse.f.identity.subject,"tenant":h.pin.tenant,"toolName":tool.name,"descriptor":String::from_utf8(fixture::signed("ctd",h.inverse.f.descriptor.clone(),2)).unwrap(),"descriptorDigest":h.inverse.f.trust.descriptor_digest,"registryKeys":public(2),"proposalKeys":public(1),"manifestKeys":public(3),"evidenceKeys":public(4),"admissionKeys":public(6),"issuerKeys":public(5),"proposalKeyId":"key-1","authorizationKey":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),"compensation":{"profile":kedgeflow::compensation_execution::PROFILE,"contractDigest":h.contract.digest().unwrap(),"parameters":original}}});

    let query = Arc::new(
        kedgeflow::recovery_config::HttpOutcomeQuerier::new(
            client(1).client().clone(),
            &query,
            INVERSE_QUERY_TOKEN.into(),
        )
        .unwrap(),
    );
    Serving {
        config: cfg,
        query,
        directory,
        minter,
        source,
        lost_store,
        _servers: vec![_gateway, _control, _target, _broker, _evidence],
    }
}
pub(super) fn token(h: &SqlInverseReady, scope: &str, now: i64) -> String {
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.inverse.jwk).unwrap()));
    crate::jwt(
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
        json!({"iss":h.inverse.f.identity.subject.iss,"sub":h.inverse.f.identity.subject.sub,"aud":crate::AUD,"exp":now/1000+60,"iat":now/1000,"scope":scope,"cnf":{"jkt":jkt}}),
        7,
    )
}

async fn run(lost: bool) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !root
        .join("tests/sdk/node_modules/@modelcontextprotocol/client/package.json")
        .is_file()
    {
        assert_ne!(std::env::var("KF_REQUIRE_SDK").as_deref(), Ok("1"));
        eprintln!("SKIP inverse SDK: official pinned client absent");
        return;
    }
    let links = Links::new().await;
    let Some(mut h) = Box::pin(sql_inverse_setup(NOW, Some(&links.gateway_url()))).await else {
        return;
    };
    h.pin.target_audience = links.dispatch_url();
    let serving = Box::pin(serve(&h, links, lost)).await;
    let mut cfg = serving.config.clone();
    let file = serving.directory.path().join("inverse-agent.json");
    let node = || {
        let file = file.clone();
        let root = root.clone();
        async move {
            let out = tokio::time::timeout(
                Duration::from_secs(30),
                tokio::process::Command::new(
                    std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into()),
                )
                .arg(root.join("tests/sdk/live-agent.mjs"))
                .arg(file)
                .kill_on_drop(true)
                .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let result: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(result["status"], "PASS");
            println!("{}", String::from_utf8_lossy(&out.stdout));
            result
        }
    };
    std::fs::write(&file, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let first = node().await;
    let attempt = first["attempt_id"].as_str().unwrap();
    let op = &h.contract.inverse_operation_key;
    let rec: kedgeflow::ledger::IssuanceRecord = serde_json::from_slice(
        &h.inverse
            .ledger
            .read_key(&format!("{}/issuance/{op}", h.inverse.prefix))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let candidate = kedgeflow::recovery::Candidate {
        grant: native::grant(&h.inverse, &rec),
        attempt_id: attempt.into(),
    };
    let query_client = serving.query.clone();
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    h.forward.ledger.stop_reservation().await.unwrap();
    let worker = RecoveryWorker::new(
        h.inverse.ledger.clone(),
        h.grants(),
        query_client,
        "key-19".into(),
        SigningKey::from_bytes(&[19; 32]),
        "spiffe://test/inverse-outcome".into(),
        h.inverse.clock.clone(),
    )
    .unwrap();
    worker.recover(&candidate).await.unwrap();
    assert_eq!(
        h.inverse.ledger.compensation_spend().await.unwrap().state,
        kedgeflow::coordination::ReservationState::Committed
    );
    cfg["mode"] = json!("resume");
    cfg["now"] = json!(NOW + 12000);
    cfg["token"] = json!(token(&h, "kf.status", NOW + 12000));
    cfg["expectedState"] = json!("committed");
    std::fs::write(&file, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let again = node().await;
    assert_eq!(again["attempt_id"], first["attempt_id"]);
    assert_eq!(again["grant_digest"], first["grant_digest"]);
    assert_eq!(serving.minter.1.load(Ordering::SeqCst), 1);
    assert_eq!(serving.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(serving.source.baselines.load(Ordering::SeqCst), 1);
    if lost {
        assert_eq!(serving.lost_store.calls.load(Ordering::SeqCst), 1);
    }
    let row=h.admin.query_one("SELECT version,last_fence,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 243);
    assert_eq!(row.get::<_, i64>(1), 2);
    assert_eq!(row.get::<_, String>(2), "free");
}
#[tokio::test]
async fn compensation_sql_official_sdk_fresh_inverse_actual_restore_and_query_only_restart() {
    Box::pin(run(false)).await;
}
#[tokio::test]
async fn compensation_sql_official_sdk_lost_target_reply_refines_original_commit_without_remint_or_resend()
 {
    Box::pin(run(true)).await;
}
