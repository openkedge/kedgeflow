//! Real SQL original effects, barrier/evaluator and inverse target composition.
use super::*;

fn sql_execution_fixture(f: &mut Fixture, resource: &str, inverse: bool) {
    f.sql();
    f.proposal["resources"][0]["id"] = json!(resource);
    f.proposal["parameters"]["resource_id"] = json!(resource);
    f.proposal["baseline_state"][0]["resource"]["id"] = json!(resource);
    f.proposal["baseline_state"][0]["state_digest"] = json!(
        digest(
            "postgres-restore-state",
            &json!({"resource":f.proposal["resources"][0],"reservation":if inverse { "booking:pilot" } else { "free" }})
        )
        .unwrap()
    );
    f.evidence["state_scope"][0]["id"] = json!(resource);
    f.descriptor["adapter_contract"]["guard_scope"] = json!([resource]);
    f.descriptor["concurrency"]["predicate_descriptor"]["clauses"][0]["resource"]["id"] =
        json!(resource);
    if inverse {
        execution_fixture(f);
    }
    f.evidence["state_digest"] = f.proposal["baseline_state"][0]["state_digest"].clone();
    f.repin_descriptor();
}
struct SqlForwardQuery(Arc<kedgeflow::postgres_store::PostgresStore>);
#[async_trait::async_trait]
impl kedgeflow::ledger::OutcomeQuerier for SqlForwardQuery {
    async fn query(
        &self,
        attempt: &str,
    ) -> kedgeflow::error::Result<kedgeflow::ledger::AuthoritativeObservation> {
        use kedgeflow::postgres_store::ReservationStore;
        let o = self
            .0
            .lookup("tenant-42", attempt)
            .await?
            .ok_or_else(|| kedgeflow::error::Error::Unknown("no original SQL result".into()))?;
        Ok(kedgeflow::ledger::AuthoritativeObservation {
            attempt_id: o.request.attempt_id,
            root_id: o.request.root_id,
            grant_digest: o.request.grant_digest,
            target_reference: "postgres/original".into(),
            status: match o.status {
                kedgeflow::postgres_action::Status::Committed => "committed",
                _ => "fenced_no_effect",
            }
            .into(),
        })
    }
}
struct SqlInverseReady {
    forward: Harness,
    inverse: Harness,
    registration: Registration,
    contract: Contract,
    qualifier: Qualifier,
    topology: kedgeflow::action_domain::Topology,
    store: Arc<kedgeflow::postgres_compensation::PostgresCompensationStore>,
    admin: tokio_postgres::Client,
    pin: kedgeflow::postgres_target::Registration,
}
impl SqlInverseReady {
    fn target_trust(&self) -> kedgeflow::compensation_target::TargetTrust {
        kedgeflow::compensation_target::TargetTrust {
            contract: self.contract.clone(),
            forward: native::trust(&self.forward, &self.registration),
            topology: self.topology.clone(),
            registration: self.pin.clone(),
            forward_gateway_workload: "spiffe://test/gateway".into(),
            outcome_keys: keys(19),
            outcome_source: "spiffe://test/inverse-outcome".into(),
        }
    }
    fn grants(&self) -> GrantVerifier {
        GrantVerifier {
            keys: keys(5),
            audience: self.inverse.registration.scope.audience.clone(),
        }
    }
}
async fn sql_inverse_ready() -> Option<SqlInverseReady> {
    Box::pin(sql_inverse_setup(NOW, None)).await
}
async fn sql_inverse_setup(now: i64, gateway_url: Option<&str>) -> Option<SqlInverseReady> {
    Box::pin(sql_inverse_setup_plan(now, gateway_url, false)).await
}
async fn sql_inverse_setup_plan(
    now: i64,
    gateway_url: Option<&str>,
    extra_no_send: bool,
) -> Option<SqlInverseReady> {
    Box::pin(sql_inverse_setup_state(
        now,
        gateway_url,
        extra_no_send,
        false,
    ))
    .await
}
async fn sql_inverse_setup_state(
    now: i64,
    gateway_url: Option<&str>,
    extra_no_send: bool,
    extra_unclaimed: bool,
) -> Option<SqlInverseReady> {
    Box::pin(sql_inverse_setup_guarded(
        now,
        gateway_url,
        extra_no_send,
        extra_unclaimed,
        None,
        None,
    ))
    .await
}
async fn sql_inverse_setup_guarded(
    now: i64,
    gateway_url: Option<&str>,
    extra_no_send: bool,
    extra_unclaimed: bool,
    gate: Option<kedgeflow::restore::RestoreGate>,
    inverse_lifetime_ms: Option<i64>,
) -> Option<SqlInverseReady> {
    use kedgeflow::{
        action_domain::{Lane, Selection, Topology},
        postgres_compensation::{Database, PostgresCompensationStore},
        postgres_store::{PostgresStore, ReservationStore, UnixDatabase},
    };
    let socket = match std::env::var("KF_POSTGRES_TEST_SOCKET") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_POSTGRES").as_deref(), Ok("1"));
            eprintln!("SKIP inverse SQL: disposable database absent");
            return None;
        }
    };
    let resource = format!("inverse-native-{:x}", rand::random::<u64>());
    let mut seed = Box::pin(Harness::with_setup(None, now, |f| {
        sql_execution_fixture(f, &resource, false)
    }))
    .await?;
    seed.f.identity.delegation_digest =
        digest("delegation", &seed.f.proposal["delegation"]).unwrap();
    let mut r = registration(&seed);
    if extra_no_send {
        let larger = super::super::hierarchical_leaf::registration(&seed, 2);
        r.hierarchy = larger.hierarchy;
        r.enrollment = larger.enrollment;
        let original = seed.f.proposal["qid"].clone();
        seed.f.proposal["qid"] = json!("compound-not-sent");
        let op = seed
            .f
            .trust
            .operation_key(&seed.f.identity, &seed.f.packet().proposal)
            .unwrap();
        seed.f.proposal["qid"] = original;
        let principal = r.saga.as_ref().unwrap().nodes[0].principal.clone();
        r.saga
            .as_mut()
            .unwrap()
            .nodes
            .push(kedgeflow::saga_forward::Node {
                node_id: "no-send".into(),
                operation_key: op,
                principal,
                depends_on: vec![],
            });
        r.validate().unwrap();
    }
    let mut c = contract(&seed, &r);
    let prototype = Box::pin(Harness::with_native_timing(
        gateway_url,
        now + 6000,
        |f| sql_execution_fixture(f, &resource, true),
        None,
        None,
        None,
        None,
        inverse_lifetime_ms,
    ))
    .await
    .unwrap();
    c.inverse_policy = prototype.registration.policy.clone();
    c.inverse_scope = prototype.registration.scope.clone();
    c.signed_inverse_ctd =
        String::from_utf8(fixture::signed("ctd", prototype.f.descriptor.clone(), 2)).unwrap();
    let mut inv = prototype.registration.clone();
    let mut trust = prototype.f.trust.clone();
    trust.inverse_contract = Some(c.clone());
    inv.trust_digest = trust_digest(&trust, &keys(6), &keys(5)).unwrap();
    let topology = Topology {
        profile: kedgeflow::action_domain::PROFILE.into(),
        forward: seed.registration.clone(),
        inverse: inv,
    };
    let mut f = Box::pin(Harness::with_environment_and_pair(
        None,
        now,
        |f| sql_execution_fixture(f, &resource, false),
        gate.clone(),
        None,
        Some((
            Selection {
                topology: topology.clone(),
                lane: Lane::Forward,
            },
            None,
        )),
    ))
    .await
    .unwrap();
    f.f.identity.delegation_digest = digest("delegation", &f.f.proposal["delegation"]).unwrap();
    f.ledger = f.ledger.clone().with_reservation(r.clone()).unwrap();
    f.ledger.enroll_reservation().await.unwrap();
    let installed = f.bootstrap().await;
    assert!(f.post(&f.ack(&installed), true).await.0.is_success());
    let q = qualifier(&f, &c, &r);
    q.enroll().await.unwrap();
    let database = UnixDatabase {
        socket_directory: socket.into(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    };
    let admin = super::sql_leaf::owner(&database).await;
    admin
        .execute(
            "INSERT INTO kf_reservation.resource VALUES ($1,$2,$3,$4,241,0,'free',true)",
            &[
                &f.registration.tenant,
                &f.registration.scope.conflict_domain,
                &resource,
                &f.registration.scope.resource.incarnation,
            ],
        )
        .await
        .unwrap();
    let snapshot = json!({"tenant":f.registration.tenant,"conflict_domain":f.registration.scope.conflict_domain,"resource":f.registration.scope.resource,"baseline_version":241,"contract_digest":c.digest().unwrap(),"restore_state_digest":c.restore_state_digest});
    admin
        .query_one("SELECT kf_compensation.capture($1::jsonb)", &[&snapshot])
        .await
        .unwrap();
    let forward_store = Arc::new(PostgresStore::new(database.clone()).unwrap());
    let record = Box::pin(issue(&f)).await;
    let candidate = native::claim(&f, &record, &format!("forward-{resource}")).await;
    f.ledger
        .authorize_dispatch(
            &candidate.grant,
            &record.grant_digest,
            &candidate.attempt_id,
        )
        .await
        .unwrap();
    let forward_request = kedgeflow::postgres_action::DispatchRequest {
        profile: kedgeflow::postgres_action::PROFILE.into(),
        action: kedgeflow::postgres_action::ACTION.into(),
        tenant: f.registration.tenant.clone(),
        conflict_domain: f.registration.scope.conflict_domain.clone(),
        attempt_id: candidate.attempt_id.clone(),
        grant_digest: record.grant_digest.clone(),
        root_id: candidate.grant.root_id.clone(),
        resource: f.registration.scope.resource.clone(),
        expected_version: 241,
        fence: candidate.grant.fence,
        reservation: "booking:pilot".into(),
        gateway_workload: "spiffe://test/gateway".into(),
        expires_at: candidate.grant.expires_at as u64,
    };
    assert_eq!(
        forward_store.apply(&forward_request).await.unwrap().status,
        kedgeflow::postgres_action::Status::Committed
    );
    let no_send = if extra_no_send {
        let original = f.f.proposal["qid"].clone();
        f.f.proposal["qid"] = json!("compound-not-sent");
        let issued = Box::pin(issue(&f)).await;
        f.f.proposal["qid"] = original;
        if extra_unclaimed {
            None
        } else {
            let c = native::claim(&f, &issued, &format!("no-send-{resource}")).await;
            Some((issued, c))
        }
    } else {
        None
    };
    f.clock.0.store(now + 6000, Ordering::SeqCst);
    kedgeflow::recovery::RecoveryWorker::new(
        f.ledger.clone(),
        GrantVerifier {
            keys: keys(5),
            audience: f.registration.scope.audience.clone(),
        },
        Arc::new(SqlForwardQuery(forward_store)),
        "key-14".into(),
        SigningKey::from_bytes(&[14; 32]),
        "spiffe://test/outcome".into(),
        f.clock.clone(),
    )
    .unwrap()
    .recover(&candidate)
    .await
    .unwrap();
    if let Some((issued, c)) = no_send {
        let queries = Arc::new(AtomicUsize::new(0));
        let receipt = native::worker(&f, &c, &issued.grant_digest, "unknown", queries.clone())
            .recover(&c)
            .await
            .unwrap();
        assert_eq!(receipt.state, "not_dispatched");
        assert_eq!(queries.load(Ordering::SeqCst), 0);
    }
    let bundle = f
        .ledger
        .export_reserved_lineage(
            &candidate,
            &c.forward_operation_key,
            &HistoryObserver::new(
                "budget-observer".into(),
                "key-15".into(),
                SigningKey::from_bytes(&[15; 32]),
            )
            .unwrap(),
            &native::trust(&f, &r),
        )
        .await
        .unwrap();
    let mut i = Box::pin(Harness::with_native_timing(
        gateway_url,
        now + 6000,
        |f| sql_execution_fixture(f, &resource, true),
        gate,
        None,
        Some((
            Selection {
                topology: topology.clone(),
                lane: Lane::Inverse,
            },
            Some(f.prefix.clone()),
        )),
        Some(c.clone()),
        inverse_lifetime_ms,
    ))
    .await
    .unwrap();
    let inverse_database = Database {
        connection: UnixDatabase {
            executor_user: "kf_inverse_executor".into(),
            query_user: "kf_inverse_reader".into(),
            ..database
        },
        barrier_user: "kf_inverse_barrier".into(),
    };
    let store = Arc::new(PostgresCompensationStore::new(inverse_database).unwrap());
    store.check_database().await.unwrap();
    let s = &i.registration.scope;
    let pin = kedgeflow::postgres_target::Registration {
        tenant: i.registration.tenant.clone(),
        conflict_domain: s.conflict_domain.clone(),
        action: s.action.clone(),
        resource: s.resource.clone(),
        adapter_contract: s.adapter_contract.clone(),
        predicate_id: s.predicate_descriptor["id"].as_str().unwrap().into(),
        predicate_version: s.predicate_descriptor["version"].as_str().unwrap().into(),
        gateway_workload: "spiffe://test/gateway".into(),
        query_workload: "spiffe://test/recovery".into(),
        target_audience: "https://inverse-target.test/dispatch".into(),
        target_scope: "reservation:restore".into(),
    };
    let target = kedgeflow::compensation_target::TargetTrust {
        contract: c.clone(),
        forward: native::trust(&f, &r),
        topology: topology.clone(),
        registration: pin.clone(),
        forward_gateway_workload: "spiffe://test/gateway".into(),
        outcome_keys: keys(19),
        outcome_source: "spiffe://test/inverse-outcome".into(),
    };
    target
        .validate(&GrantVerifier {
            keys: keys(5),
            audience: i.registration.scope.audience.clone(),
        })
        .unwrap();
    let barrier = target
        .barrier(
            store.as_ref(),
            &bundle,
            now + 6000,
            20000,
            "key-17",
            &SigningKey::from_bytes(&[17; 32]),
        )
        .await
        .unwrap();
    let proof = kedgeflow::compensation_target::applicability(
        &c,
        &native::trust(&f, &r),
        bundle,
        barrier,
        now + 6000,
        "key-18",
        &SigningKey::from_bytes(&[18; 32]),
    )
    .unwrap();
    q.qualify(proof.clone()).await.unwrap();
    q.begin_compensation().await.unwrap();
    i.f.proposal["parameters"] = json!(proof.parameters);
    let installed = i.bootstrap().await;
    assert!(i.post(&i.ack(&installed), true).await.0.is_success());
    let cfg = json!({"profile":kedgeflow::compensation_execution::PROFILE,"contract":c,"forward":native::trust_value(&f,&r),"outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"});
    let cfg: kedgeflow::compensation_execution::ExecutionConfig =
        serde_json::from_value(cfg).unwrap();
    i.ledger = cfg.attach(i.ledger.clone()).unwrap();
    Some(SqlInverseReady {
        forward: f,
        inverse: i,
        registration: r,
        contract: c,
        qualifier: q,
        topology,
        store,
        admin,
        pin,
    })
}

async fn sql_inverse_authorize(
    ready: &mut SqlInverseReady,
) -> (
    kedgeflow::ledger::IssuanceRecord,
    kedgeflow::recovery::Candidate,
    String,
) {
    use kedgeflow::{
        broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangeRequest},
        target_token::{ReferenceTokenMinter, TargetTokenMinter},
    };
    let i = &mut ready.inverse;
    let now = kedgeflow::clock::Clock::now_ms(i.clock.as_ref());
    let expires = now / 1000 + 54;
    let audience = i.f.proposal["delegation"]["token_audience"]
        .as_str()
        .unwrap()
        .to_owned();
    let token = jwt(
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
        json!({"iss":i.f.identity.subject.iss,"sub":i.f.identity.subject.sub,"aud":audience,"exp":expires,"iat":now/1000,"scope":"capacity.reserve","cnf":{"jkt":i.f.identity.dpop_jkt}}),
        7,
    );
    i.f.proposal["delegation"] = json!({"access_token_digest":hex::encode(Sha256::digest(token.as_bytes())),"dpop_jkt":i.f.identity.dpop_jkt,"authorization_server":i.f.identity.subject.iss,"token_audience":audience,"scopes":["capacity.reserve"],"expires_at":expires*1000});
    i.f.identity.delegation_digest = digest("delegation", &i.f.proposal["delegation"]).unwrap();
    i.f.identity.access_token = token.clone();
    let mut provider = super::exchange::Fixture::new();
    provider.snapshot.issuer = i.f.identity.subject.iss.clone();
    provider.snapshot.subject_audience = audience;
    provider.snapshot.subject_keys[0].kid = "key-7".into();
    provider.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    provider.snapshot.registrations[0].subject = i.f.identity.subject.clone();
    provider.snapshot.registrations[0].allowed_scopes =
        std::collections::BTreeSet::from(["capacity.reserve".into()]);
    provider.snapshot.not_before = now;
    provider.snapshot.expires_at = now + 120000;
    provider.snapshot.subject_keys[0].not_before = now;
    provider.snapshot.subject_keys[0].expires_at = now + 120000;
    provider.snapshot.actor_keys[0].not_before = now;
    provider.snapshot.actor_keys[0].expires_at = now + 120000;
    let actor=provider.actor_token(json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),json!({"sub":"spiffe://test/agent","aud":"https://broker.test/exchange","exp":now/1000+60,"iat":now/1000}));
    let authorizer = BrokerAuthorizer::new(
        BrokerRegistration {
            gateway_workload: ready.pin.gateway_workload.clone(),
            target_audience: ready.pin.target_audience.clone(),
            target_scope: ready.pin.target_scope.clone(),
            max_lifetime_ms: 5000,
            tool: i.tool(),
        },
        GrantVerifier {
            keys: keys(5),
            audience: i.registration.scope.audience.clone(),
        },
        i.ledger.clone(),
        Arc::new(provider.provider()),
        i.clock.clone(),
    )
    .unwrap();
    let rec = execution_issue(i).await.unwrap().record;
    let candidate = native::claim(i, &rec, &format!("restore-{}", ready.pin.resource.id)).await;
    let request = ExchangeRequest {
        subject_token: token,
        actor_token: actor,
        signed_grant: rec.signed_grant.clone(),
        grant_digest: rec.grant_digest.clone(),
        attempt_id: candidate.attempt_id.clone(),
        audience: ready.pin.target_audience.clone(),
        scope: ready.pin.target_scope.clone(),
    };
    let workload = super::exchange::workload(&ready.pin.gateway_workload);
    let permit = authorizer.authorize(&request, &workload).await.unwrap();
    assert!(authorizer.authorize(&request, &workload).await.is_err());
    let credential = ReferenceTokenMinter::new(
        "https://broker.test/exchange".into(),
        "key-29".into(),
        SigningKey::from_bytes(&[29; 32]),
    )
    .unwrap()
    .mint(&permit, kedgeflow::clock::Clock::now_ms(i.clock.as_ref()))
    .await
    .unwrap();
    i.ledger
        .authorize_dispatch(&candidate.grant, &rec.grant_digest, &candidate.attempt_id)
        .await
        .unwrap();
    (rec, candidate, credential)
}
#[tokio::test]
async fn compensation_sql_native_fresh_authority_real_barrier_broker_restore_and_original_query() {
    use kedgeflow::{
        compensation_target::{Dispatch, PROFILE as HTTP},
        postgres_compensation::CompensationStore,
        target_token::TargetTokenVerifier,
    };
    let Some(mut h) = sql_inverse_ready().await else {
        return;
    };
    let held = native::budget(&h.forward, &h.registration).await;
    let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    let (binding, qualification) = h
        .inverse
        .ledger
        .compensation_dispatch_material(&candidate.grant, &rec.grant_digest, &candidate.attempt_id)
        .await
        .unwrap();
    let request = Dispatch {
        profile: HTTP.into(),
        operation: "dispatch".into(),
        signed_grant: URL_SAFE_NO_PAD.encode(rec.signed_grant.as_bytes()),
        attempt_id: candidate.attempt_id.clone(),
        qualification,
        binding,
    };
    let target = h.target_trust();
    let tokens = TargetTokenVerifier::new("https://broker.test/exchange".into(), keys(29)).unwrap();
    assert!(
        target
            .bind(&h.grants(), &tokens, &request, "bad", NOW + 6000)
            .is_err()
    );
    let bound = target
        .bind(&h.grants(), &tokens, &request, &token, NOW + 6000)
        .unwrap();
    let out = h.store.apply(&bound).await.unwrap();
    assert_eq!(out.status, kedgeflow::postgres_action::Status::Committed);
    assert_eq!(out.post_version, Some(243));
    assert_eq!(h.store.apply(&bound).await.unwrap(), out);
    assert_eq!(
        h.store
            .lookup(&h.pin.tenant, &candidate.attempt_id)
            .await
            .unwrap()
            .unwrap(),
        out
    );
    let row=h.admin.query_one("SELECT version,last_fence,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 243);
    assert_eq!(row.get::<_, i64>(1), 2);
    assert_eq!(row.get::<_, String>(2), "free");
    assert_eq!(native::budget(&h.forward, &h.registration).await, held);
    assert_eq!(
        h.inverse.ledger.compensation_spend().await.unwrap().state,
        kedgeflow::coordination::ReservationState::Unknown
    );
    assert_eq!(h.qualifier.history().await.unwrap().len(), 1);
}

const INVERSE_QUERY_TOKEN: &str = "generated-inverse-query-role-token-000000000000000000";
const INVERSE_BARRIER_TOKEN: &str = "generated-inverse-barrier-role-token-0000000000000000";
struct LostSqlInverse {
    real: Arc<kedgeflow::postgres_compensation::PostgresCompensationStore>,
    calls: AtomicUsize,
    queries: AtomicUsize,
}
#[async_trait::async_trait]
impl kedgeflow::postgres_compensation::CompensationStore for LostSqlInverse {
    async fn apply(
        &self,
        q: &kedgeflow::postgres_compensation::DispatchRequest,
    ) -> kedgeflow::error::Result<kedgeflow::postgres_compensation::Outcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.real.apply(q).await?;
        Err(kedgeflow::error::Error::Unknown(
            "discarded inverse reply after real SQL COMMIT".into(),
        ))
    }
    async fn lookup(
        &self,
        tenant: &str,
        attempt: &str,
    ) -> kedgeflow::error::Result<Option<kedgeflow::postgres_compensation::Outcome>> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        self.real.lookup(tenant, attempt).await
    }
    async fn barrier(
        &self,
        q: &kedgeflow::postgres_compensation::BarrierQuery,
    ) -> kedgeflow::error::Result<Option<kedgeflow::postgres_compensation::BarrierObservation>>
    {
        self.real.barrier(q).await
    }
}
fn inverse_service(
    h: &SqlInverseReady,
    store: Arc<dyn kedgeflow::postgres_compensation::CompensationStore>,
    dispatch: &str,
    query: &str,
    barrier: &str,
) -> Arc<kedgeflow::compensation_target_http::Service> {
    Arc::new(
        kedgeflow::compensation_target_http::Service::new(
            h.target_trust(),
            h.grants(),
            kedgeflow::target_token::TargetTokenVerifier::new(
                "https://broker.test/exchange".into(),
                keys(29),
            )
            .unwrap(),
            store,
            h.inverse.clock.clone(),
            [dispatch, query, barrier],
            INVERSE_QUERY_TOKEN,
            INVERSE_BARRIER_TOKEN,
            "spiffe://test/barrier".into(),
            "key-17".into(),
            SigningKey::from_bytes(&[17; 32]),
            20000,
        )
        .unwrap(),
    )
}
#[tokio::test]
async fn compensation_sql_native_mtls_lost_commit_reply_restart_and_original_recovery_after_stop() {
    use kedgeflow::{
        compensation_target::{Dispatch, PROFILE as HTTP},
        ledger::OutcomeQuerier,
    };
    let Some(mut h) = sql_inverse_ready().await else {
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("https://{}", listener.local_addr().unwrap());
    let dispatch = format!("{base}/dispatch");
    let query = format!("{base}/query");
    let barrier = format!("{base}/barrier");
    h.pin.target_audience = dispatch.clone();
    let pki = support::pki_for_workloads(&[
        "spiffe://test/gateway",
        "spiffe://test/recovery",
        "spiffe://test/barrier",
        "spiffe://test/agent",
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
    let tls = kedgeflow::tls::server_config_pem(
        pki[0].server.as_bytes(),
        pki[0].server_key.as_bytes(),
        pki[0].ca.as_bytes(),
    )
    .unwrap();
    let lost = Arc::new(LostSqlInverse {
        real: h.store.clone(),
        calls: AtomicUsize::new(0),
        queries: AtomicUsize::new(0),
    });
    let service = inverse_service(&h, lost.clone(), &dispatch, &query, &barrier);
    let running = tokio::spawn(kedgeflow::server::serve_router(
        listener,
        tls.clone(),
        service.router(),
    ));
    let forward = h.qualifier.history().await.unwrap()[0]
        .proof
        .forward
        .clone();
    let request = json!({"profile":HTTP,"operation":"barrier","forward":forward});
    let response = client(2)
        .client()
        .post(&barrier)
        .bearer_auth(INVERSE_BARRIER_TOKEN)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let signed: Statement = response.json().await.unwrap();
    kedgeflow::compensation_target::applicability(
        &h.contract,
        &native::trust(&h.forward, &h.registration),
        forward,
        signed,
        NOW + 6000,
        "key-18",
        &SigningKey::from_bytes(&[18; 32]),
    )
    .unwrap();
    assert_eq!(
        client(0)
            .client()
            .post(&barrier)
            .bearer_auth(INVERSE_BARRIER_TOKEN)
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    let (binding, qualification) = h
        .inverse
        .ledger
        .compensation_dispatch_material(&candidate.grant, &rec.grant_digest, &candidate.attempt_id)
        .await
        .unwrap();
    let request = Dispatch {
        profile: HTTP.into(),
        operation: "dispatch".into(),
        signed_grant: URL_SAFE_NO_PAD.encode(rec.signed_grant.as_bytes()),
        attempt_id: candidate.attempt_id.clone(),
        qualification,
        binding,
    };
    assert_eq!(
        client(3)
            .client()
            .post(&dispatch)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let response = client(0)
        .client()
        .post(&dispatch)
        .bearer_auth(&token)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(lost.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.inverse.ledger.compensation_spend().await.unwrap().state,
        kedgeflow::coordination::ReservationState::Unknown
    );
    running.abort();
    let _ = running.await;
    let listener = tokio::net::TcpListener::bind(base.strip_prefix("https://").unwrap())
        .await
        .unwrap();
    let service = inverse_service(&h, lost.clone(), &dispatch, &query, &barrier);
    let running = tokio::spawn(kedgeflow::server::serve_router(
        listener,
        tls,
        service.router(),
    ));
    let observer = Arc::new(
        kedgeflow::recovery_config::HttpOutcomeQuerier::new(
            client(1).client().clone(),
            &query,
            INVERSE_QUERY_TOKEN.into(),
        )
        .unwrap(),
    );
    let found = observer.query(&candidate.attempt_id).await.unwrap();
    assert_eq!(found.status, "committed");
    assert_eq!(found.grant_digest, rec.grant_digest);
    h.forward.ledger.stop_reservation().await.unwrap();
    h.inverse.clock.0.store(NOW + 12000, Ordering::SeqCst);
    let worker = kedgeflow::recovery::RecoveryWorker::new(
        h.inverse.ledger.clone(),
        h.grants(),
        observer,
        "key-19".into(),
        SigningKey::from_bytes(&[19; 32]),
        "spiffe://test/inverse-outcome".into(),
        h.inverse.clock.clone(),
    )
    .unwrap();
    let first = worker.recover(&candidate).await.unwrap();
    assert_eq!(first.state, "committed");
    assert_eq!(
        first.receipt_digest,
        worker.recover(&candidate).await.unwrap().receipt_digest
    );
    let spend = h.inverse.ledger.compensation_spend().await.unwrap();
    assert_eq!(
        spend.state,
        kedgeflow::coordination::ReservationState::Committed
    );
    assert_eq!(
        spend.attempt_id.as_deref(),
        Some(candidate.attempt_id.as_str())
    );
    assert_eq!(lost.calls.load(Ordering::SeqCst), 1);
    assert_eq!(lost.queries.load(Ordering::SeqCst), 2);
    assert!(
        h.inverse
            .ledger
            .claim(&candidate.grant, &rec.grant_digest, "replacement")
            .await
            .is_err()
    );
    running.abort();
    let _ = running.await;
}
#[tokio::test]
async fn compensation_sql_native_intervening_writer_refuses_restore_and_holds_original_spend() {
    use kedgeflow::{
        compensation_target::{Dispatch, PROFILE as HTTP},
        postgres_compensation::CompensationStore,
        target_token::TargetTokenVerifier,
    };
    let Some(mut h) = sql_inverse_ready().await else {
        return;
    };
    let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    let (binding, qualification) = h
        .inverse
        .ledger
        .compensation_dispatch_material(&candidate.grant, &rec.grant_digest, &candidate.attempt_id)
        .await
        .unwrap();
    let request = Dispatch {
        profile: HTTP.into(),
        operation: "dispatch".into(),
        signed_grant: URL_SAFE_NO_PAD.encode(rec.signed_grant.as_bytes()),
        attempt_id: candidate.attempt_id.clone(),
        qualification,
        binding,
    };
    let tokens = TargetTokenVerifier::new("https://broker.test/exchange".into(), keys(29)).unwrap();
    let bound = h
        .target_trust()
        .bind(&h.grants(), &tokens, &request, &token, NOW + 6000)
        .unwrap();
    h.admin.execute("UPDATE kf_reservation.resource SET version=version+1,reservation='external-writer' WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
    assert_eq!(
        h.store.apply(&bound).await.unwrap().status,
        kedgeflow::postgres_action::Status::GuardRejected
    );
    assert_eq!(
        h.store
            .lookup(&h.pin.tenant, &candidate.attempt_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        kedgeflow::postgres_action::Status::GuardRejected
    );
    assert!(
        h.target_trust()
            .barrier(
                h.store.as_ref(),
                &request.qualification.proof.forward,
                NOW + 6000,
                20000,
                "key-17",
                &SigningKey::from_bytes(&[17; 32])
            )
            .await
            .is_err()
    );
    assert_eq!(
        h.inverse.ledger.compensation_spend().await.unwrap().state,
        kedgeflow::coordination::ReservationState::Unknown
    );
    let row=h.admin.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 243);
    assert_eq!(row.get::<_, String>(1), "external-writer");
    assert!(
        h.inverse
            .ledger
            .claim(&candidate.grant, &rec.grant_digest, "another")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn compensation_sql_signed_semantic_substitutions_and_target_role_pins_refuse() {
    use kedgeflow::{
        compensation_target::{Dispatch, PROFILE as HTTP},
        target_token::TargetTokenVerifier,
    };
    let Some(mut h) = sql_inverse_ready().await else {
        return;
    };
    let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    let (binding, qualification) = h
        .inverse
        .ledger
        .compensation_dispatch_material(&candidate.grant, &rec.grant_digest, &candidate.attempt_id)
        .await
        .unwrap();
    let good = Dispatch {
        profile: HTTP.into(),
        operation: "dispatch".into(),
        signed_grant: URL_SAFE_NO_PAD.encode(rec.signed_grant.as_bytes()),
        attempt_id: candidate.attempt_id.clone(),
        qualification,
        binding,
    };
    let tokens = TargetTokenVerifier::new("https://broker.test/exchange".into(), keys(29)).unwrap();
    let target = h.target_trust();
    assert!(
        target
            .bind(&h.grants(), &tokens, &good, &token, NOW + 6000)
            .is_ok()
    );
    for field in [
        "outcome_trust_digest",
        "topology_digest",
        "contract_digest",
        "qualification_digest",
        "grant_digest",
        "certificate_digest",
        "parameters_digest",
    ] {
        let mut value = json!(good);
        value["binding"]["payload"][field] = json!("f".repeat(64));
        let unsigned = json!({"profile":value["binding"]["profile"],"key_id":value["binding"]["key_id"],"payload":value["binding"]["payload"]});
        let mut msg =
            format!("KedgeFlow:{}\0", kedgeflow::compensation_execution::PROFILE).into_bytes();
        msg.extend(kedgeflow::contracts::canonical(&unsigned).unwrap());
        value["binding"]["signature"] =
            json!(URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[5; 32]).sign(&msg).to_bytes()));
        let bad: Dispatch = serde_json::from_value(value).unwrap();
        assert!(
            target
                .bind(&h.grants(), &tokens, &bad, &token, NOW + 6000)
                .is_err(),
            "{field}"
        );
    }
    let mut bad = good.clone();
    bad.attempt_id = "replacement".into();
    assert!(
        target
            .bind(&h.grants(), &tokens, &bad, &token, NOW + 6000)
            .is_err()
    );
    let mut bad = good.clone();
    bad.qualification.proof.barrier.payload["no_late_commit"] = json!(false);
    resign(&mut bad.qualification.proof);
    assert!(
        target
            .bind(&h.grants(), &tokens, &bad, &token, NOW + 6000)
            .is_err()
    );
    assert!(
        target
            .bind(&h.grants(), &tokens, &good, &token, NOW + 30000)
            .is_err()
    );
    let mut changed = h.target_trust();
    changed.outcome_source = "spiffe://test/replaced-outcome".into();
    assert!(
        changed
            .bind(&h.grants(), &tokens, &good, &token, NOW + 6000)
            .is_err()
    );
    let mut changed = h.target_trust();
    changed.outcome_keys = keys(17);
    assert!(changed.validate(&h.grants()).is_err());
    let mut body = json!(good);
    body["extra"] = json!(true);
    assert!(Dispatch::decode(&serde_json::to_vec(&body).unwrap()).is_err());
    body = json!(good);
    body.as_object_mut().unwrap().remove("binding");
    assert!(Dispatch::decode(&serde_json::to_vec(&body).unwrap()).is_err());
    assert!(
        kedgeflow::compensation_target::applicability(
            &h.contract,
            &native::trust(&h.forward, &h.registration),
            good.qualification.proof.forward.clone(),
            good.qualification.proof.barrier.clone(),
            NOW + 6000,
            "key-17",
            &SigningKey::from_bytes(&[17; 32])
        )
        .is_err()
    );
    let count: i64 = h
        .admin
        .query_one(
            "SELECT count(*) FROM kf_compensation.attempt WHERE tenant=$1 AND contract_digest=$2",
            &[&h.pin.tenant, &h.contract.digest().unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn compensation_sql_shipping_target_evaluator_and_native_adapter_use_original_protected_material()
 {
    use kedgeflow::{
        adapter::ResourceAdapter,
        broker::TargetCredential,
        clock::{Clock, SystemClock},
        gateway::VerifiedCall,
    };
    use std::os::unix::fs::PermissionsExt;
    let started = SystemClock.now_ms();
    let Some(mut h) = Box::pin(sql_inverse_setup(started, None)).await else {
        return;
    };
    let until = h.inverse.clock.now_ms();
    let current = SystemClock.now_ms();
    if current < until {
        tokio::time::sleep(Duration::from_millis((until - current) as u64 + 30)).await;
    }
    h.inverse
        .clock
        .0
        .store(SystemClock.now_ms(), Ordering::SeqCst);
    let ticking = h.inverse.clock.clone();
    let _ticker = super::super::live_agent::Running(tokio::spawn(async move {
        loop {
            ticking.0.store(SystemClock.now_ms(), Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }));
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, raw: &[u8]| {
        let path = directory.path().join(name);
        std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let pki = support::pki_for_workloads(&[
        "spiffe://test/gateway",
        "spiffe://test/recovery",
        "spiffe://test/barrier",
    ]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let dispatch = format!("https://{address}/dispatch");
    let query = format!("https://{address}/query");
    let barrier = format!("https://{address}/barrier");
    h.pin.target_audience = dispatch.clone();
    let ca = write("ca.pem", pki[0].ca.as_bytes());
    let cert = write("server.pem", pki[0].server.as_bytes());
    let key = write("server-key.pem", pki[0].server_key.as_bytes());
    let query_token = write("query-token", INVERSE_QUERY_TOKEN.as_bytes());
    let barrier_token = write("barrier-token", INVERSE_BARRIER_TOKEN.as_bytes());
    let barrier_key = write("barrier-key", STANDARD.encode([17; 32]).as_bytes());
    let app_key = write("app-key", STANDARD.encode([18; 32]).as_bytes());
    let forward = h.qualifier.history().await.unwrap()[0]
        .proof
        .forward
        .clone();
    let selected = h.qualifier.history().await.unwrap()[0]
        .proof
        .barrier
        .clone();
    let forward_path = write("forward.json", &serde_json::to_vec(&forward).unwrap());
    let barrier_path = write("barrier.json", &serde_json::to_vec(&selected).unwrap());
    let evaluator = json!({"contract":h.contract,"forward":native::trust_value(&h.forward,&h.registration),"key_id":"key-18","signing_key_file":app_key});
    let evaluator_path = write("evaluator.json", &serde_json::to_vec(&evaluator).unwrap());
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-compensation-evaluate"))
        .arg("--config")
        .arg(evaluator_path)
        .arg("--forward")
        .arg(forward_path)
        .arg("--barrier")
        .arg(barrier_path)
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result = Proof::decode(&out.stdout).unwrap();
    inverse::verify(
        &h.contract,
        &native::trust(&h.forward, &h.registration),
        &result,
        SystemClock.now_ms(),
    )
    .unwrap();
    let cfg = json!({"profile":kedgeflow::compensation_target::PROFILE,"listen":address,"dispatch_url":dispatch,"query_url":query,"barrier_url":barrier,"certificate":cert,"private_key":key,"workload_ca":ca,
        "database":{"connection":{"socket_directory":std::fs::canonicalize(std::env::var("KF_POSTGRES_TEST_SOCKET").unwrap()).unwrap(),"port":5432,"database":"postgres","executor_user":"kf_inverse_executor","query_user":"kf_inverse_reader"},"barrier_user":"kf_inverse_barrier"},
        "trust":{"inverse_execution":{"profile":kedgeflow::compensation_execution::PROFILE,"contract":h.contract,"forward":native::trust_value(&h.forward,&h.registration),"outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"},"topology":h.topology,"registration":h.pin,"forward_gateway_workload":"spiffe://test/gateway"},
        "grant_keys":public(5),"gateway_audience":h.inverse.registration.scope.audience,"token_issuer":"https://broker.test/exchange","target_keys":public(29),"query_token_file":query_token,"barrier_token_file":barrier_token,"barrier_workload":"spiffe://test/barrier","barrier_key_id":"key-17","barrier_signing_key_file":barrier_key,"barrier_lifetime_ms":20000});
    let config_path = write("target.json", &serde_json::to_vec(&cfg).unwrap());
    for flag in ["--check", "--check-database"] {
        let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-compensation-target"))
            .arg("--config")
            .arg(&config_path)
            .arg(flag)
            .arg("--postgres-peer-uid")
            .arg(rustix::process::geteuid().as_raw().to_string())
            .output()
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for field in [
        "profile",
        "barrier_url",
        "barrier_key_id",
        "target_keys",
        "query_token_file",
    ] {
        let mut bad = cfg.clone();
        bad[field] = match field {
            "profile" => json!("unknown"),
            "barrier_url" => json!(dispatch),
            "barrier_key_id" => json!("key-18"),
            "target_keys" => json!(public(17)),
            _ => json!(cfg["barrier_token_file"]),
        };
        let parsed = kedgeflow::compensation_target_config::Config::decode(
            &serde_json::to_vec(&bad).unwrap(),
        )
        .unwrap();
        assert!(parsed.service(None).await.is_err(), "{field}");
    }
    let parsed =
        kedgeflow::compensation_target_config::Config::decode(&serde_json::to_vec(&cfg).unwrap())
            .unwrap();
    parsed.service(None).await.unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-compensation-target"));
    command
        .arg("--config")
        .arg(&config_path)
        .arg("--postgres-peer-uid")
        .arg(rustix::process::geteuid().as_raw().to_string())
        .kill_on_drop(true)
        .stderr(std::process::Stdio::piped());
    let mut process = command.spawn().unwrap();
    let client = |n: usize| {
        kedgeflow::tls::pinned_client_pem(
            pki[n].ca.as_bytes(),
            pki[n].client.as_bytes(),
            pki[n].client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    };
    let reader = kedgeflow::recovery_config::HttpOutcomeQuerier::new(
        client(1).client().clone(),
        &query,
        INVERSE_QUERY_TOKEN.into(),
    )
    .unwrap();
    for _ in 0..100 {
        if let Ok(response)=client(1).client().post(&query).bearer_auth(INVERSE_QUERY_TOKEN).json(&json!({"profile":kedgeflow::recovery::PROFILE,"operation":"query","attempt_id":"readiness"})).send().await{assert_eq!(response.status(),reqwest::StatusCode::NOT_FOUND);break;}
        if let Some(code) = process.try_wait().unwrap() {
            panic!("shipping inverse target exited: {code}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    h.inverse
        .clock
        .0
        .store(SystemClock.now_ms(), Ordering::SeqCst);
    let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut h)).await;
    let call = VerifiedCall {
        request: serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":h.inverse.tool().name,"arguments":h.inverse.f.proposal["parameters"]}})).unwrap(),
        grant:candidate.grant.clone(),grant_digest:rec.grant_digest.clone(),signed_grant:rec.signed_grant.as_bytes().to_vec(),attempt_id:candidate.attempt_id.clone(),identity:h.inverse.f.identity.clone(),descriptor:h.inverse.tool(),
    };
    let adapter = kedgeflow::compensation_adapter::CompensationAdapter::new(
        &dispatch,
        client(0),
        h.target_trust(),
        h.grants(),
        kedgeflow::target_token::TargetTokenVerifier::new(
            "https://broker.test/exchange".into(),
            keys(29),
        )
        .unwrap(),
        h.inverse.ledger.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let token_expiry = serde_json::from_slice::<Value>(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()["exp"]
        .as_i64()
        .unwrap()
        * 1000;
    let result = adapter
        .dispatch(
            &call,
            &TargetCredential {
                token,
                expires_at_ms: token_expiry,
                audience: dispatch,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.status, "committed");
    use kedgeflow::ledger::OutcomeQuerier;
    assert_eq!(
        reader.query(&candidate.attempt_id).await.unwrap().status,
        "committed"
    );
    process.kill().await.unwrap();
    let _ = process.wait().await;
}

struct FixedInverseIdentity(kedgeflow::auth::Identity);
#[async_trait::async_trait]
impl kedgeflow::broker_authorization::ExchangeIdentityProvider for FixedInverseIdentity {
    async fn verify(
        &self,
        subject: &str,
        actor: &str,
        _: i64,
    ) -> kedgeflow::error::Result<kedgeflow::broker_authorization::VerifiedExchangeIdentity> {
        assert_eq!(subject, self.0.access_token);
        assert_eq!(actor, "synthetic-actor-boundary");
        Ok(kedgeflow::broker_authorization::VerifiedExchangeIdentity {
            identity: self.0.clone(),
            subject_valid_until: NOW + 60000,
            actor_valid_until: NOW + 60000,
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compensation_sql_broker_permit_cas_compares_original_forward_stop_and_retains_no_mint_authority()
 {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use kedgeflow::{
        action_domain::{Lane, Selection},
        broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangeRequest},
    };
    let Some(h) = sql_inverse_ready().await else {
        return;
    };
    let rec = execution_issue(&h.inverse).await.unwrap().record;
    let candidate = native::claim(&h.inverse, &rec, "raced-sql-inverse-broker").await;
    assert!(
        h.inverse
            .ledger
            .compensation_dispatch_material(
                &candidate.grant,
                &rec.grant_digest,
                &candidate.attempt_id
            )
            .await
            .is_err()
    );
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let key = Arc::new(std::sync::Mutex::new(String::new()));
    let router = Router::new().route(
        "/v3/kv/txn",
        post({
            let entered = entered.clone();
            let release = release.clone();
            let key = key.clone();
            move |Json(v): Json<Value>| {
                let entered = entered.clone();
                let release = release.clone();
                let key = key.clone();
                async move {
                    let permit = v["success"].as_array().and_then(|ops| {
                        ops.iter().find_map(|o| {
                            o["request_put"]["key"]
                                .as_str()
                                .and_then(|s| STANDARD.decode(s).ok())
                                .and_then(|b| String::from_utf8(b).ok())
                                .filter(|s| s.ends_with("/credential-permit"))
                        })
                    });
                    if let Some(k) = permit {
                        *key.lock().unwrap() = k;
                        entered.notify_one();
                        release.notified().await;
                    }
                    let response = reqwest::Client::new()
                        .post(format!(
                            "{}/v3/kv/txn",
                            std::env::var("ETCD_ENDPOINT").unwrap()
                        ))
                        .json(&v)
                        .send()
                        .await
                        .unwrap();
                    (
                        response.status(),
                        [("content-type", "application/json")],
                        response.bytes().await.unwrap(),
                    )
                        .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let _proxy = super::super::live_agent::Running(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    let cfg:kedgeflow::compensation_execution::ExecutionConfig=serde_json::from_value(json!({"profile":kedgeflow::compensation_execution::PROFILE,"contract":h.contract,"forward":native::trust_value(&h.forward,&h.registration),"outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"})).unwrap();
    let ledger = cfg
        .attach(
            EtcdLedger::new(reqwest::Client::new(), endpoint, &h.inverse.prefix)
                .unwrap()
                .with_clock(h.inverse.clock.clone())
                .with_action_domain(Selection {
                    topology: h.topology.clone(),
                    lane: Lane::Inverse,
                })
                .unwrap(),
        )
        .unwrap();
    let authorizer = BrokerAuthorizer::new(
        BrokerRegistration {
            gateway_workload: h.pin.gateway_workload.clone(),
            target_audience: h.pin.target_audience.clone(),
            target_scope: h.pin.target_scope.clone(),
            max_lifetime_ms: 3000,
            tool: h.inverse.tool(),
        },
        h.grants(),
        ledger,
        Arc::new(FixedInverseIdentity(h.inverse.f.identity.clone())),
        h.inverse.clock.clone(),
    )
    .unwrap();
    let request = ExchangeRequest {
        subject_token: h.inverse.f.identity.access_token.clone(),
        actor_token: "synthetic-actor-boundary".into(),
        signed_grant: rec.signed_grant,
        grant_digest: rec.grant_digest,
        attempt_id: candidate.attempt_id,
        audience: h.pin.target_audience.clone(),
        scope: h.pin.target_scope.clone(),
    };
    let workload = super::super::exchange::workload(&h.pin.gateway_workload);
    let pending = tokio::spawn(async move { authorizer.authorize(&request, &workload).await });
    tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    h.forward.ledger.stop_reservation().await.unwrap();
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    let permit_key = key.lock().unwrap().clone();
    assert!(!permit_key.is_empty());
    assert!(
        h.inverse
            .ledger
            .read_key(&permit_key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.inverse.ledger.compensation_spend().await.unwrap().state,
        kedgeflow::coordination::ReservationState::Unknown
    );
}

#[path = "compensation_sql_agent.rs"]
mod agent;

#[path = "compensation_lineage.rs"]
mod lineage;

#[path = "compensation_failure.rs"]
mod failure;
