//! Required real Kubernetes/native authority qualification. This file is not a
//! simulated cluster and cannot run without an explicit owned fixture.
use super::*;
use kedgeflow::{
    clock::{Clock, SystemClock},
    kube_drain as kd,
    kube_drain_api::Api,
    kube_drain_observer::Observer as PhysicalObserver,
    kube_drain_proof::Trust as PhysicalTrust,
    kube_drain_runtime::Controller,
};
fn now() -> i64 {
    SystemClock.now_ms()
}
fn configure_physical(f: &mut Fixture, c: &kd::Contract) {
    let resource = c.resource().unwrap();
    f.proposal["qid"] = json!(format!("physical-{}", c.cluster_uid));
    f.proposal["resources"] = json!([resource]);
    f.proposal["parameters"] = json!({"node":c.node.name,"expected_version":c.generation});
    f.proposal["baseline_state"][0]["resource"] = json!(resource);
    f.proposal["baseline_state"][0]["version"] = json!(c.generation.to_string());
    f.proposal["baseline_state"][0]["state_digest"] = json!(c.digest().unwrap());
    f.descriptor["action"] = json!(kd::ACTION);
    f.descriptor["consequence_description"] = json!(
        "Accepts a bounded Level C node drain; cordon and evictions are separate requests. Native commit is controller acceptance, and physical completion requires independent observation. No physical inverse is registered."
    );
    f.proposal["action"]["id"] = json!(kd::ACTION);
    f.descriptor["parameter_schema"] = c.parameter_schema().unwrap();
    let schema_digest = digest("parameter-schema", &f.descriptor["parameter_schema"]).unwrap();
    f.descriptor["parameter_schema_digest"] = json!(schema_digest);
    f.descriptor["rendering"]["parameter_schema_digest"] = json!(schema_digest);
    f.descriptor["adapter_contract"] = kd::adapter_contract();
    f.descriptor["concurrency"]["conflict_domain"] =
        json!(format!("physical:{}:{}", c.cluster_uid, c.node.uid));
    f.descriptor["concurrency"]["predicate_descriptor"]["clauses"][0]["resource"] = json!(resource);
    f.descriptor["concurrency"]["predicate_descriptor"]["clauses"][0]["expected_version"] =
        json!(c.generation.to_string());
    f.descriptor["concurrency"]["coverage"] = kd::coverage();
    f.evidence["state_scope"] = json!([resource]);
    f.evidence["state_digest"] = json!(c.digest().unwrap());
    f.evidence["result"]["version"] = json!(c.generation.to_string());
    let q = f.trust.evidence.get_mut("capacity").unwrap();
    for p in &mut q.predicates {
        if let kedgeflow::admission::EvidencePredicate::StringEquals { field, expected } = p
            && field == "version"
        {
            *expected = c.generation.to_string();
        }
    }
    q.obligation.predicate_digest = digest("evidence-predicate", &json!(q.predicates)).unwrap();
    f.trust.obligation_manifest_digest = f.trust.registered_obligations_digest().unwrap();
    f.identity.delegation_digest = digest("delegation", &f.proposal["delegation"]).unwrap();
    f.repin_descriptor();
}
fn control_trust(h: &Harness, native: &Value, namespace: &str) -> Value {
    json!({"operation":native["lineage"],"historical":[{"registration":h.registration,"trust":native["lineage"]}],"administrative_keys":{"publish_policy":public(10),"register_descriptor":public(11),"install":public(12),"revoke":public(13)},"observer_id":"physical-observer","observer_keys":public(49),"namespace":namespace})
}
fn configure_physical_provider(f: &mut Fixture, c: &kd::Contract) {
    f.trust.required_scope = "node.drain".into();
    f.identity.scopes = std::collections::BTreeSet::from(["node.drain".into()]);
    f.proposal["delegation"]["scopes"] = json!(["node.drain"]);
    f.proposal["delegation"]["token_audience"] = json!(crate::AUD);
    f.identity.delegation_digest = digest("delegation", &f.proposal["delegation"]).unwrap();
    let schema = json!({"type":"object","additionalProperties":false,"properties":{"available_replicas":{"type":"integer"},"minimum_available":{"type":"integer"},"contract_generation":{"type":"string"},"satisfied":{"type":"boolean"}},"required":["available_replicas","minimum_available","contract_generation","satisfied"]});
    let question = json!({"contract_digest":c.digest().unwrap(),"question":"Does the pinned real Kubernetes inventory satisfy the declared workload and remaining-node availability bounds? This observation is not an atomic physical guard or current SQL reservation proof."});
    f.evidence["provider_id"] = json!("fixture:kubernetes-availability-observer");
    f.evidence["question_ref"] = json!({"id":"fixture:question:kubernetes-availability","schema":"urn:kedgeflow:test:kubernetes-availability-question:1.0","digest":digest("kube-drain-question",&question).unwrap()});
    f.evidence["result_schema"] = json!({"id":"fixture:result:kubernetes-availability","schema":"urn:kedgeflow:test:kubernetes-availability-result:1.0","digest":digest("result-schema",&schema).unwrap()});
    f.evidence["result"] = json!({"available_replicas":c.workload.minimum_available,"minimum_available":c.workload.minimum_available,"contract_generation":c.generation.to_string(),"satisfied":true});
    let q = f.trust.evidence.get_mut("capacity").unwrap();
    q.provider_id = f.evidence["provider_id"].as_str().unwrap().into();
    q.question = serde_json::from_value(f.evidence["question_ref"].clone()).unwrap();
    q.result_schema_ref = serde_json::from_value(f.evidence["result_schema"].clone()).unwrap();
    q.result_schema = schema;
    q.predicates = vec![
        kedgeflow::admission::EvidencePredicate::IntegerAtLeast {
            field: "available_replicas".into(),
            minimum: c.workload.minimum_available as i64,
        },
        kedgeflow::admission::EvidencePredicate::StringEquals {
            field: "contract_generation".into(),
            expected: c.generation.to_string(),
        },
    ];
    q.obligation.predicate_digest = digest("evidence-predicate", &json!(q.predicates)).unwrap();
    f.trust.obligation_manifest_digest = f.trust.registered_obligations_digest().unwrap();
}
fn fresh(h: &mut Harness) {
    let at = now();
    h.clock.0.store(0, Ordering::SeqCst);
    h.f.proposal["created_at"] = json!(at - 4);
    h.f.proposal["baseline_state"][0]["observed_at"] = json!(at - 5);
    h.f.proposal["baseline_state"][0]["expires_at"] = json!(at + 30000);
    h.f.evidence["observed_at"] = json!(at - 3);
    h.f.evidence["expires_at"] = json!(at + 30000);
    h.f.identity.delegation_digest = digest("delegation", &h.f.proposal["delegation"]).unwrap();
}
async fn owner_now(s: &Saga, action: IntentAction, n: u64) -> saga::PhaseState {
    let proof = if action == IntentAction::Quiesce {
        None
    } else {
        Some(Box::pin(s.collect()).await.unwrap())
    };
    let head = proof
        .as_ref()
        .map(|p| p.snapshot.phase_head.clone())
        .unwrap_or(s.status().await.unwrap().head);
    let at = now();
    let expiry = if action == IntentAction::Observe {
        at + 60000
    } else {
        (at + 60000).min(s.registration().expires_at)
    };
    let intent = Intent::sign(
        IntentPayload {
            family_digest: s.registration().digest().unwrap(),
            operation_key: format!("{n:064x}"),
            expected_head: head,
            issued_at: at,
            expires_at: expiry,
            action,
            proof_digest: proof.as_ref().map(|p| p.snapshot.digest().unwrap()),
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    Box::pin(s.apply(intent, proof)).await.unwrap()
}
async fn attach_now(f: &Family, r: &kedgeflow::family::Registration, child: &str, n: u64) {
    let at = now();
    let command = kedgeflow::family::Command::sign(
        kedgeflow::family::CommandPayload {
            family_digest: r.digest().unwrap(),
            operation_key: format!("{n:064x}"),
            expected_head: f.status().await.unwrap().head,
            issued_at: at,
            expires_at: at + 30000,
            action: kedgeflow::family::Action::Attach {
                child_id: child.into(),
                parent: "root".into(),
            },
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    f.apply(command).await.unwrap();
}
struct Ready {
    _base: Harness,
    r: kedgeflow::family::Registration,
    sql: SqlInverseReady,
    physical: Harness,
    contract: kd::Contract,
    saga: Saga,
    _family: Family,
    controller: Arc<Controller>,
    api: Arc<Api>,
    api_ca: Vec<u8>,
    database: UnixDatabase,
}
async fn setup_physical() -> Ready {
    Box::pin(setup_physical_api(None)).await
}
async fn setup_physical_api(selected: Option<(kd::Contract, Vec<u8>)>) -> Ready {
    Box::pin(setup_physical_options(selected, None)).await
}
async fn setup_physical_options(
    selected: Option<(kd::Contract, Vec<u8>)>,
    gateway: Option<&str>,
) -> Ready {
    let directory = std::path::PathBuf::from(
        std::env::var("KF_KUBE_FIXTURE").expect("required owned real Kubernetes fixture path"),
    );
    let (contract, ca) = selected.unwrap_or_else(|| {
        (
            kd::Contract::decode(&std::fs::read(directory.join("contract.json")).unwrap()).unwrap(),
            std::fs::read(directory.join("ca.pem")).unwrap(),
        )
    });
    let socket =
        std::env::var("KF_POSTGRES_TEST_SOCKET").expect("required real PostgreSQL fixture");
    let at = now();
    let a = Box::pin(Blueprint::with_times(0, None, at, at))
        .await
        .unwrap();
    let mut seed = Box::pin(Harness::with_setup(gateway, at, |f| {
        configure_physical(f, &contract);
        if gateway.is_some() {
            configure_physical_provider(f, &contract);
        }
    }))
    .await
    .unwrap();
    fresh(&mut seed);
    let pr = registration_named_capacity(&seed, "physical-root", "actual-kube-drain", 0);
    let base = Box::pin(Harness::with_setup(None, at, |_| {}))
        .await
        .unwrap();
    base.clock.0.store(0, Ordering::SeqCst);
    let mut forward = native::trust_value(&seed, &pr);
    forward["namespace"] = json!(base.prefix);
    let pt = PhysicalTrust {
        operating: None,
        contract: contract.clone(),
        controller: ObserverPin {
            id: "drain-controller".into(),
            keys: public(47),
        },
        observer: ObserverPin {
            id: "physical-observer".into(),
            keys: public(49),
        },
        control_trust: control_trust(&seed, &forward, &base.prefix),
    };
    let physical_node = Node {
        child_id: "child-1".into(),
        operation_key: pr.saga.as_ref().unwrap().nodes[0].operation_key.clone(),
        depends_on: vec!["child-0".into()],
        forward_trust: forward,
        compound_trust: None,
        physical: Some(pt.clone()),
    };
    let mut r = crate::family_tests::registration_from_children_at(
        &base,
        vec![
            Child {
                id: "child-0".into(),
                reservation: a.registration.clone(),
                topology: Some(a.topology.clone()),
                inverse: Some(a.contract.clone()),
            },
            Child {
                id: "child-1".into(),
                reservation: pr.clone(),
                topology: None,
                inverse: None,
            },
        ],
        2,
        a.registration
            .saga
            .as_ref()
            .unwrap()
            .valid_from
            .max(pr.saga.as_ref().unwrap().valid_from),
        a.registration
            .saga
            .as_ref()
            .unwrap()
            .expires_at
            .min(pr.saga.as_ref().unwrap().expires_at),
    );
    r.compensation = 1;
    r.profile = saga::PROFILE.into();
    r.composition = Some(Plan {
        profile: r.profile.clone(),
        saga_id: "real-kube-drain".into(),
        nodes: vec![a.node(0, &base.prefix), physical_node],
        family_observer: ObserverPin {
            id: "family-observer".into(),
            keys: public(33),
        },
        observer: ObserverPin {
            id: "aggregate-observer".into(),
            keys: public(34),
        },
    });
    r.validate().unwrap();
    let family = Family::new(base.ledger.clone(), r.clone()).unwrap();
    family.enroll().await.unwrap();
    attach_now(&family, &r, "child-0", 100).await;
    attach_now(&family, &r, "child-1", 101).await;
    let database = UnixDatabase {
        socket_directory: socket.into(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    };
    let mut sql = Box::pin(a.enroll(0, &r, &database)).await;
    fresh(&mut sql.forward);
    fresh(&mut sql.inverse);
    let mut physical = Box::pin(Harness::with_family_options(
        gateway,
        at,
        |f| {
            configure_physical(f, &contract);
            if gateway.is_some() {
                configure_physical_provider(f, &contract);
            }
        },
        None,
        None,
        None,
        None,
        None,
        Some((
            r.namespace.clone(),
            kedgeflow::family::Selection {
                registration: r.clone(),
                child_id: "child-1".into(),
            },
        )),
    ))
    .await
    .unwrap();
    fresh(&mut physical);
    physical.ledger.enroll_reservation().await.unwrap();
    let installed = physical.bootstrap().await;
    assert!(
        physical
            .post(&physical.ack(&installed), true)
            .await
            .0
            .is_success()
    );
    let api = Arc::new(
        Api::new(
            &contract.api_origin,
            &ca,
            std::fs::read_to_string(directory.join("mutator.token")).unwrap(),
            Arc::new(SystemClock),
        )
        .unwrap(),
    );
    let read_api = Arc::new(
        Api::new(
            &contract.api_origin,
            &ca,
            std::fs::read_to_string(directory.join("observer.token")).unwrap(),
            Arc::new(SystemClock),
        )
        .unwrap(),
    );
    let observer = PhysicalObserver::new(
        pt.clone(),
        read_api,
        "key-49".into(),
        SigningKey::from_bytes(&[49; 32]),
        Arc::new(SystemClock),
    )
    .unwrap();
    let saga = Saga::new(
        Family::new(base.ledger.clone(), r.clone()).unwrap(),
        BTreeMap::from([
            (
                "child-0".into(),
                MemberObservers {
                    forward: super::observer("budget-observer", 15),
                    compound: Some(super::observer("compound-observer", 20)),
                },
            ),
            (
                "child-1".into(),
                MemberObservers {
                    forward: super::observer("budget-observer", 15),
                    compound: None,
                },
            ),
        ]),
        super::observer("aggregate-observer", 34),
    )
    .unwrap()
    .with_physical_observer("child-1".into(), observer)
    .unwrap();
    let controller = Arc::new(
        Controller::new(
            physical.ledger.clone(),
            pt,
            api.clone(),
            GrantVerifier {
                keys: keys(5),
                audience: physical.registration.scope.audience.clone(),
            },
            kedgeflow::target_token::TargetTokenVerifier::new(
                "https://broker.test/exchange".into(),
                keys(29),
            )
            .unwrap(),
            "spiffe://test/gateway".into(),
            "https://kube-target.test/accept".into(),
            "node:drain".into(),
            "key-47".into(),
            SigningKey::from_bytes(&[47; 32]),
            Arc::new(SystemClock),
        )
        .unwrap(),
    );
    Ready {
        _base: base,
        r,
        sql,
        physical,
        contract,
        saga,
        _family: family,
        controller,
        api,
        api_ca: ca,
        database,
    }
}
async fn authorize_physical(
    h: &mut Harness,
) -> (
    kedgeflow::ledger::IssuanceRecord,
    kedgeflow::recovery::Candidate,
    String,
) {
    authorize_physical_for(h, "https://kube-target.test/accept").await
}
async fn authorize_physical_for(
    h: &mut Harness,
    target: &str,
) -> (
    kedgeflow::ledger::IssuanceRecord,
    kedgeflow::recovery::Candidate,
    String,
) {
    use kedgeflow::{
        broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangeRequest},
        target_token::{ReferenceTokenMinter, TargetTokenMinter},
    };
    fresh(h);
    let at = now();
    let expires = at / 1000 + 54;
    let audience = h.f.proposal["delegation"]["token_audience"]
        .as_str()
        .unwrap()
        .to_owned();
    let subject = jwt(
        json!({"alg":"EdDSA","typ":"at+jwt","kid":"key-7"}),
        json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":audience,"exp":expires,"iat":at/1000,"scope":"capacity.reserve","cnf":{"jkt":h.f.identity.dpop_jkt}}),
        7,
    );
    h.f.proposal["delegation"] = json!({"access_token_digest":hex::encode(Sha256::digest(subject.as_bytes())),"dpop_jkt":h.f.identity.dpop_jkt,"authorization_server":h.f.identity.subject.iss,"token_audience":audience,"scopes":["capacity.reserve"],"expires_at":expires*1000});
    h.f.identity.delegation_digest = digest("delegation", &h.f.proposal["delegation"]).unwrap();
    h.f.identity.access_token = subject.clone();
    let mut p = crate::exchange::Fixture::new();
    p.snapshot.issuer = h.f.identity.subject.iss.clone();
    p.snapshot.subject_audience = audience;
    p.snapshot.subject_keys[0].kid = "key-7".into();
    p.snapshot.subject_keys[0].public_key =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    p.snapshot.registrations[0].subject = h.f.identity.subject.clone();
    p.snapshot.registrations[0].allowed_scopes =
        std::collections::BTreeSet::from(["capacity.reserve".into()]);
    p.snapshot.not_before = at;
    p.snapshot.expires_at = at + 120000;
    p.snapshot.subject_keys[0].not_before = at;
    p.snapshot.subject_keys[0].expires_at = at + 120000;
    p.snapshot.actor_keys[0].not_before = at;
    p.snapshot.actor_keys[0].expires_at = at + 120000;
    let actor=p.actor_token(json!({"alg":"ES256","typ":"JWT","kid":"actor-1"}),json!({"sub":"spiffe://test/agent","aud":"https://broker.test/exchange","exp":at/1000+60,"iat":at/1000}));
    let broker = BrokerAuthorizer::new(
        BrokerRegistration {
            gateway_workload: "spiffe://test/gateway".into(),
            target_audience: target.into(),
            target_scope: "node:drain".into(),
            max_lifetime_ms: 5000,
            tool: h.tool(),
        },
        GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        },
        h.ledger.clone(),
        Arc::new(p.provider()),
        h.clock.clone(),
    )
    .unwrap();
    Box::pin(refresh(h)).await;
    let record = Box::pin(execution_issue(h)).await.unwrap().record;
    let candidate = Box::pin(native::claim(h, &record, "original-kube-drain")).await;
    let request = ExchangeRequest {
        subject_token: subject,
        actor_token: actor,
        signed_grant: record.signed_grant.clone(),
        grant_digest: record.grant_digest.clone(),
        attempt_id: candidate.attempt_id.clone(),
        audience: target.into(),
        scope: "node:drain".into(),
    };
    let permit = Box::pin(broker.authorize(
        &request,
        &crate::exchange::workload("spiffe://test/gateway"),
    ))
    .await
    .unwrap();
    assert!(
        Box::pin(broker.authorize(
            &request,
            &crate::exchange::workload("spiffe://test/gateway")
        ))
        .await
        .is_err()
    );
    let token = ReferenceTokenMinter::new(
        "https://broker.test/exchange".into(),
        "key-29".into(),
        SigningKey::from_bytes(&[29; 32]),
    )
    .unwrap()
    .mint(&permit, now())
    .await
    .unwrap();
    Box::pin(h.ledger.authorize_dispatch(
        &candidate.grant,
        &record.grant_digest,
        &candidate.attempt_id,
    ))
    .await
    .unwrap();
    (record, candidate, token)
}
async fn reserve_now(r: &mut Ready) {
    fresh(&mut r.sql.forward);
    Box::pin(refresh(&r.sql.forward)).await;
    let h = &r.sql.forward;
    let rec = Box::pin(issue(h)).await;
    let candidate = Box::pin(native::claim(
        h,
        &rec,
        &format!("forward-{}", r.sql.pin.resource.id),
    ))
    .await;
    let dispatched = Box::pin(h.ledger.authorize_dispatch(
        &candidate.grant,
        &rec.grant_digest,
        &candidate.attempt_id,
    ))
    .await;
    assert!(
        dispatched.is_ok(),
        "SQL dispatch: {dispatched:?}; remaining grant ms={}",
        candidate.grant.expires_at - now()
    );
    let store = Arc::new(PostgresStore::new(r.database.clone()).unwrap());
    let request = kedgeflow::postgres_action::DispatchRequest {
        profile: kedgeflow::postgres_action::PROFILE.into(),
        action: kedgeflow::postgres_action::ACTION.into(),
        tenant: h.registration.tenant.clone(),
        conflict_domain: h.registration.scope.conflict_domain.clone(),
        attempt_id: candidate.attempt_id.clone(),
        grant_digest: rec.grant_digest.clone(),
        root_id: candidate.grant.root_id.clone(),
        resource: h.registration.scope.resource.clone(),
        expected_version: 241,
        fence: candidate.grant.fence,
        reservation: "booking:pilot".into(),
        gateway_workload: "spiffe://test/gateway".into(),
        expires_at: candidate.grant.expires_at as u64,
    };
    let outcome = store.apply(&request).await.unwrap();
    assert_eq!(
        outcome.status,
        kedgeflow::postgres_action::Status::Committed
    );
    let attempt = h
        .ledger
        .status(&candidate.grant, &candidate.attempt_id)
        .await
        .unwrap();
    h.ledger.finish_recorded(&candidate.grant,&attempt,"committed",&json!({"kind":"adapter_reply","result":{"resultType":"complete","isError":false,"structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":candidate.attempt_id,"grant_digest":rec.grant_digest,"resource":candidate.grant.resources[0],"fence":candidate.grant.fence,"status":"committed","post_version":outcome.post_version},"kedgeflow_postgres_outcome":outcome}}})).await.unwrap();
    kedgeflow::recovery::RecoveryWorker::new(
        h.ledger.clone(),
        GrantVerifier {
            keys: keys(5),
            audience: h.registration.scope.audience.clone(),
        },
        Arc::new(SqlForwardQuery(store)),
        "key-14".into(),
        SigningKey::from_bytes(&[14; 32]),
        "spiffe://test/outcome".into(),
        h.clock.clone(),
    )
    .unwrap()
    .recover(&candidate)
    .await
    .unwrap();
}
async fn seal_acceptance(
    r: &Ready,
    record: &kedgeflow::ledger::IssuanceRecord,
    candidate: &kedgeflow::recovery::Candidate,
    accepted: &kedgeflow::kube_drain_proof::Signed<kedgeflow::kube_drain_journal::State>,
) {
    let attempt = r
        .physical
        .ledger
        .status(&candidate.grant, &candidate.attempt_id)
        .await
        .unwrap();
    r.physical.ledger.finish_recorded(&candidate.grant,&attempt,"committed",&json!({"kind":"adapter_reply","result":{"resultType":"complete","isError":false,"structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":candidate.attempt_id,"grant_digest":record.grant_digest,"resource":candidate.grant.resources[0],"fence":candidate.grant.fence,"status":"committed","post_version":r.contract.generation},"kedgeflow_drain_acceptance":accepted}}})).await.unwrap();
    native::worker(
        &r.physical,
        candidate,
        &record.grant_digest,
        "committed",
        Arc::new(AtomicUsize::new(0)),
    )
    .recover(candidate)
    .await
    .unwrap();
}
fn admin_scenario(operation: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = std::process::Command::new(
        std::env::var("KF_KUBE_TEST_PYTHON").expect("explicit test Python"),
    )
    .current_dir(root)
    .args(["scripts/kube-drain-owned.py", operation, "--fixture"])
    .arg(std::env::var("KF_KUBE_FIXTURE").unwrap())
    .arg("--kubectl")
    .arg(std::env::var("KF_KUBE_TEST_KUBECTL").expect("explicit owned kubectl"))
    .arg("--kubeconfig")
    .arg(std::env::var("KF_KUBE_TEST_KUBECONFIG").expect("explicit private kubeconfig"))
    .arg("--context")
    .arg(std::env::var("KF_KUBE_TEST_CONTEXT").expect("explicit owned context"))
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "owned fixture availability setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
async fn restore_sql_now(r: &mut Ready) {
    let at = now();
    Box::pin(refresh(&r.sql.inverse)).await;
    Box::pin(qualify(&mut r.sql, at)).await;
    Box::pin(owner_now(&r.saga, IntentAction::PrepareCompensation, 5)).await;
    fresh(&mut r.sql.inverse);
    Box::pin(refresh(&r.sql.inverse)).await;
    let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut r.sql)).await;
    let (binding, qualification) = r
        .sql
        .inverse
        .ledger
        .compensation_dispatch_material(&candidate.grant, &rec.grant_digest, &candidate.attempt_id)
        .await
        .unwrap();
    let request = kedgeflow::compensation_target::Dispatch {
        profile: kedgeflow::compensation_target::PROFILE.into(),
        operation: "dispatch".into(),
        signed_grant: URL_SAFE_NO_PAD.encode(rec.signed_grant.as_bytes()),
        attempt_id: candidate.attempt_id.clone(),
        qualification,
        binding,
    };
    let bound = r
        .sql
        .target_trust()
        .bind(
            &r.sql.grants(),
            &kedgeflow::target_token::TargetTokenVerifier::new(
                "https://broker.test/exchange".into(),
                keys(29),
            )
            .unwrap(),
            &request,
            &token,
            now(),
        )
        .unwrap();
    let outcome = r.sql.store.apply(&bound).await.unwrap();
    assert_eq!(
        outcome.status,
        kedgeflow::postgres_action::Status::Committed
    );
    assert_eq!(outcome.post_version, Some(243));
    let h = &r.sql.inverse;
    let attempt = h
        .ledger
        .status(&candidate.grant, &candidate.attempt_id)
        .await
        .unwrap();
    h.ledger.finish_recorded(&candidate.grant,&attempt,"committed",&json!({"kind":"adapter_reply","result":{"resultType":"complete","isError":false,"structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":candidate.attempt_id,"grant_digest":rec.grant_digest,"resource":candidate.grant.resources[0],"fence":candidate.grant.fence,"status":"committed","post_version":outcome.post_version},"kedgeflow_postgres_inverse_outcome":outcome}}})).await.unwrap();
    lineage::worker(&r.sql).recover(&candidate).await.unwrap();
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 6)).await;
}
fn retain(r: &Ready, name: &str, aggregate: &saga::AggregateBundle) {
    let trust = saga::AuditTrust {
        registration: r.r.clone(),
    };
    let report = saga::verify_aggregate(aggregate, &trust).unwrap();
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let out = std::path::PathBuf::from(out).join(name);
        std::fs::create_dir_all(&out).unwrap();
        for (name, value) in [
            ("aggregate.json", json!(aggregate)),
            ("audit-trust.json", json!(trust)),
            ("verification.json", json!(report)),
        ] {
            std::fs::write(out.join(name), canonical(&value).unwrap()).unwrap();
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_closed_unstarted_acceptance_allows_fresh_original_sql_inverse() {
    let mut r = Box::pin(setup_physical()).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let (record, candidate, token) = Box::pin(authorize_physical(&mut r.physical)).await;
    let accepted = Box::pin(r.controller.accept(
        record.signed_grant.clone(),
        candidate.attempt_id.clone(),
        r.physical.f.proposal["parameters"].clone(),
        &token,
    ))
    .await
    .unwrap();
    assert!(r.controller.close_unstarted().await.is_err());
    seal_acceptance(&r, &record, &candidate, &accepted).await;
    Box::pin(owner_now(&r.saga, IntentAction::Quiesce, 3)).await;
    assert!(Box::pin(r.controller.advance()).await.is_err());
    let closed = r.controller.close_unstarted().await.unwrap();
    assert!(closed.body.closed.is_some());
    assert!(closed.body.steps.is_empty());
    assert!(
        r.controller
            .close_absent(&record.signed_grant, &candidate.attempt_id)
            .await
            .is_err()
    );
    assert_eq!(
        r.controller.advance().await.unwrap().digest().unwrap(),
        closed.digest().unwrap()
    );
    let summary = r.saga.collect().await.unwrap().verify(&r.r).unwrap();
    assert_eq!(summary["child-1"].forward, saga::ForwardState::NoEffect);
    assert_eq!(
        summary["child-1"].physical_status.as_deref(),
        Some("no_physical_effect")
    );
    restore_sql_now(&mut r).await;
    let aggregate = r
        .saga
        .export(&super::observer("family-observer", 33))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.r.clone(),
        },
    )
    .unwrap();
    assert_eq!(report.status, "compensated");
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    let row = r.sql.admin.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2", &[&r.sql.pin.tenant, &r.sql.pin.resource.id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 243);
    assert_eq!(row.get::<_, String>(1), "free");
    retain(&r, "kube-drain-no-effect", &aggregate);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_sql_predecessor_native_acceptance_and_observed_completion() {
    let mut r = Box::pin(setup_physical()).await;
    assert!(Box::pin(execution_issue(&r.physical)).await.is_err());
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 1)).await;
    assert!(Box::pin(execution_issue(&r.physical)).await.is_err());
    Box::pin(reserve_now(&mut r)).await;
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 2)).await;
    let (record, candidate, token) = Box::pin(authorize_physical(&mut r.physical)).await;
    let accepted = Box::pin(r.controller.accept(
        record.signed_grant.clone(),
        candidate.attempt_id.clone(),
        r.physical.f.proposal["parameters"].clone(),
        &token,
    ))
    .await
    .unwrap();
    assert!(accepted.body.steps.is_empty());
    seal_acceptance(&r, &record, &candidate, &accepted).await;
    let before = Box::pin(r.saga.export(&super::observer("family-observer", 33)))
        .await
        .unwrap();
    let trust = saga::AuditTrust {
        registration: r.r.clone(),
    };
    let report = saga::verify_aggregate(&before, &trust).unwrap();
    assert_eq!(report.status, "unresolved");
    assert_eq!(
        report.nodes["child-1"].physical_status.as_deref(),
        Some("accepted")
    );
    let cordon = Box::pin(r.controller.advance()).await.unwrap();
    assert_eq!(cordon.body.steps.len(), 1);
    assert!(
        (200..300).contains(&cordon.body.steps[0].response.as_ref().unwrap().http_status),
        "cordon response: {:?}",
        cordon.body.steps[0].response
    );
    admin_scenario("block");
    Box::pin(refresh(&r.physical)).await;
    let blocked = Box::pin(r.controller.advance()).await.unwrap();
    assert_eq!(blocked.body.steps.len(), 2);
    assert_eq!(
        blocked.body.steps[1].response.as_ref().unwrap().http_status,
        429
    );
    let inventory = r.api.inventory(&r.contract).await.unwrap();
    assert_eq!(
        blocked
            .body
            .physical_status(&r.contract, &inventory)
            .unwrap(),
        "blocked"
    );
    let held = r.saga.collect().await.unwrap().verify(&r.r).unwrap();
    assert_eq!(held["child-1"].forward, saga::ForwardState::Unknown);
    assert_eq!(held["child-0"].forward, saga::ForwardState::Committed);
    admin_scenario("unblock");
    Box::pin(refresh(&r.physical)).await;
    let evict = Box::pin(r.controller.advance()).await.unwrap();
    assert_eq!(evict.body.steps.len(), 3);
    assert!((200..300).contains(&evict.body.steps[2].response.as_ref().unwrap().http_status));
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let i = r.api.inventory(&r.contract).await.unwrap();
        if evict.body.physical_status(&r.contract, &i).unwrap() == "observed_completed" {
            break;
        }
        assert!(std::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Box::pin(owner_now(&r.saga, IntentAction::Observe, 3)).await;
    let aggregate = Box::pin(r.saga.export(&super::observer("family-observer", 33)))
        .await
        .unwrap();
    let report = saga::verify_aggregate(&aggregate, &trust).unwrap();
    assert_eq!(report.status, "forward_completed");
    // An aggregate collector signature cannot replace the independent physical
    // member, its native write epoch, or its complete controller journal.
    for variant in 0..4 {
        let mut wrong = aggregate.clone();
        let m = wrong
            .evidence
            .current
            .snapshot
            .members
            .get_mut("child-1")
            .unwrap();
        match variant {
            0 => m.physical = None,
            1 => {
                let p = m.physical.as_mut().unwrap();
                p.observation.body.native_epoch = "f".repeat(64);
                p.observation = kedgeflow::kube_drain_proof::Signed::sign(
                    "physical_observation",
                    p.observation.body.clone(),
                    &r.r.composition.as_ref().unwrap().nodes[1]
                        .physical
                        .as_ref()
                        .unwrap()
                        .observer,
                    "key-49",
                    &SigningKey::from_bytes(&[49; 32]),
                )
                .unwrap();
            }
            2 => {
                let p = m.physical.as_mut().unwrap();
                p.controller.as_mut().unwrap().body.steps.clear();
            }
            _ => {
                let old = m
                    .physical
                    .as_mut()
                    .unwrap()
                    .retained_completion
                    .as_mut()
                    .unwrap();
                old.observation.body.native_epoch = "invalid".into();
                old.observation = kedgeflow::kube_drain_proof::Signed::sign(
                    "physical_observation",
                    old.observation.body.clone(),
                    &r.r.composition.as_ref().unwrap().nodes[1]
                        .physical
                        .as_ref()
                        .unwrap()
                        .observer,
                    "key-49",
                    &SigningKey::from_bytes(&[49; 32]),
                )
                .unwrap();
            }
        }
        wrong.evidence.current =
            crate::family_saga_tests::model_seal(&r.r, wrong.evidence.current.snapshot, 34);
        crate::family_saga_tests::sign_model_aggregate(&mut wrong, 34);
        assert!(
            saga::verify_aggregate(&wrong, &trust).is_err(),
            "variant {variant}"
        );
    }
    // Closed absence cannot carry a contradictory controller history or a
    // previously observed physical completion, even with valid role signatures.
    let physical_trust = r.r.composition.as_ref().unwrap().nodes[1]
        .physical
        .as_ref()
        .unwrap();
    let mut contradictory = aggregate.evidence.current.snapshot.members["child-1"]
        .physical
        .clone()
        .unwrap();
    let accepted = &contradictory.controller.as_ref().unwrap().body.accepted;
    let gate = kedgeflow::kube_drain_proof::Signed::sign(
        "closed_no_dispatch",
        kedgeflow::kube_drain_proof::NoDispatch {
            profile: kd::PROFILE.into(),
            contract_digest: r.contract.digest().unwrap(),
            operation_key: r.r.composition.as_ref().unwrap().nodes[1]
                .operation_key
                .clone(),
            grant_digest: accepted.grant_digest.clone(),
            attempt_id: accepted.attempt_id.clone(),
            closed_at: contradictory.observation.body.observed_at,
            family_head: accepted.authority.family.family_head.clone(),
            phase_head: accepted.authority.family.phase_head.clone(),
        },
        &physical_trust.controller,
        "key-47",
        &SigningKey::from_bytes(&[47; 32]),
    )
    .unwrap();
    contradictory.controller = None;
    contradictory.observation.body.controller_digest = None;
    contradictory.observation.body.gate_digest = Some(gate.digest().unwrap());
    contradictory.observation.body.inventory = None;
    contradictory.closed_absence = Some(gate);
    contradictory.observation = kedgeflow::kube_drain_proof::Signed::sign(
        "physical_observation",
        contradictory.observation.body.clone(),
        &physical_trust.observer,
        "key-49",
        &SigningKey::from_bytes(&[49; 32]),
    )
    .unwrap();
    let operation = &r.r.composition.as_ref().unwrap().nodes[1].operation_key;
    assert!(
        contradictory
            .verify_sources(physical_trust, operation, now())
            .is_err()
    );
    contradictory.control_history = None;
    assert!(
        contradictory
            .verify_sources(physical_trust, operation, now())
            .is_err()
    );
    assert_eq!(
        report.nodes["child-1"].physical_status.as_deref(),
        Some("observed_completed")
    );
    assert_eq!((report.held_forward, report.held_compensation), (2, 1));
    assert!(!report.execution_authority);
    Box::pin(owner_now(&r.saga, IntentAction::Quiesce, 4)).await;
    // Observed physical drain has no registered inverse. It cannot release the
    // committed SQL reservation by claiming an automatic physical rollback.
    let capture = Box::pin(r.saga.collect()).await.unwrap();
    let at = now();
    let intent = Intent::sign(
        IntentPayload {
            family_digest: r.r.digest().unwrap(),
            operation_key: format!("{:064x}", 5),
            expected_head: capture.snapshot.phase_head.clone(),
            issued_at: at,
            expires_at: (at + 60000).min(r.r.expires_at),
            action: IntentAction::PrepareCompensation,
            proof_digest: Some(capture.snapshot.digest().unwrap()),
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    assert!(Box::pin(r.saga.apply(intent, Some(capture))).await.is_err());
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let out = std::path::PathBuf::from(out).join("kube-drain-completed");
        std::fs::create_dir_all(&out).unwrap();
        for (name, value) in [
            ("aggregate.json", json!(aggregate)),
            ("audit-trust.json", json!(trust)),
            ("verification.json", json!(report)),
            ("controller-state.json", json!(evict)),
        ] {
            std::fs::write(out.join(name), canonical(&value).unwrap()).unwrap();
        }
    }
}

#[path = "kube_drain_process.rs"]
mod process;
