//! Actual two-resource SQL composition. All immutable catalog pins are prepared
//! before the one empty-namespace enrollment, and each original leaf retains its
//! own admission, claim, dispatch, SQL result and native recovery receipts.
use super::*;
use kedgeflow::{
    action_domain::{Lane, Selection, Topology},
    family::{Child, Family},
    family_saga::{
        self as saga, Intent, IntentAction, IntentPayload, MemberObservers, Node, ObserverPin,
        Plan, Saga,
    },
    postgres_compensation::{CompensationStore, Database, PostgresCompensationStore},
    postgres_store::{PostgresStore, ReservationStore, UnixDatabase},
};

fn configure(f: &mut Fixture, resource: &str, inverse: bool) {
    sql_execution_fixture(f, resource, inverse);
    f.proposal["qid"] = json!(format!(
        "{resource}-{}",
        if inverse { "inverse" } else { "forward" }
    ));
    f.descriptor["concurrency"]["conflict_domain"] = json!(format!("family-domain-{resource}"));
    if inverse {
        f.proposal["delegation"]["token_audience"] = json!(crate::AUD);
    }
    f.identity.delegation_digest = digest("delegation", &f.proposal["delegation"]).unwrap();
    f.repin_descriptor();
}
struct Blueprint {
    seed: Harness,
    prototype: Harness,
    registration: Registration,
    contract: Contract,
    topology: Topology,
    resource: String,
    inverse_gateway: Option<String>,
    inverse_admit: String,
    target_audience: String,
    broker_lifetime: i64,
}
impl Blueprint {
    async fn new(n: usize) -> Option<Self> {
        Self::with_links(n, None).await
    }
    async fn with_links(n: usize, links: Option<&super::agent::Links>) -> Option<Self> {
        let resource = format!("family-sql-{n}-{:x}", rand::random::<u64>());
        let seed = Box::pin(Harness::with_setup(None, NOW, |f| {
            configure(f, &resource, false)
        }))
        .await?;
        let r = registration_named(&seed, &format!("{resource}-root"), &resource);
        let mut c = contract_named(&seed, &r, &format!("{resource}-inverse"));
        let inverse_gateway = links.map(|l| l.gateway_url());
        let mut prototype = Box::pin(Harness::with_setup(
            inverse_gateway.as_deref(),
            NOW + 6000,
            |f| configure(f, &resource, true),
        ))
        .await
        .unwrap();
        let inverse_admit = links
            .map(|l| l.admit_url())
            .unwrap_or_else(|| "https://control.test/admit".into());
        prototype.tool_admission_endpoint = inverse_admit.clone();
        c.inverse_policy = prototype.registration.policy.clone();
        c.inverse_scope = prototype.registration.scope.clone();
        c.signed_inverse_ctd =
            String::from_utf8(fixture::signed("ctd", prototype.f.descriptor.clone(), 2)).unwrap();
        let mut inverse = prototype.registration.clone();
        let mut t = prototype.f.trust.clone();
        t.inverse_contract = Some(c.clone());
        inverse.trust_digest = trust_digest(&t, &keys(6), &keys(5)).unwrap();
        let topology = Topology {
            profile: kedgeflow::action_domain::PROFILE.into(),
            forward: seed.registration.clone(),
            inverse,
        };
        Some(Self {
            seed,
            prototype,
            registration: r,
            contract: c,
            topology,
            resource,
            inverse_gateway,
            inverse_admit,
            target_audience: links
                .map(|l| l.dispatch_url())
                .unwrap_or_else(|| "https://inverse-target.test/dispatch".into()),
            broker_lifetime: if links.is_some() { 3000 } else { 5000 },
        })
    }
    fn node(&self, n: usize, namespace: &str) -> Node {
        let mut forward = native::trust_value(&self.seed, &self.registration);
        forward["namespace"] = json!(namespace);
        let mut inverse =
            native::trust_value(&self.prototype, &self.registration)["lineage"].clone();
        inverse["gateway_audience"] = json!(self.prototype.registration.scope.audience);
        inverse["inverse_contract"] = json!(self.contract);
        inverse["outcome_keys"] = json!(public(19));
        inverse["source_id"] = json!("spiffe://test/inverse-outcome");
        let mut tool = self.prototype.tool();
        tool.inverse_contract = Some(self.contract.clone());
        let compound = json!({"forward":forward,"inverse":inverse,"topology":self.topology,"contract":self.contract,
            "broker":{"gateway_workload":"spiffe://test/gateway","target_audience":self.target_audience,"target_scope":"reservation:restore","max_lifetime_ms":self.broker_lifetime,"tool":tool},"observer_id":"compound-observer","observer_keys":public(20)});
        Node {
            child_id: format!("child-{n}"),
            operation_key: self.contract.forward_operation_key.clone(),
            depends_on: if n == 0 {
                vec![]
            } else {
                vec!["child-0".into()]
            },
            forward_trust: forward,
            compound_trust: Some(compound),
        }
    }
    async fn enroll(
        self,
        n: usize,
        r: &kedgeflow::family::Registration,
        database: &UnixDatabase,
    ) -> SqlInverseReady {
        let selected = kedgeflow::family::Selection {
            registration: r.clone(),
            child_id: format!("child-{n}"),
        };
        let f = Box::pin(Harness::with_family_options(
            None,
            NOW,
            |f| configure(f, &self.resource, false),
            None,
            None,
            Some((
                Selection {
                    topology: self.topology.clone(),
                    lane: Lane::Forward,
                },
                Some(r.namespace.clone()),
            )),
            None,
            None,
            Some((r.namespace.clone(), selected.clone())),
        ))
        .await
        .unwrap();
        f.ledger.enroll_reservation().await.unwrap();
        let installed = f.bootstrap().await;
        assert!(f.post(&f.ack(&installed), true).await.0.is_success());
        let q = qualifier(&f, &self.contract, &self.registration);
        q.enroll().await.unwrap();
        let mut i = Box::pin(Harness::with_family_options(
            self.inverse_gateway.as_deref(),
            NOW + 6000,
            |f| configure(f, &self.resource, true),
            None,
            None,
            Some((
                Selection {
                    topology: self.topology.clone(),
                    lane: Lane::Inverse,
                },
                Some(r.namespace.clone()),
            )),
            Some(self.contract.clone()),
            None,
            Some((r.namespace.clone(), selected)),
        ))
        .await
        .unwrap();
        i.tool_admission_endpoint = self.inverse_admit.clone();
        let installed = i.bootstrap().await;
        assert!(i.post(&i.ack(&installed), true).await.0.is_success());
        let cfg:kedgeflow::compensation_execution::ExecutionConfig=serde_json::from_value(json!({"profile":kedgeflow::compensation_execution::PROFILE,"contract":self.contract,"forward":native::trust_value(&f,&self.registration),"outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"})).unwrap();
        i.ledger = cfg.attach(i.ledger.clone()).unwrap();
        let admin = crate::sql_leaf::owner(database).await;
        admin
            .execute(
                "INSERT INTO kf_reservation.resource VALUES ($1,$2,$3,$4,241,0,'free',true)",
                &[
                    &f.registration.tenant,
                    &f.registration.scope.conflict_domain,
                    &self.resource,
                    &f.registration.scope.resource.incarnation,
                ],
            )
            .await
            .unwrap();
        let capture = json!({"tenant":f.registration.tenant,"conflict_domain":f.registration.scope.conflict_domain,"resource":f.registration.scope.resource,"baseline_version":241,"contract_digest":self.contract.digest().unwrap(),"restore_state_digest":self.contract.restore_state_digest});
        admin
            .query_one("SELECT kf_compensation.capture($1::jsonb)", &[&capture])
            .await
            .unwrap();
        let store = Arc::new(
            PostgresCompensationStore::new(Database {
                connection: UnixDatabase {
                    executor_user: "kf_inverse_executor".into(),
                    query_user: "kf_inverse_reader".into(),
                    ..database.clone()
                },
                barrier_user: "kf_inverse_barrier".into(),
            })
            .unwrap(),
        );
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
            target_audience: self.target_audience,
            target_scope: "reservation:restore".into(),
        };
        // Seed/prototype held no native state; the actual contexts above must
        // reproduce exactly the pre-enrolled public catalog.
        assert_eq!(f.registration, self.topology.forward);
        assert_eq!(i.registration, self.topology.inverse);
        SqlInverseReady {
            forward: f,
            inverse: i,
            registration: self.registration,
            contract: self.contract,
            qualifier: q,
            topology: self.topology,
            store,
            admin,
            pin,
        }
    }
}
fn observer(id: &str, n: u8) -> HistoryObserver {
    HistoryObserver::new(
        id.into(),
        format!("key-{n}"),
        SigningKey::from_bytes(&[n; 32]),
    )
    .unwrap()
}
fn collector(base: EtcdLedger, r: &kedgeflow::family::Registration) -> Saga {
    Saga::new(
        Family::new(base, r.clone()).unwrap(),
        (0..2)
            .map(|n| {
                (
                    format!("child-{n}"),
                    MemberObservers {
                        forward: observer("budget-observer", 15),
                        compound: Some(observer("compound-observer", 20)),
                    },
                )
            })
            .collect(),
        observer("aggregate-observer", 34),
    )
    .unwrap()
}
async fn transition(s: &Saga, action: IntentAction, n: u64, at: i64) -> saga::PhaseState {
    let proof = if action == IntentAction::Quiesce {
        None
    } else {
        Some(Box::pin(s.collect()).await.unwrap())
    };
    let head = match &proof {
        Some(p) => p.snapshot.phase_head.clone(),
        None => s.status().await.unwrap().head,
    };
    let intent = Intent::sign(
        IntentPayload {
            family_digest: s.registration().digest().unwrap(),
            operation_key: format!("{n:064x}"),
            expected_head: head,
            issued_at: at,
            expires_at: at + 1000,
            action,
            proof_digest: proof.as_ref().map(|p| p.snapshot.digest().unwrap()),
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    Box::pin(s.apply(intent, proof)).await.unwrap()
}
fn advance(base: &Harness, members: &[SqlInverseReady], at: i64) {
    base.clock.0.store(at, Ordering::SeqCst);
    for m in members {
        m.forward.clock.0.store(at, Ordering::SeqCst);
        m.inverse.clock.0.store(at, Ordering::SeqCst);
    }
}
async fn refresh(h: &Harness) {
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
}
async fn forward(h: &mut SqlInverseReady, database: &UnixDatabase, at: i64) {
    let f = &h.forward;
    let rec = Box::pin(issue(f)).await;
    let candidate = Box::pin(native::claim(
        f,
        &rec,
        &format!("forward-{}", h.pin.resource.id),
    ))
    .await;
    Box::pin(f.ledger.authorize_dispatch(
        &candidate.grant,
        &rec.grant_digest,
        &candidate.attempt_id,
    ))
    .await
    .unwrap();
    let store = Arc::new(PostgresStore::new(database.clone()).unwrap());
    let request = kedgeflow::postgres_action::DispatchRequest {
        profile: kedgeflow::postgres_action::PROFILE.into(),
        action: kedgeflow::postgres_action::ACTION.into(),
        tenant: f.registration.tenant.clone(),
        conflict_domain: f.registration.scope.conflict_domain.clone(),
        attempt_id: candidate.attempt_id.clone(),
        grant_digest: rec.grant_digest.clone(),
        root_id: candidate.grant.root_id.clone(),
        resource: f.registration.scope.resource.clone(),
        expected_version: 241,
        fence: candidate.grant.fence,
        reservation: "booking:pilot".into(),
        gateway_workload: "spiffe://test/gateway".into(),
        expires_at: candidate.grant.expires_at as u64,
    };
    assert_eq!(
        store.apply(&request).await.unwrap().status,
        kedgeflow::postgres_action::Status::Committed
    );
    f.clock.0.store(at + 6000, Ordering::SeqCst);
    kedgeflow::recovery::RecoveryWorker::new(
        f.ledger.clone(),
        GrantVerifier {
            keys: keys(5),
            audience: f.registration.scope.audience.clone(),
        },
        Arc::new(SqlForwardQuery(store)),
        "key-14".into(),
        SigningKey::from_bytes(&[14; 32]),
        "spiffe://test/outcome".into(),
        f.clock.clone(),
    )
    .unwrap()
    .recover(&candidate)
    .await
    .unwrap();
}
async fn qualify(h: &mut SqlInverseReady, at: i64) {
    let t = lineage::trust(h);
    let issuance: kedgeflow::ledger::IssuanceRecord = serde_json::from_slice(
        &h.forward
            .ledger
            .read_key(&format!(
                "{}/issuance/{}",
                h.forward.prefix, h.contract.forward_operation_key
            ))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let f = h
        .forward
        .ledger
        .export_reserved_lineage(
            &kedgeflow::recovery::Candidate {
                grant: native::grant(&h.forward, &issuance),
                attempt_id: format!("forward-{}", h.pin.resource.id),
            },
            &h.contract.forward_operation_key,
            &observer("budget-observer", 15),
            &t.forward,
        )
        .await
        .unwrap();
    let barrier = h
        .target_trust()
        .barrier(
            h.store.as_ref(),
            &f,
            at,
            20000,
            "key-17",
            &SigningKey::from_bytes(&[17; 32]),
        )
        .await
        .unwrap();
    let p = kedgeflow::compensation_target::applicability(
        &h.contract,
        &t.forward,
        f,
        barrier,
        at,
        "key-18",
        &SigningKey::from_bytes(&[18; 32]),
    )
    .unwrap();
    h.qualifier.qualify(p.clone()).await.unwrap();
    h.inverse.f.proposal["parameters"] = json!(p.parameters);
}
struct TwoSql {
    base: Harness,
    r: kedgeflow::family::Registration,
    members: Vec<SqlInverseReady>,
    database: UnixDatabase,
    saga: Saga,
    family: Family,
}
async fn setup(links: Option<&[super::agent::Links]>) -> Option<TwoSql> {
    let socket = match std::env::var("KF_POSTGRES_TEST_SOCKET") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_POSTGRES").as_deref(), Ok("1"));
            return None;
        }
    };
    let a = match links {
        Some(links) => Box::pin(Blueprint::with_links(0, Some(&links[0]))).await?,
        None => Box::pin(Blueprint::new(0)).await?,
    };
    let b = match links {
        Some(links) => Box::pin(Blueprint::with_links(1, Some(&links[1])))
            .await
            .unwrap(),
        None => Box::pin(Blueprint::new(1)).await.unwrap(),
    };
    let base = Harness::new().await.unwrap();
    let database = UnixDatabase {
        socket_directory: socket.into(),
        port: 5432,
        database: "postgres".into(),
        executor_user: "kf_executor".into(),
        query_user: "kf_reader".into(),
    };
    let mut r = crate::family_tests::registration_from_children(
        &base,
        [&a, &b]
            .iter()
            .enumerate()
            .map(|(n, p)| Child {
                id: format!("child-{n}"),
                reservation: p.registration.clone(),
                topology: Some(p.topology.clone()),
                inverse: Some(p.contract.clone()),
            })
            .collect(),
        2,
    );
    r.profile = saga::PROFILE.into();
    r.composition = Some(Plan {
        profile: r.profile.clone(),
        saga_id: "actual-two-sql".into(),
        nodes: vec![a.node(0, &base.prefix), b.node(1, &base.prefix)],
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
    eprintln!("family saga: protected two-contract catalog validated");
    let family = Family::new(base.ledger.clone(), r.clone()).unwrap();
    family.enroll().await.unwrap();
    eprintln!("family saga: fresh genesis enrolled");
    for n in 0..2 {
        crate::family_tests::attach(&family, &r, 100 + n, "root", &format!("child-{n}"), false)
            .await;
    }
    let members = vec![
        Box::pin(a.enroll(0, &r, &database)).await,
        Box::pin(b.enroll(1, &r, &database)).await,
    ];
    let saga = collector(base.ledger.clone(), &r);
    eprintln!("family saga: actual two-member controls/budgets/qualifiers enrolled");
    Some(TwoSql {
        base,
        r,
        members,
        database,
        saga,
        family,
    })
}
#[tokio::test]
async fn family_saga_native_two_sql_contracts_reverse_original_inverses_and_complete_aggregate() {
    let Some(TwoSql {
        base,
        r,
        mut members,
        database,
        saga,
        family: _,
    }) = Box::pin(setup(None)).await
    else {
        return;
    };
    // All budgets, controls, inverse contracts and attachments precede even the
    // first root native authority. Missing initial capture refuses admission.
    assert!(
        Box::pin(execution_issue(&members[0].forward))
            .await
            .is_err()
    );
    assert!(
        Box::pin(execution_issue(&members[1].forward))
            .await
            .is_err()
    );
    advance(&base, &members, NOW + 6000);
    let old_capture = Box::pin(saga.collect()).await.unwrap();
    Box::pin(refresh(&members[0].forward)).await;
    let stale_intent = Intent::sign(
        IntentPayload {
            family_digest: r.digest().unwrap(),
            operation_key: format!("{:064x}", 90),
            expected_head: old_capture.snapshot.phase_head.clone(),
            issued_at: NOW + 6000,
            expires_at: NOW + 7000,
            action: IntentAction::Observe,
            proof_digest: Some(old_capture.snapshot.digest().unwrap()),
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    assert!(
        Box::pin(saga.apply(stale_intent, Some(old_capture)))
            .await
            .is_err()
    );
    assert!(saga.status().await.unwrap().events.is_empty());
    Box::pin(transition(&saga, IntentAction::Observe, 1, NOW + 6000)).await;
    eprintln!("family saga: initial coherent capture retained");
    assert!(
        Box::pin(execution_issue(&members[1].forward))
            .await
            .is_err()
    );
    eprintln!("family saga: native dependent forward refused before predecessor commit");
    Box::pin(forward(&mut members[0], &database, NOW + 6000)).await;
    eprintln!("family saga: first actual SQL forward committed");
    advance(&base, &members, NOW + 12000);
    Box::pin(refresh(&members[1].forward)).await;
    Box::pin(transition(&saga, IntentAction::Observe, 2, NOW + 12000)).await;
    Box::pin(forward(&mut members[1], &database, NOW + 12000)).await;
    advance(&base, &members, NOW + 18000);
    for m in &members {
        Box::pin(refresh(&m.inverse)).await;
    }
    for m in &mut members {
        Box::pin(qualify(m, NOW + 18000)).await;
    }
    Box::pin(transition(&saga, IntentAction::Observe, 3, NOW + 18000)).await;
    Box::pin(transition(&saga, IntentAction::Quiesce, 4, NOW + 18000)).await;
    assert!(
        Box::pin(execution_issue(&members[0].inverse))
            .await
            .is_err()
    );
    Box::pin(transition(
        &saga,
        IntentAction::PrepareCompensation,
        5,
        NOW + 18000,
    ))
    .await;
    eprintln!("family saga: both SQL forwards qualified and global compensation prepared");
    assert!(
        Box::pin(execution_issue(&members[0].inverse))
            .await
            .is_err()
    );
    let mut unknown_evidence = None;
    for n in [1usize, 0] {
        Box::pin(refresh(&members[n].inverse)).await;
        let at = kedgeflow::clock::Clock::now_ms(base.clock.as_ref());
        let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut members[n])).await;
        eprintln!(
            "family saga: original inverse child-{n} freshly admitted, claimed and dispatched"
        );
        let h = &members[n];
        let (binding, qualification) = h
            .inverse
            .ledger
            .compensation_dispatch_material(
                &candidate.grant,
                &rec.grant_digest,
                &candidate.attempt_id,
            )
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
        let bound = h
            .target_trust()
            .bind(
                &h.grants(),
                &kedgeflow::target_token::TargetTokenVerifier::new(
                    "https://broker.test/exchange".into(),
                    keys(29),
                )
                .unwrap(),
                &request,
                &token,
                at,
            )
            .unwrap();
        // The original claimed inverse is unknown until the real original SQL
        // result is independently queried. Its global claim slot stays held.
        advance(&base, &members, at + 6000);
        assert_eq!(
            lineage::worker(h).recover(&candidate).await.unwrap().state,
            "unknown"
        );
        assert!(saga.status().await.unwrap().in_flight.is_some());
        if n == 1 {
            let unknown = Box::pin(saga.export(&observer("family-observer", 33)))
                .await
                .unwrap();
            let report = saga::verify_aggregate(
                &unknown,
                &saga::AuditTrust {
                    registration: r.clone(),
                },
            )
            .unwrap();
            assert_eq!(report.status, "unresolved");
            assert!(report.retained_in_flight.is_some());
            assert_eq!((report.held_forward, report.held_compensation), (2, 2));
            assert!(!report.execution_authority);
            unknown_evidence = Some(Box::new((unknown, report)));
        }
        assert_eq!(
            h.store.apply(&bound).await.unwrap().status,
            kedgeflow::postgres_action::Status::Committed
        );
        assert_eq!(h.store.apply(&bound).await.unwrap().post_version, Some(243));
        assert_eq!(
            lineage::worker(h).recover(&candidate).await.unwrap().state,
            "committed"
        );
        Box::pin(transition(
            &saga,
            IntentAction::Observe,
            6 + n as u64,
            at + 6000,
        ))
        .await;
        assert!(saga.status().await.unwrap().in_flight.is_none());
        eprintln!("family saga: original inverse child-{n} committed and globally settled");
    }
    let recreated = collector(base.ledger.clone(), &r);
    let aggregate = Box::pin(recreated.export(&observer("family-observer", 33)))
        .await
        .unwrap();
    let report = saga::verify_aggregate(
        &aggregate,
        &saga::AuditTrust {
            registration: r.clone(),
        },
    )
    .unwrap();
    assert_eq!(report.status, "compensated");
    assert!(!report.execution_authority);
    assert_eq!(report.held_forward, 2);
    assert_eq!(report.held_compensation, 2);
    for case in [
        "missing-member",
        "missing-proof",
        "original-claim-head",
        "native-outcome",
    ] {
        let mut wrong = aggregate.clone();
        match case {
            "missing-member" => {
                wrong.evidence.current.snapshot.members.remove("child-1");
            }
            "missing-proof" => {
                wrong.evidence.proofs.pop_first();
            }
            "original-claim-head" => {
                wrong
                    .evidence
                    .current
                    .snapshot
                    .members
                    .get_mut("child-1")
                    .unwrap()
                    .composition_bindings
                    .as_mut()
                    .unwrap()
                    .get_mut("inverse/claim")
                    .unwrap()
                    .view
                    .phase_head = aggregate.evidence.phase.head.clone();
            }
            "native-outcome" => {
                wrong
                    .evidence
                    .current
                    .snapshot
                    .members
                    .get_mut("child-1")
                    .unwrap()
                    .compound
                    .as_mut()
                    .unwrap()
                    .evidence
                    .inverse
                    .as_mut()
                    .unwrap()
                    .lineage
                    .as_mut()
                    .unwrap()
                    .outcomes
                    .receipts
                    .pop();
            }
            _ => unreachable!(),
        }
        wrong.evidence.current =
            crate::family_saga_tests::model_seal(&r, wrong.evidence.current.snapshot, 34);
        crate::family_saga_tests::sign_model_aggregate(&mut wrong, 34);
        assert!(
            saga::verify_aggregate(
                &wrong,
                &saga::AuditTrust {
                    registration: r.clone()
                }
            )
            .is_err(),
            "{case}"
        );
    }
    let files = tempfile::tempdir().unwrap();
    let bundle = files.path().join("aggregate.json");
    let trust = files.path().join("trust.json");
    std::fs::write(&bundle, canonical(&json!(aggregate)).unwrap()).unwrap();
    std::fs::write(
        &trust,
        canonical(&json!(saga::AuditTrust {
            registration: r.clone()
        }))
        .unwrap(),
    )
    .unwrap();
    let verified = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-family-saga"))
            .args(["verify", "--bundle"])
            .arg(&bundle)
            .arg("--trust")
            .arg(&trust)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let public: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(public["status"], "compensated");
    assert_eq!(public["execution_authority"], false);
    let mut rows = Vec::new();
    for m in &members {
        let row=m.admin.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&m.pin.tenant,&m.pin.resource.id]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 243);
        assert_eq!(row.get::<_, String>(1), "free");
        rows.push(json!({"resource":m.pin.resource,"version":row.get::<_,i64>(0),"reservation":row.get::<_,String>(1),"inverse_spend":m.inverse.ledger.compensation_spend().await.unwrap()}));
    }
    // Preserve complete public original execution evidence in a fresh record
    // when the conformance runner supplies its owned output directory.
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let out = std::path::PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        let out = out.join("family-saga-two-sql");
        std::fs::create_dir(&out).unwrap();
        let (unknown, unknown_report) = *unknown_evidence.unwrap();
        for (name, value) in [
            ("aggregate.json", json!(aggregate)),
            ("unknown-aggregate.json", json!(unknown)),
            ("unknown-verification.json", json!(unknown_report)),
            (
                "audit-trust.json",
                json!(saga::AuditTrust {
                    registration: r.clone()
                }),
            ),
            ("verification.json", json!(report)),
            (
                "target-rows.json",
                json!({"scope":"disposable real SQL, native fixture clock and generated custody; no deployed acceptance","rows":rows}),
            ),
        ] {
            std::fs::write(out.join(name), canonical(&value).unwrap()).unwrap();
        }
    }
}

// These clients are fully validated against the original forward catalog but
// forwards execute through the native fixture above. This test qualifies the
// official SDK inverse runner, not SDK forward or owner-command execution.
fn forward_client(h: &SqlInverseReady, inverse: &Value, directory: &std::path::Path) -> Value {
    let f = &h.forward;
    let mut cfg = inverse.clone();
    cfg["qid"] = f.f.proposal["qid"].clone();
    cfg["proposalTemplate"] = f.f.proposal.clone();
    cfg["storeDirectory"] = json!(directory);
    cfg["tls"] =
        json!({"ca":f.agent_pki.ca,"cert":f.agent_pki.client,"key":f.agent_pki.client_key});
    cfg["config"]["gatewayUrl"] = json!(f.registration.scope.audience);
    cfg["config"]["delegationAudience"] = f.f.proposal["delegation"]["token_audience"].clone();
    cfg["config"]["descriptor"] =
        json!(String::from_utf8(fixture::signed("ctd", f.f.descriptor.clone(), 2)).unwrap());
    cfg["config"]["descriptorDigest"] = json!(f.f.trust.descriptor_digest);
    cfg["config"]
        .as_object_mut()
        .unwrap()
        .remove("compensation");
    cfg
}

#[tokio::test]
async fn family_saga_official_sdk_two_sql_inverses_lost_commit_reply_and_restart_after_root_stop() {
    use kedgeflow::clock::Clock;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !root
        .join("tests/sdk/node_modules/@modelcontextprotocol/client/package.json")
        .is_file()
    {
        assert_ne!(std::env::var("KF_REQUIRE_SDK").as_deref(), Ok("1"));
        eprintln!("SKIP family saga SDK: official pinned client absent");
        return;
    }
    let links = vec![
        super::agent::Links::new().await,
        super::agent::Links::new().await,
    ];
    let Some(TwoSql {
        base,
        r,
        mut members,
        database,
        saga,
        family,
    }) = Box::pin(setup(Some(&links))).await
    else {
        return;
    };
    advance(&base, &members, NOW + 6000);
    Box::pin(refresh(&members[0].forward)).await;
    Box::pin(transition(&saga, IntentAction::Observe, 1, NOW + 6000)).await;
    Box::pin(forward(&mut members[0], &database, NOW + 6000)).await;
    advance(&base, &members, NOW + 12000);
    Box::pin(refresh(&members[1].forward)).await;
    Box::pin(transition(&saga, IntentAction::Observe, 2, NOW + 12000)).await;
    Box::pin(forward(&mut members[1], &database, NOW + 12000)).await;
    advance(&base, &members, NOW + 18000);
    for m in &members {
        Box::pin(refresh(&m.inverse)).await;
    }
    for m in &mut members {
        Box::pin(qualify(m, NOW + 18000)).await;
    }
    Box::pin(transition(&saga, IntentAction::Observe, 3, NOW + 18000)).await;
    Box::pin(transition(&saga, IntentAction::Quiesce, 4, NOW + 18000)).await;
    Box::pin(transition(
        &saga,
        IntentAction::PrepareCompensation,
        5,
        NOW + 18000,
    ))
    .await;
    let mut serving = Vec::new();
    for (n, link) in links.into_iter().enumerate() {
        serving.push(Box::pin(super::agent::serve(&members[n], link, n == 0)).await);
    }
    let directory = tempfile::tempdir().unwrap();
    let member_config:serde_json::Map<String,Value> = members.iter().enumerate().map(|(n,h)| {
        (format!("child-{n}"),json!({"inverse":serving[n].config,"forward":forward_client(h,&serving[n].config,&directory.path().join(format!("forward-{n}")))}))
    }).collect();
    let mut cfg = json!({"registration":r,"members":member_config,"runnerStoreDirectory":directory.path().join("runner"),"preparedDirectory":directory.path().join("prepared")});
    let file = directory.path().join("family-agent.json");
    let mut wire_records = Vec::new();
    for n in [1usize, 0] {
        Box::pin(refresh(&members[n].inverse)).await;
        let at = base.clock.now_ms();
        cfg["child"] = json!(format!("child-{n}"));
        cfg["mode"] = json!("normal");
        cfg["expectedState"] = json!(if n == 0 { "unknown" } else { "committed" });
        cfg["state"] = json!(saga.status().await.unwrap());
        let child = format!("child-{n}");
        cfg["members"][&child]["inverse"]["now"] = json!(at);
        cfg["members"][&child]["inverse"]["token"] = json!(super::agent::token(
            &members[n],
            "capacity.reserve kf.admit kf.issue kf.status kf.evidence",
            at
        ));
        std::fs::write(&file, canonical(&cfg).unwrap()).unwrap();
        let node = || async {
            let out = tokio::time::timeout(
                Duration::from_secs(60),
                tokio::process::Command::new(
                    std::env::var("KF_SDK_NODE").unwrap_or_else(|_| "node".into()),
                )
                .arg(root.join("tests/sdk/family-saga-live.mjs"))
                .arg(&file)
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
            eprintln!(
                "family saga: official SDK child-{n} {} {}",
                result["mode"], result["state"]
            );
            result
        };
        let first = node().await;
        let h = &members[n];
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
            attempt_id: first["attempt_id"].as_str().unwrap().into(),
        };
        advance(&base, &members, at + 6000);
        if n == 0 {
            let command = kedgeflow::family::Command::sign(
                kedgeflow::family::CommandPayload {
                    family_digest: r.digest().unwrap(),
                    operation_key: format!("{:064x}", 200),
                    expected_head: family.status().await.unwrap().head,
                    issued_at: at + 6000,
                    expires_at: at + 7000,
                    action: kedgeflow::family::Action::Stop {
                        branch_id: "root".into(),
                    },
                },
                "owner",
                &SigningKey::from_bytes(&[31; 32]),
            )
            .unwrap();
            family.apply(command).await.unwrap();
            assert!(!family.status().await.unwrap().active);
        }
        let worker = kedgeflow::recovery::RecoveryWorker::new(
            h.inverse.ledger.clone(),
            h.grants(),
            serving[n].query.clone(),
            "key-19".into(),
            SigningKey::from_bytes(&[19; 32]),
            "spiffe://test/inverse-outcome".into(),
            h.inverse.clock.clone(),
        )
        .unwrap();
        assert_eq!(worker.recover(&candidate).await.unwrap().state, "committed");
        cfg["mode"] = json!("resume");
        cfg["expectedState"] = json!("committed");
        cfg["members"][&child]["inverse"]["now"] = json!(at + 6000);
        cfg["members"][&child]["inverse"]["token"] =
            json!(super::agent::token(h, "kf.status", at + 6000));
        std::fs::write(&file, canonical(&cfg).unwrap()).unwrap();
        let again = node().await;
        assert_eq!(first["attempt_id"], again["attempt_id"]);
        assert_eq!(first["grant_digest"], again["grant_digest"]);
        assert_eq!(serving[n].counts(), (1, 1, 1, usize::from(n == 0)));
        wire_records.extend([first, again]);
        Box::pin(transition(
            &saga,
            IntentAction::Observe,
            10 + n as u64,
            at + 6000,
        ))
        .await;
        assert!(saga.status().await.unwrap().in_flight.is_none());
    }
    let aggregate =
        Box::pin(collector(base.ledger.clone(), &r).export(&observer("family-observer", 33)))
            .await
            .unwrap();
    let trust = saga::AuditTrust { registration: r };
    let report = saga::verify_aggregate(&aggregate, &trust).unwrap();
    assert_eq!(report.status, "compensated");
    assert!(!report.family_active);
    assert!(!report.execution_authority);
    assert_eq!((report.held_forward, report.held_compensation), (2, 2));
    let mut rows = Vec::new();
    for m in &members {
        let row=m.admin.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&m.pin.tenant,&m.pin.resource.id]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 243);
        assert_eq!(row.get::<_, String>(1), "free");
        rows.push(json!({"resource":m.pin.resource,"version":row.get::<_,i64>(0),"reservation":row.get::<_,String>(1)}));
    }
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let out = std::path::PathBuf::from(out).join("family-saga-sdk-two-sql");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        std::fs::create_dir(&out).unwrap();
        for (name, value) in [
            ("aggregate.json", json!(aggregate)),
            ("audit-trust.json", json!(trust)),
            ("verification.json", json!(report)),
            ("wire.json", json!(wire_records)),
            ("target-rows.json", json!(rows)),
        ] {
            std::fs::write(out.join(name), canonical(&value).unwrap()).unwrap();
        }
    }
}

struct PausedTxn {
    endpoint: String,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    _server: crate::live_agent::Running,
}
impl PausedTxn {
    async fn new(stage: &'static str) -> Self {
        use axum::{Json, Router, response::IntoResponse, routing::post};
        use std::sync::atomic::AtomicBool;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let once = Arc::new(AtomicBool::new(true));
        let upstream = std::env::var("ETCD_ENDPOINT").unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post({
                let entered = entered.clone();
                let release = release.clone();
                move |Json(value): Json<Value>| {
                    let entered = entered.clone();
                    let release = release.clone();
                    let once = once.clone();
                    let upstream = upstream.clone();
                    async move {
                        let decode = |v: &Value| {
                            v.as_str()
                                .and_then(|s| STANDARD.decode(s).ok())
                                .map(|b| String::from_utf8_lossy(&b).into_owned())
                        };
                        let selected = if stage == "capture" {
                            value["success"].as_array().is_some_and(Vec::is_empty)
                                && value["compare"].as_array().is_some_and(|c| {
                                    c.iter()
                                        .filter(|c| {
                                            decode(&c["key"]).is_some_and(|k| {
                                                k.contains("/inverse-contracts/")
                                                    && k.ends_with("/contract")
                                            })
                                        })
                                        .count()
                                        == 2
                                })
                        } else {
                            value["success"].as_array().is_some_and(|ops| {
                                ops.iter().any(|op| {
                                    if stage == "dispatch" {
                                        decode(&op["request_put"]["value"]).as_deref()
                                            == Some("dispatch_authorized")
                                    } else {
                                        decode(&op["request_put"]["key"])
                                            .is_some_and(|k| k.contains(&format!("/{stage}/")))
                                    }
                                })
                            })
                        };
                        if selected && once.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
                        let response = reqwest::Client::new()
                            .post(format!("{upstream}/v3/kv/txn"))
                            .json(&value)
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
        let server = crate::live_agent::Running(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }));
        Self {
            endpoint,
            entered,
            release,
            _server: server,
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_saga_native_final_capture_and_forward_authority_races_refuse_stale_cas() {
    for stage in ["capture", "admission", "issuance", "attempts", "dispatch"] {
        let Some(TwoSql {
            base,
            r,
            mut members,
            saga,
            family,
            ..
        }) = Box::pin(setup(None)).await
        else {
            return;
        };
        advance(&base, &members, NOW + 6000);
        Box::pin(refresh(&members[0].forward)).await;
        Box::pin(transition(&saga, IntentAction::Observe, 1, NOW + 6000)).await;
        let rec = if matches!(stage, "attempts" | "dispatch") {
            Some(Box::pin(issue(&members[0].forward)).await)
        } else {
            None
        };
        let candidate = if stage == "dispatch" {
            Some(
                Box::pin(native::claim(
                    &members[0].forward,
                    rec.as_ref().unwrap(),
                    "race-original",
                ))
                .await,
            )
        } else {
            None
        };
        let proxy = PausedTxn::new(stage).await;
        let proxy_ledger = EtcdLedger::new(reqwest::Client::new(), &proxy.endpoint, &base.prefix)
            .unwrap()
            .with_clock(base.clock.clone());
        let operation = if stage == "capture" {
            let s = collector(proxy_ledger, &r);
            tokio::spawn(async move { Box::pin(s.collect()).await.map(|_| ()) })
        } else {
            let mut h = members.remove(0).forward;
            h.ledger = kedgeflow::family::Selection {
                registration: r.clone(),
                child_id: "child-0".into(),
            }
            .attach(
                proxy_ledger
                    .requiring_control(Some(h.registration.trust_digest.clone()))
                    .with_action_domain(Selection {
                        topology: r.children[0].topology.clone().unwrap(),
                        lane: Lane::Forward,
                    })
                    .unwrap(),
            )
            .unwrap();
            tokio::spawn(async move {
                match stage {
                    "attempts" => {
                        let rec = rec.unwrap();
                        let grant = native::grant(&h, &rec);
                        Box::pin(h.ledger.claim_recorded(
                            &grant,
                            &rec.grant_digest,
                            "raced",
                            &kedgeflow::recovery::ExecutionRecord {
                                signed_grant: rec.signed_grant,
                                tool: "node_drain".into(),
                                parameters: h.f.proposal["parameters"].clone(),
                            },
                        ))
                        .await
                        .map(|_| ())
                    }
                    "dispatch" => {
                        let rec = rec.unwrap();
                        let c = candidate.unwrap();
                        Box::pin(h.ledger.authorize_dispatch(
                            &c.grant,
                            &rec.grant_digest,
                            &c.attempt_id,
                        ))
                        .await
                    }
                    _ => Box::pin(execution_issue(&h)).await.map(|_| ()),
                }
            })
        };
        tokio::time::timeout(Duration::from_secs(60), proxy.entered.notified())
            .await
            .expect(stage);
        if stage == "capture" {
            // A real unrelated native control write advances the capture epoch.
            Box::pin(refresh(&members[1].forward)).await;
        } else if matches!(stage, "admission" | "attempts") {
            Box::pin(transition(&saga, IntentAction::Quiesce, 2, NOW + 6000)).await;
        } else {
            crate::family_tests::stop(&family, &r, 2, "root").await;
        }
        proxy.release.notify_one();
        assert!(
            operation.await.unwrap().is_err(),
            "stale {stage} CAS accepted"
        );
        eprintln!("family saga: raced {stage} final CAS refused");
    }
}

async fn prepare_two(
    base: &Harness,
    members: &mut [SqlInverseReady],
    database: &UnixDatabase,
    saga: &Saga,
) {
    advance(base, members, NOW + 6000);
    Box::pin(refresh(&members[0].forward)).await;
    Box::pin(transition(saga, IntentAction::Observe, 1, NOW + 6000)).await;
    Box::pin(forward(&mut members[0], database, NOW + 6000)).await;
    advance(base, members, NOW + 12000);
    Box::pin(refresh(&members[1].forward)).await;
    Box::pin(transition(saga, IntentAction::Observe, 2, NOW + 12000)).await;
    Box::pin(forward(&mut members[1], database, NOW + 12000)).await;
    advance(base, members, NOW + 18000);
    for m in members.iter() {
        Box::pin(refresh(&m.inverse)).await;
    }
    for m in members.iter_mut() {
        Box::pin(qualify(m, NOW + 18000)).await;
    }
    Box::pin(transition(saga, IntentAction::Observe, 3, NOW + 18000)).await;
    Box::pin(transition(saga, IntentAction::Quiesce, 4, NOW + 18000)).await;
    Box::pin(transition(
        saga,
        IntentAction::PrepareCompensation,
        5,
        NOW + 18000,
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_saga_competing_original_inverse_claims_hold_one_unknown_global_slot() {
    let Some(TwoSql {
        base,
        r,
        mut members,
        database,
        saga,
        ..
    }) = Box::pin(setup(None)).await
    else {
        return;
    };
    Box::pin(prepare_two(&base, &mut members, &database, &saga)).await;
    let (rec, candidate, _) = Box::pin(sql_inverse_authorize_plan(&mut members[1], true)).await;
    let h = &members[1];
    assert_eq!(
        h.inverse
            .ledger
            .compensation_spend()
            .await
            .unwrap()
            .attempt_id
            .as_deref(),
        Some(candidate.attempt_id.as_str())
    );
    assert_eq!(
        saga.status()
            .await
            .unwrap()
            .in_flight
            .as_ref()
            .unwrap()
            .grant_digest,
        rec.grant_digest
    );
    // No target call is made. A missing original target result is unknown,
    // never evidence that the operation or a possible dispatch had no effect.
    advance(&base, &members, NOW + 24000);
    assert_eq!(
        lineage::worker(h).recover(&candidate).await.unwrap().state,
        "unknown"
    );
    let aggregate = Box::pin(saga.export(&observer("family-observer", 33)))
        .await
        .unwrap();
    let report = saga::verify_aggregate(&aggregate, &saga::AuditTrust { registration: r }).unwrap();
    assert_eq!(report.status, "unresolved");
    assert!(report.retained_in_flight.is_some());
    assert_eq!((report.held_forward, report.held_compensation), (2, 2));
    assert!(
        Box::pin(execution_issue(&members[0].inverse))
            .await
            .is_err()
    );
    let projected = saga.status().await.unwrap();
    assert_eq!(
        projected.in_flight.unwrap().attempt_id,
        candidate.attempt_id
    );
    assert!(!report.execution_authority);
}

#[tokio::test]
async fn family_saga_real_sql_inverse_guard_failure_blocks_ancestor_and_retains_costs() {
    let Some(TwoSql {
        base,
        r,
        mut members,
        database,
        saga,
        ..
    }) = Box::pin(setup(None)).await
    else {
        return;
    };
    Box::pin(prepare_two(&base, &mut members, &database, &saga)).await;
    let (rec, candidate, token) = Box::pin(sql_inverse_authorize(&mut members[1])).await;
    let h = &members[1];
    let (binding, qualification) = h
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
    let bound = h
        .target_trust()
        .bind(
            &h.grants(),
            &kedgeflow::target_token::TargetTokenVerifier::new(
                "https://broker.test/exchange".into(),
                keys(29),
            )
            .unwrap(),
            &request,
            &token,
            NOW + 18000,
        )
        .unwrap();
    // An actual concurrent resource owner changes the row after qualification.
    // The original inverse must preserve that new state, not restore over it.
    assert_eq!(h.admin.execute("UPDATE kf_reservation.resource SET version=version+1,reservation='other-owner' WHERE tenant=$1 AND resource_id=$2",&[&h.pin.tenant,&h.pin.resource.id]).await.unwrap(),1);
    let rejected = h.store.apply(&bound).await.unwrap();
    assert_eq!(
        rejected.status,
        kedgeflow::postgres_action::Status::GuardRejected
    );
    let attempt = h
        .inverse
        .ledger
        .status(&candidate.grant, &candidate.attempt_id)
        .await
        .unwrap();
    h.inverse.ledger.finish_recorded(
        &candidate.grant, &attempt, "state_guard_violation",
        &json!({"kind":"adapter_reply","result":{"resultType":"complete","isError":true,"structuredContent":{"kedgeflow_terminal_receipt":{"attempt_id":candidate.attempt_id,"grant_digest":rec.grant_digest,"resource":candidate.grant.resources[0],"fence":candidate.grant.fence,"status":"state_guard_violation","post_version":rejected.post_version},"kedgeflow_postgres_inverse_outcome":rejected}}}),
    ).await.unwrap();
    advance(&base, &members, NOW + 24000);
    assert_eq!(
        lineage::worker(h).recover(&candidate).await.unwrap().state,
        "state_guard_violation"
    );
    Box::pin(transition(&saga, IntentAction::Observe, 6, NOW + 24000)).await;
    assert!(saga.status().await.unwrap().in_flight.is_none());
    assert!(
        Box::pin(execution_issue(&members[0].inverse))
            .await
            .is_err()
    );
    let aggregate = Box::pin(saga.export(&observer("family-observer", 33)))
        .await
        .unwrap();
    let trust = saga::AuditTrust { registration: r };
    let report = saga::verify_aggregate(&aggregate, &trust).unwrap();
    assert_eq!(report.status, "compensation_failed");
    assert_eq!(report.nodes["child-1"].inverse, saga::InverseState::Failed);
    assert!(report.nodes["child-1"].inverse_receipt.is_some());
    // Failure is observable without converting native unknown consumption into
    // a refundable allowance or a proven-no-effect record.
    let spend = h.inverse.ledger.compensation_spend().await.unwrap();
    assert_eq!(
        spend.state,
        kedgeflow::coordination::ReservationState::Unknown
    );
    assert!(spend.receipt_digest.is_none());
    assert_eq!((report.held_forward, report.held_compensation), (2, 2));
    assert!(!report.execution_authority);
    let mut rows = Vec::new();
    for (n, m) in members.iter().enumerate() {
        let row=m.admin.query_one("SELECT version,reservation FROM kf_reservation.resource WHERE tenant=$1 AND resource_id=$2",&[&m.pin.tenant,&m.pin.resource.id]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), if n == 0 { 242 } else { 243 });
        assert_eq!(
            row.get::<_, String>(1),
            if n == 0 {
                "booking:pilot"
            } else {
                "other-owner"
            }
        );
        rows.push(json!({"resource":m.pin.resource,"version":row.get::<_,i64>(0),"reservation":row.get::<_,String>(1)}));
    }
    if let Some(out) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let out = std::path::PathBuf::from(out).join("family-saga-sql-failure");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        std::fs::create_dir(&out).unwrap();
        for (name, value) in [
            ("aggregate.json", json!(aggregate)),
            ("audit-trust.json", json!(trust)),
            ("verification.json", json!(report)),
            (
                "target-rows.json",
                json!({"scope":"actual native authority and SQL store; original guard-rejected reply retained as adapter evidence; negative query alone remains unknown","rows":rows}),
            ),
        ] {
            std::fs::write(out.join(name), canonical(&value).unwrap()).unwrap();
        }
    }
}

#[tokio::test]
async fn family_saga_cached_original_qualification_still_refuses_fresh_admission_at_expiry() {
    let Some(TwoSql {
        base,
        r,
        mut members,
        database,
        saga,
        ..
    }) = Box::pin(setup(None)).await
    else {
        return;
    };
    Box::pin(prepare_two(&base, &mut members, &database, &saga)).await;
    // Preparation and repeated collection warm the exact historical replay.
    Box::pin(saga.collect()).await.unwrap();
    let at = members[1].qualifier.history().await.unwrap()[0]
        .verification
        .valid_until;
    assert!(at < r.expires_at);
    advance(&base, &members, at);
    let operation = members[1].contract.inverse_operation_key.clone();
    let h = &mut members[1].inverse;
    Box::pin(refresh(h)).await;
    h.f.proposal["created_at"] = json!(at);
    h.f.proposal["baseline_state"][0]["observed_at"] = json!(at);
    h.f.proposal["baseline_state"][0]["expires_at"] = json!(at + 10000);
    h.f.evidence["observed_at"] = json!(at);
    h.f.evidence["expires_at"] = json!(at + 10000);
    let clock = Time(at);
    let mut packet = h.f.packet();
    let mut manifest: Value = serde_json::from_slice(&packet.manifest).unwrap();
    manifest["payload"]["assembled_at"] = json!(at);
    packet.manifest = fixture::signed("manifest", manifest["payload"].clone(), 3);
    let inputs =
        h.f.trust
            .verify_inputs(&h.f.identity, packet.borrowed(), &clock)
            .unwrap();
    let controller = AdmissionController::new(
        CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
        "key-6".into(),
        SigningKey::from_bytes(&[6; 32]),
    )
    .unwrap();
    let prepared = controller.prepare(&inputs, &clock).unwrap();
    let error = Box::pin(h.ledger.admit(&prepared, &clock))
        .await
        .expect_err("expired historical cache admitted inverse");
    assert!(
        error
            .to_string()
            .contains("inverse contract, original effect or qualification proof refused"),
        "{error}"
    );
    assert!(
        h.ledger
            .read_key(&format!("{}/issuance/{}", h.prefix, operation))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_saga_original_inverse_issuance_readset_refuses_concurrent_qualification() {
    let Some(TwoSql {
        base,
        r,
        mut members,
        database,
        saga,
        ..
    }) = Box::pin(setup(None)).await
    else {
        return;
    };
    Box::pin(prepare_two(&base, &mut members, &database, &saga)).await;
    let member = members.remove(1);
    let original = member.qualifier.history().await.unwrap()[0].proof.clone();
    let target = member.target_trust();
    let forward_clock = member.forward.clock.clone();
    let direct = member.inverse.ledger.clone();
    let mut h = member.inverse;
    let inverse_clock = h.clock.clone();
    let proxy = PausedTxn::new("issuance").await;
    let selected = kedgeflow::family::Selection {
        registration: r.clone(),
        child_id: "child-1".into(),
    }
    .attach(
        EtcdLedger::new(reqwest::Client::new(), &proxy.endpoint, &base.prefix)
            .unwrap()
            .with_clock(h.clock.clone())
            .requiring_control(Some(h.registration.trust_digest.clone()))
            .with_action_domain(Selection {
                topology: member.topology.clone(),
                lane: Lane::Inverse,
            })
            .unwrap(),
    )
    .unwrap();
    let cfg:kedgeflow::compensation_execution::ExecutionConfig=serde_json::from_value(json!({"profile":kedgeflow::compensation_execution::PROFILE,"contract":member.contract,"forward":native::trust_value(&member.forward,&member.registration),"outcome_keys":public(19),"source_id":"spiffe://test/inverse-outcome"})).unwrap();
    h.ledger = cfg.attach(selected).unwrap();
    let operation = tokio::spawn(async move { Box::pin(execution_issue(&h)).await });
    tokio::time::timeout(Duration::from_secs(60), proxy.entered.notified())
        .await
        .unwrap();
    let at = NOW + 18001;
    base.clock.0.store(at, Ordering::SeqCst);
    forward_clock.0.store(at, Ordering::SeqCst);
    inverse_clock.0.store(at, Ordering::SeqCst);
    let barrier = target
        .barrier(
            member.store.as_ref(),
            &original.forward,
            at,
            20000,
            "key-17",
            &SigningKey::from_bytes(&[17; 32]),
        )
        .await
        .unwrap();
    let replacement = kedgeflow::compensation_target::applicability(
        &member.contract,
        &native::trust(&member.forward, &member.registration),
        original.forward,
        barrier,
        at,
        "key-18",
        &SigningKey::from_bytes(&[18; 32]),
    )
    .unwrap();
    member.qualifier.qualify(replacement).await.unwrap();
    assert_eq!(member.qualifier.history().await.unwrap().len(), 2);
    proxy.release.notify_one();
    assert!(operation.await.unwrap().is_err());
    assert!(
        direct
            .read_key(&format!(
                "{}/issuance/{}",
                base.prefix, member.contract.inverse_operation_key
            ))
            .await
            .unwrap()
            .is_none()
    );
    assert!(direct.compensation_spend().await.is_err());
    assert!(saga.status().await.unwrap().in_flight.is_none());
}

#[tokio::test]
async fn family_saga_cached_expected_proof_comparisons_refuse_deleted_original_history() {
    let Some(TwoSql {
        base,
        mut members,
        database,
        saga,
        ..
    }) = Box::pin(setup(None)).await
    else {
        return;
    };
    Box::pin(prepare_two(&base, &mut members, &database, &saga)).await;
    let h = &members[1];
    let q = h.qualifier.history().await.unwrap().pop().unwrap();
    let event = q.proof.forward.events.first().unwrap();
    let key = format!(
        "{}/reservation-history/{}/events/{:06}",
        base.prefix,
        h.registration.digest().unwrap(),
        event.sequence
    );
    assert!(h.forward.ledger.read_key(&key).await.unwrap().is_some());
    // This owned storage-integrity fault leaves the signed checkpoint and head
    // untouched. A warmed historical cache must still check the original bytes.
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v3/kv/deleterange",
            std::env::var("ETCD_ENDPOINT").unwrap()
        ))
        .json(&json!({"key":STANDARD.encode(key.as_bytes())}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(response.json::<Value>().await.unwrap()["deleted"], "1");
    assert!(h.forward.ledger.read_key(&key).await.unwrap().is_none());
    let head = saga.status().await.unwrap().head;
    assert!(Box::pin(execution_issue(&h.inverse)).await.is_err());
    assert_eq!(saga.status().await.unwrap().head, head);
    assert!(h.inverse.ledger.compensation_spend().await.is_err());
    assert!(
        h.inverse
            .ledger
            .read_key(&format!(
                "{}/issuance/{}",
                base.prefix, h.contract.inverse_operation_key
            ))
            .await
            .unwrap()
            .is_none()
    );
}
