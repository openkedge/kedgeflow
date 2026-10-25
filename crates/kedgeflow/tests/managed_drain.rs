//! Pure proposed-profile vectors. No native CAS, SQL or Kubernetes qualification.
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use kedgeflow::{
    contracts::{self, Grant, Resource, digest},
    current_reservation as sql,
    family_saga::ObserverPin,
    kube_drain::{self as kd, Contract},
    managed_drain::{self as md, Enrollment},
    managed_drain_journal::{Change, Core, Event, Origin, QueryKind},
    physical_operations as op, postgres_action as pg,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[path = "support/current_reservation_fixture.rs"]
mod source_fixture;
fn pin(id: &str, n: u8) -> ObserverPin {
    ObserverPin {
        id: id.into(),
        keys: BTreeMap::from([(
            "key".into(),
            STANDARD.encode(SigningKey::from_bytes(&[n; 32]).verifying_key().as_bytes()),
        )]),
    }
}
fn contract() -> Contract {
    serde_json::from_value(json!({"profile":kd::PROFILE,"cluster_uid":"realm-1","api_origin":"https://cluster.test/","ca_sha256":"a".repeat(64),"node":{"name":"node-1","uid":"node-uid-1"},"generation":1,"availability_nodes":[{"name":"node-1","uid":"node-uid-1"},{"name":"node-2","uid":"node-uid-2"}],"minimum_ready_nodes":1,"workload":{"deployment":{"namespace":"orders","object":{"name":"orders","uid":"deployment-1"}},"generation":1,"replica_set":{"name":"orders-rs","uid":"rs-1"},"pdb":{"name":"orders","uid":"pdb-1"},"pdb_generation":1,"pdb_min_available":1,"minimum_available":1},"allowed_daemon_sets":[],"allowed_mirror_pods":[],"maximum_pods":8,"maximum_requests":16,"maximum_deferred_ms":60000,"grace_period_seconds":1})).unwrap()
}
fn enrollment(c: &Contract) -> Enrollment {
    Enrollment {
        profile: md::PROFILE.into(),
        namespace: "/managed-test".into(),
        child_id: "physical".into(),
        operation_key: "b".repeat(64),
        mechanical_contract_digest: c.digest().unwrap(),
        target_audience: "https://drain.test/accept".into(),
        target_scope: "node.drain.managed".into(),
        controller_workload: "spiffe://test/controller".into(),
        supervisor_workload: "spiffe://test/supervisor".into(),
        evidence_workload: "spiffe://test/evidence".into(),
        operating_observer: pin("operating", 91),
        policy: op::Policy {
            profile: op::PROFILE.into(),
            tenant: "tenant-42".into(),
            resource_owner_id: "team:platform".into(),
            on_call_team_id: "team:oncall".into(),
            incident_sink: op::IncidentSink {
                id: "incident-sink".into(),
                url: "https://incident.test/physical".into(),
                acknowledgement_keys: pin("sink", 92).keys,
                maximum_delivery_attempts: 3,
            },
            initial_backoff_ms: 10,
            maximum_backoff_ms: 20,
            maximum_automated_queries: 4,
            reconcile_for_ms: 60000,
            post_deadline_observation: op::PostDeadline::QueryOnly {
                maximum_queries: 2,
                observe_for_ms: 50,
            },
            expiry_action: op::ExpiryAction::StopConsequentialWork,
        },
        current_sql: source_fixture::registration(),
        clock_uncertainty_ms: 5,
        maximum_authorization_to_send_ms: 1000,
    }
}
fn origin(e: &Enrollment, c: &Contract) -> Origin {
    Origin {
        original: op::Original {
            profile: op::PROFILE.into(),
            enrollment_digest: e.digest().unwrap(),
            policy_digest: e.policy.digest().unwrap(),
            family_registration_digest: "f".repeat(64),
            child_id: e.child_id.clone(),
            operation_key: e.operation_key.clone(),
            root_id: "root-physical".into(),
            grant_digest: "1".repeat(64),
            attempt_id: "attempt-physical".into(),
            contract_digest: c.digest().unwrap(),
            resource: c.resource().unwrap(),
            realm_uid: c.cluster_uid.clone(),
            node_uid: c.node.uid.clone(),
            dispatched_at: 1000,
            native_dispatch_digest: "2".repeat(64),
        },
        signed_grant: "unit-vector-only-not-a-grant".into(),
        forward_signed_grant: "unit-vector-only-not-a-grant".into(),
        forward_attempt_id: "attempt-sql".into(),
        grant_expires_at: 6000,
    }
}
fn fixture() -> (Enrollment, Origin, Core) {
    let c = contract();
    let e = enrollment(&c);
    e.validate(&c).unwrap();
    let o = origin(&e, &c);
    let s = Core::initial(&e, &o).unwrap();
    (e, o, s)
}
fn step(s: &Core, e: &Enrollment, o: &Origin, at: i64, c: Change) -> Core {
    s.apply(e, o, at, &c, None).unwrap()
}
fn reserve(s: &Core, e: &Enrollment, o: &Origin, at: i64, kind: QueryKind) -> Core {
    step(
        s,
        e,
        o,
        at,
        Change::QueryReserved {
            query_kind: kind,
            number: s.before_queries + s.after_queries + 1,
        },
    )
}
fn accepted(e: &Enrollment, o: &Origin, s: &Core) -> Core {
    let s = reserve(s, e, o, 1000, QueryKind::Accept);
    step(
        &s,
        e,
        o,
        1001,
        Change::ControllerAccepted {
            proof_digest: "3".repeat(64),
        },
    )
}
#[test]
fn managed_enrollment_is_closed_and_uses_an_explicit_named_action() {
    let c = contract();
    let e = enrollment(&c);
    let raw = contracts::canonical(&json!(e)).unwrap();
    assert_eq!(Enrollment::decode(&raw, &c).unwrap(), e);
    for (field, value) in [
        ("profile", json!(kd::PROFILE)),
        ("namespace", json!("/bad/../scope")),
        ("namespace", json!("/bad//scope")),
        ("controller_workload", json!(e.supervisor_workload)),
        ("evidence_workload", json!(e.controller_workload)),
        ("maximum_authorization_to_send_ms", json!(1001)),
        ("clock_uncertainty_ms", json!(1001)),
        ("extra", json!(true)),
        ("current_sql", Value::Null),
    ] {
        let mut bad = json!(e);
        bad[field] = value;
        assert!(
            Enrollment::decode(&contracts::canonical(&bad).unwrap(), &c).is_err(),
            "{field}"
        );
    }
    for field in json!(e).as_object().unwrap().keys() {
        let mut bad = json!(e);
        bad.as_object_mut().unwrap().remove(field);
        assert!(
            Enrollment::decode(&contracts::canonical(&bad).unwrap(), &c).is_err(),
            "missing {field}"
        );
    }
    let schema = e.schema(&c).unwrap();
    md::validate_schema(md::VERSION, &schema).unwrap();
    assert!(kd::validate_schema("1.0", &schema).is_err());
    assert!(md::validate_schema(md::VERSION, &c.parameter_schema().unwrap()).is_err());
    let mut changed = e.clone();
    changed.policy.resource_owner_id = "team:other".into();
    assert_ne!(schema, changed.schema(&c).unwrap());
    let mut bad = schema;
    bad["additionalProperties"] = json!(true);
    assert!(md::validate_schema(md::VERSION, &bad).is_err());
    let a = contracts::Action {
        id: md::ACTION.into(),
        version: md::VERSION.into(),
        digest: "a".repeat(64),
    };
    contracts::validate_action_adapter(&a, &md::adapter_contract(), &c.resource().unwrap(), None)
        .unwrap();
    assert!(
        contracts::validate_action_adapter(
            &a,
            &kd::adapter_contract(),
            &c.resource().unwrap(),
            None
        )
        .is_err()
    );
}
#[test]
fn managed_slot_is_shared_consumed_and_cannot_be_stolen_after_a_restart() {
    let (e, o, s) = fixture();
    assert!(
        s.apply(
            &e,
            &o,
            1000,
            &Change::QueryReserved {
                query_kind: QueryKind::Observe,
                number: 1
            },
            None
        )
        .is_err()
    );
    let s = reserve(&s, &e, &o, 1000, QueryKind::Accept);
    let s: Core = serde_json::from_value(json!(s)).unwrap();
    assert_eq!(s.before_queries, 1);
    for kind in [QueryKind::Accept, QueryKind::Advance, QueryKind::Observe] {
        assert!(
            s.apply(
                &e,
                &o,
                2000,
                &Change::QueryReserved {
                    query_kind: kind,
                    number: 2
                },
                None
            )
            .is_err()
        );
    }
    assert!(
        s.apply(
            &e,
            &o,
            5999,
            &Change::QueryUnavailable {
                number: 1,
                reason: "interrupted".into()
            },
            None
        )
        .is_err()
    );
    let s = step(
        &s,
        &e,
        &o,
        6000,
        Change::QueryUnavailable {
            number: 1,
            reason: "interrupted".into(),
        },
    );
    let s = reserve(&s, &e, &o, 6000, QueryKind::Observe);
    assert_eq!(s.before_queries, 2);
    assert_eq!(s.pending.unwrap().number, 2);
}
#[test]
fn managed_deadline_opens_owned_outbox_even_with_an_inflight_unavailable_source() {
    let (e, o, s) = fixture();
    let s = accepted(&e, &o, &s);
    let s = reserve(&s, &e, &o, 1010, QueryKind::Advance);
    let deadline = s.deadline;
    assert!(
        s.apply(
            &e,
            &o,
            deadline,
            &Change::QueryUnavailable {
                number: 2,
                reason: "transport".into()
            },
            None
        )
        .is_err()
    );
    let s = step(&s, &e, &o, deadline, Change::Escalated);
    let i = s.incident.as_ref().unwrap();
    assert!(s.stop_required);
    assert!(s.unresolved());
    assert_eq!(i.deadline, 61000);
    assert_eq!(s.pending.as_ref().unwrap().number, 2);
    let s = step(
        &s,
        &e,
        &o,
        deadline,
        Change::QueryUnavailable {
            number: 2,
            reason: "interrupted".into(),
        },
    );
    assert!(
        s.apply(
            &e,
            &o,
            deadline,
            &Change::ControllerPending {
                sequence: 1,
                proof_digest: "4".repeat(64)
            },
            None
        )
        .is_err()
    );
    let s = reserve(&s, &e, &o, deadline, QueryKind::Observe);
    assert_eq!(s.after_queries, 1);
    assert_eq!(s.pending.as_ref().unwrap().expires_at, 61050);
    assert!(
        s.apply(
            &e,
            &o,
            deadline + 1,
            &Change::QueryReserved {
                query_kind: QueryKind::Advance,
                number: 4
            },
            None
        )
        .is_err()
    );
}
#[test]
fn managed_lost_pending_never_becomes_a_second_send_or_no_effect() {
    let (e, o, s) = fixture();
    let s = accepted(&e, &o, &s);
    let s = reserve(&s, &e, &o, 1010, QueryKind::Advance);
    let s = step(
        &s,
        &e,
        &o,
        1011,
        Change::ControllerPending {
            sequence: 1,
            proof_digest: "4".repeat(64),
        },
    );
    assert!(
        s.apply(
            &e,
            &o,
            1012,
            &Change::ClosedNoEffect {
                proof_digest: "5".repeat(64)
            },
            None
        )
        .is_err()
    );
    let s = step(
        &s,
        &e,
        &o,
        1012,
        Change::SendChecked {
            sequence: 1,
            proof_digest: "6".repeat(64),
        },
    );
    assert!(
        s.apply(
            &e,
            &o,
            1013,
            &Change::SendChecked {
                sequence: 1,
                proof_digest: "6".repeat(64)
            },
            None
        )
        .is_err()
    );
    let s = step(&s, &e, &o, s.deadline, Change::Escalated);
    assert!(
        s.apply(
            &e,
            &o,
            s.deadline,
            &Change::SendChecked {
                sequence: 2,
                proof_digest: "7".repeat(64)
            },
            None
        )
        .is_err()
    );
    assert!(s.unresolved());
    assert_eq!(s.pending_steps, 1);
    assert_eq!(s.send_checks, 1);
}
#[test]
fn managed_delivery_retries_keep_original_identity_and_acknowledgement_cannot_resolve() {
    let (e, o, s) = fixture();
    let deadline = s.deadline;
    let s = step(&s, &e, &o, deadline, Change::Escalated);
    let incident = s.incident.clone().unwrap();
    let s = step(&s, &e, &o, deadline, Change::DeliveryReserved { number: 1 });
    assert!(
        s.apply(
            &e,
            &o,
            deadline + 1,
            &Change::DeliveryFailed {
                number: 1,
                reason: "interrupted".into()
            },
            None
        )
        .is_err()
    );
    let s = step(
        &s,
        &e,
        &o,
        deadline + 5000,
        Change::DeliveryFailed {
            number: 1,
            reason: "interrupted".into(),
        },
    );
    let s = step(
        &s,
        &e,
        &o,
        deadline + 5000,
        Change::DeliveryReserved { number: 2 },
    );
    let s = step(
        &s,
        &e,
        &o,
        deadline + 5001,
        Change::DeliveryAcknowledged {
            number: 2,
            acknowledgement_digest: "8".repeat(64),
        },
    );
    let after = s.incident.as_ref().unwrap();
    assert_eq!(after.id, incident.id);
    assert_eq!(after.event_digest, incident.event_digest);
    assert!(s.unresolved());
    assert!(s.stop_required);
    assert!(
        s.apply(
            &e,
            &o,
            deadline + 5010,
            &Change::DeliveryReserved { number: 3 },
            None
        )
        .is_err()
    );
}
#[test]
fn managed_query_budgets_backoff_and_final_observation_window_are_finite() {
    let (mut e, _, _) = fixture();
    e.policy.maximum_automated_queries = 1;
    let o = origin(&e, &contract());
    let s = Core::initial(&e, &o).unwrap();
    let s = reserve(&s, &e, &o, 6000, QueryKind::Observe);
    let s = step(
        &s,
        &e,
        &o,
        6001,
        Change::QueryUnavailable {
            number: 1,
            reason: "transport".into(),
        },
    );
    assert!(
        s.apply(
            &e,
            &o,
            7000,
            &Change::QueryReserved {
                query_kind: QueryKind::Observe,
                number: 2
            },
            None
        )
        .is_err()
    );
    let deadline = s.deadline;
    let s = step(&s, &e, &o, deadline, Change::Escalated);
    let s = reserve(&s, &e, &o, deadline, QueryKind::Observe);
    let s = step(
        &s,
        &e,
        &o,
        deadline + 1,
        Change::QueryUnavailable {
            number: 2,
            reason: "transport".into(),
        },
    );
    assert!(
        s.apply(
            &e,
            &o,
            deadline + 9,
            &Change::QueryReserved {
                query_kind: QueryKind::Observe,
                number: 3
            },
            None
        )
        .is_err()
    );
    let s = reserve(&s, &e, &o, deadline + 10, QueryKind::Observe);
    let s = step(
        &s,
        &e,
        &o,
        deadline + 11,
        Change::QueryUnavailable {
            number: 3,
            reason: "malformed".into(),
        },
    );
    assert!(
        s.apply(
            &e,
            &o,
            deadline + 30,
            &Change::QueryReserved {
                query_kind: QueryKind::Observe,
                number: 4
            },
            None
        )
        .is_err()
    );
    assert_eq!(s.before_queries, 1);
    assert_eq!(s.after_queries, 2);
    let (mut e, _, _) = fixture();
    e.policy.post_deadline_observation = op::PostDeadline::Disabled;
    let o = origin(&e, &contract());
    let s = Core::initial(&e, &o).unwrap();
    let deadline = s.deadline;
    let s = step(&s, &e, &o, deadline, Change::Escalated);
    assert!(
        s.apply(
            &e,
            &o,
            deadline,
            &Change::QueryReserved {
                query_kind: QueryKind::Observe,
                number: 1
            },
            None
        )
        .is_err()
    );
}
#[test]
fn managed_full_event_chain_rejects_splicing_time_reversal_and_overflow() {
    let (e, o, s) = fixture();
    let first = Event::new(None, &s, &e, &o, 1000, Change::Dispatched, None).unwrap();
    let second = Event::new(
        Some(&first),
        &first.after,
        &e,
        &o,
        1001,
        Change::QueryReserved {
            query_kind: QueryKind::Accept,
            number: 1,
        },
        None,
    )
    .unwrap();
    assert_eq!(second.previous_digest, Some(first.digest().unwrap()));
    assert!(
        Event::new(
            Some(&first),
            &second.after,
            &e,
            &o,
            1002,
            Change::Escalated,
            None
        )
        .is_err()
    );
    assert!(
        Event::new(
            Some(&second),
            &second.after,
            &e,
            &o,
            1000,
            Change::QueryUnavailable {
                number: 1,
                reason: "transport".into()
            },
            None
        )
        .is_err()
    );
    assert!(kedgeflow::managed_drain_journal::add(contracts::MAX_SAFE_INTEGER as i64, 1).is_err());
    let mut o = o;
    o.original.dispatched_at = contracts::MAX_SAFE_INTEGER as i64;
    assert!(Core::initial(&e, &o).is_err());
}
fn sql_witness(e: &Enrollment, o: &Origin) -> (Grant, sql::Witness) {
    // Use only the fixture's closed Grant shape, not its signature or authority.
    let v: Value = serde_json::from_str(include_str!("../../../fixtures/grant.json")).unwrap();
    let mut g: Grant = serde_json::from_value(v["payload"].clone()).unwrap();
    g.action.id = pg::ACTION.into();
    g.resources = vec![e.current_sql.resource.clone()];
    g.root_id = "original-sql-execution-root".into();
    g.expires_at = 6000;
    g.parameters_digest = digest(
        "parameters",
        &json!(pg::Parameters {
            resource_id: e.current_sql.resource.id.clone(),
            expected_version: 1,
            reservation: "held".into()
        }),
    )
    .unwrap();
    let head = sql::Signed::sign(
        "storage_head",
        sql::StorageHead {
            storage_id: e.current_sql.storage.storage_id.clone(),
            generation: 1,
            sequence: 7,
            resource: e.current_sql.resource.clone(),
            boundary_digest: digest("sql-storage-boundary", &json!(e.current_sql.storage)).unwrap(),
            published_at: 900,
            expires_at: 7000,
        },
        &e.current_sql.storage.owner,
        "key",
        &SigningKey::from_bytes(&[95; 32]),
    )
    .unwrap();
    let q = sql::Query {
        profile: sql::PROFILE.into(),
        enrollment_digest: e.digest().unwrap(),
        origin: o.clone(),
        reservation_digest: "9".repeat(64),
        requested_at: 2000,
    };
    let body = sql::Observation {
        requested_at: 2000,
        query_digest: q.digest().unwrap(),
        enrollment_digest: e.digest().unwrap(),
        origin_digest: o.digest().unwrap(),
        reservation_digest: q.reservation_digest.clone(),
        source_claim: sql::SourceClaim {
            profile: sql::PROFILE.into(),
            enrollment_digest: e.digest().unwrap(),
            origin_digest: o.digest().unwrap(),
            reservation_digest: q.reservation_digest.clone(),
            query_digest: q.digest().unwrap(),
            requested_at: 2000,
            operating_head_digest: "c".repeat(64),
            claimed_at: 2000,
            expires_at: 6000,
        },
        storage_head: head,
        sql: kedgeflow::postgres_compensation::BarrierObservation {
            contract_digest: e.current_sql.compensation_contract_digest.clone(),
            forward_outcome: pg::Outcome {
                profile: pg::PROFILE.into(),
                request: pg::DispatchRequest {
                    profile: pg::PROFILE.into(),
                    action: pg::ACTION.into(),
                    tenant: e.current_sql.tenant.clone(),
                    conflict_domain: g.conflict_domain.clone(),
                    attempt_id: o.forward_attempt_id.clone(),
                    grant_digest: "a".repeat(64),
                    root_id: g.root_id.clone(),
                    resource: e.current_sql.resource.clone(),
                    expected_version: 1,
                    fence: g.fence,
                    reservation: "held".into(),
                    gateway_workload: "spiffe://test/gateway".into(),
                    expires_at: 6000,
                },
                status: pg::Status::Committed,
                post_version: Some(2),
            },
            resource: e.current_sql.resource.clone(),
            observed_version: 2,
            restore_state_digest: "b".repeat(64),
        },
        from: 2001,
        until: 2002,
        expires_at: 6000,
    };
    (
        g,
        sql::Signed::sign(
            "reservation_observation",
            body,
            &e.current_sql.provider,
            "key",
            &SigningKey::from_bytes(&[94; 32]),
        )
        .unwrap(),
    )
}
#[test]
fn current_sql_witness_checks_exact_original_resource_fence_version_state_and_freshness() {
    let (e, o, _) = fixture();
    let (g, w) = sql_witness(&e, &o);
    let verify = |w: &sql::Witness, g: &Grant, at| {
        w.validate_current(&e, &o, &"9".repeat(64), at, g, &"a".repeat(64))
    };
    verify(&w, &g, 2003).unwrap();
    assert!(verify(&w, &g, 6000).is_err());
    for (field, value) in [
        ("observed_version", json!(3)),
        (
            "resource",
            json!(Resource {
                id: "orders-db".into(),
                incarnation: "restored".into()
            }),
        ),
        ("restore_state_digest", json!("not-a-digest")),
    ] {
        let mut b = json!(w.body);
        b["sql"][field] = value;
        let bad = sql::Signed::sign(
            "reservation_observation",
            serde_json::from_value::<sql::Observation>(b).unwrap(),
            &e.current_sql.provider,
            "key",
            &SigningKey::from_bytes(&[94; 32]),
        )
        .unwrap();
        assert!(verify(&bad, &g, 2003).is_err(), "{field}");
    }
    for (field, value) in [
        ("fence", json!(g.fence + 1)),
        ("reservation", json!("changed")),
        ("attempt_id", json!("other")),
        ("grant_digest", json!("c".repeat(64))),
        ("root_id", json!("other")),
        ("conflict_domain", json!("other")),
    ] {
        let mut b = json!(w.body);
        b["sql"]["forward_outcome"]["request"][field] = value;
        let bad = sql::Signed::sign(
            "reservation_observation",
            serde_json::from_value::<sql::Observation>(b).unwrap(),
            &e.current_sql.provider,
            "key",
            &SigningKey::from_bytes(&[94; 32]),
        )
        .unwrap();
        assert!(verify(&bad, &g, 2003).is_err(), "{field}");
    }
    let mut wrong = g;
    wrong.root_id = "other".into();
    assert!(verify(&w, &wrong, 2003).is_err());
}
#[test]
fn current_sql_storage_head_has_a_separate_role_and_must_still_be_current_at_use() {
    let (e, o, _) = fixture();
    let (g, mut w) = sql_witness(&e, &o);
    w.body.storage_head.body.expires_at = 2003;
    w.body.storage_head = sql::Signed::sign(
        "storage_head",
        w.body.storage_head.body,
        &e.current_sql.storage.owner,
        "key",
        &SigningKey::from_bytes(&[95; 32]),
    )
    .unwrap();
    let w = sql::Signed::sign(
        "reservation_observation",
        w.body,
        &e.current_sql.provider,
        "key",
        &SigningKey::from_bytes(&[94; 32]),
    )
    .unwrap();
    assert!(
        w.validate_current(&e, &o, &"9".repeat(64), 2003, &g, &"a".repeat(64))
            .is_err()
    );
    let (_, w) = sql_witness(&e, &o);
    assert!(
        w.body
            .storage_head
            .verify("storage_head", &e.current_sql.provider)
            .is_err()
    );
    assert!(
        w.verify("reservation_observation", &e.current_sql.storage.owner)
            .is_err()
    );
    let mut w = w;
    w.body.storage_head.body.generation += 1;
    assert!(
        w.validate_current(&e, &o, &"9".repeat(64), 2003, &g, &"a".repeat(64))
            .is_err()
    );
}

#[test]
fn managed_trust_cannot_normalize_null_or_reuse_incident_and_source_keys() {
    let c = contract();
    let e = enrollment(&c);
    let legacy = json!({"contract":c,"controller":pin("controller",47),"observer":pin("physical-observer",49),"control_trust":{}});
    let decoded: kedgeflow::kube_drain_proof::Trust =
        serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(json!(decoded), legacy);
    for value in [Value::Null, json!(false), json!([])] {
        let mut bad = legacy.clone();
        bad["operating"] = value;
        assert!(serde_json::from_value::<kedgeflow::kube_drain_proof::Trust>(bad).is_err());
    }
    let mut bad = e.clone();
    bad.current_sql.provider.keys = bad.policy.incident_sink.acknowledgement_keys.clone();
    assert!(bad.validate(&c).is_err());
    let mut bad = e.clone();
    bad.operating_observer.id = bad.current_sql.storage.owner.id.clone();
    assert!(bad.validate(&c).is_err());
    let o = origin(&e, &c);
    let mut changed = e;
    changed.policy.resource_owner_id = "team:substituted".into();
    assert!(Core::initial(&changed, &o).is_err());
}
