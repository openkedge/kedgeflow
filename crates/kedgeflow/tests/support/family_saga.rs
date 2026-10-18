//! Draft composition validation over native inventories; execution stays closed.
use super::*;
use kedgeflow::{
    family::{Family, Registration, Selection},
    family_saga::{
        ForwardState, Intent, IntentAction, IntentPayload, MemberSnapshot, Node, ObserverPin,
        PROFILE, Plan, Snapshot,
    },
    reserved_leaf,
};

fn observer(n: u8) -> ObserverPin {
    ObserverPin {
        id: format!("observer-{n}"),
        keys: BTreeMap::from([(
            format!("key-{n}"),
            base64::engine::general_purpose::STANDARD
                .encode(SigningKey::from_bytes(&[n; 32]).verifying_key().as_bytes()),
        )]),
    }
}
async fn draft() -> Option<(Vec<Harness>, Registration)> {
    let mut hosts = Vec::new();
    let mut children = Vec::new();
    let mut nodes = Vec::new();
    for n in 0..2 {
        let h = Harness::with_setup(None, NOW, |f| family_tests::configure(f, n)).await?;
        let mut r = hierarchical_leaf::registration_named(&h, 1, &format!("draft-member-root-{n}"));
        let op =
            h.f.trust
                .operation_key(&h.f.identity, &h.f.packet().proposal)
                .unwrap();
        r.profile = kedgeflow::saga_forward::PROFILE.into();
        r.saga = Some(kedgeflow::saga_forward::Plan {
            profile: r.profile.clone(),
            saga_id: format!("member-{n}"),
            valid_from: NOW - 1000,
            expires_at: NOW + 60000,
            nodes: vec![kedgeflow::saga_forward::Node {
                node_id: "forward".into(),
                operation_key: op.clone(),
                principal: kedgeflow::hierarchical_leaf::Principal {
                    subject: h.f.identity.subject.clone(),
                    workload_id: h.f.identity.workload_id.clone(),
                },
                depends_on: vec![],
            }],
            outcome_keys: observer(14).keys,
            source_id: "spiffe://test/outcome".into(),
        });
        r.validate().unwrap();
        let mut trust = reserved_history::trust_value(&h, &r);
        // The proposal pins one future family namespace. These native fixtures
        // remain separate: no atomic multi-member capture is claimed here.
        if let Some(seed) = hosts.first() {
            let seed: &Harness = seed;
            trust["namespace"] = json!(seed.prefix);
        }
        nodes.push(Node {
            child_id: format!("child-{n}"),
            operation_key: op,
            depends_on: if n == 0 {
                vec![]
            } else {
                vec!["child-0".into()]
            },
            forward_trust: trust,
            compound_trust: None,
        });
        children.push(kedgeflow::family::Child {
            id: format!("child-{n}"),
            reservation: r,
            topology: None,
            inverse: None,
        });
        hosts.push(h);
    }
    let mut r = family_tests::registration_from_children(&hosts[0], children, 2);
    r.profile = PROFILE.into();
    r.composition = Some(Plan {
        profile: PROFILE.into(),
        saga_id: "draft-two-contracts".into(),
        nodes,
        family_observer: observer(33),
        observer: observer(34),
    });
    r.validate().unwrap();
    Some((hosts, r))
}
async fn inventory(h: &Harness, r: &reserved_leaf::Registration) -> MemberSnapshot {
    let base = format!("{}/reservation-history/{}", h.prefix, r.digest().unwrap());
    let head: Value = serde_json::from_slice(
        &h.ledger
            .read_key(&format!("{base}/head"))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let mut events = Vec::new();
    for n in 1..=head["sequence"].as_u64().unwrap() {
        events.push(
            serde_json::from_slice(
                &h.ledger
                    .read_key(&format!("{base}/events/{n:06}"))
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
        );
    }
    let op = &r.saga.as_ref().unwrap().nodes[0].operation_key;
    let mut authorizations = BTreeMap::new();
    if h.ledger
        .read_key(&format!("{}/issuance/{op}", h.prefix))
        .await
        .unwrap()
        .is_some()
    {
        let raw = |collection: &str| format!("{}/{collection}/{op}", h.prefix);
        let chain: Value = serde_json::from_slice(
            &h.ledger
                .read_key(&raw("admission-chain"))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        authorizations.insert(
            op.clone(),
            kedgeflow::lineage::AuthorizationBundle {
                admission: serde_json::from_slice(
                    &h.ledger.read_key(&raw("admission")).await.unwrap().unwrap(),
                )
                .unwrap(),
                packet: serde_json::from_value(chain["packet"].clone()).unwrap(),
                issuance: serde_json::from_slice(
                    &h.ledger.read_key(&raw("issuance")).await.unwrap().unwrap(),
                )
                .unwrap(),
                lease_authority: None,
            },
        );
    }
    MemberSnapshot {
        captured_at: kedgeflow::clock::Clock::now_ms(h.clock.as_ref()),
        events,
        authorizations,
        executions: BTreeMap::new(),
        unclaimed: true,
        inverse_absent: true,
        compound: None,
    }
}

#[tokio::test]
async fn family_saga_draft_closed_execution_and_exact_public_plan() {
    let Some((hosts, r)) = draft().await else {
        return;
    };
    let wire = serde_json::to_vec(&r).unwrap();
    assert_eq!(Registration::decode(&wire).unwrap(), r);
    let original = hosts[0]
        .ledger
        .read_key(&format!("{}/family/required", r.namespace))
        .await
        .unwrap();
    assert!(Family::new(hosts[0].ledger.clone(), r.clone()).is_err());
    assert!(
        Selection {
            registration: r.clone(),
            child_id: "child-0".into()
        }
        .attach(hosts[0].ledger.clone())
        .is_err()
    );
    assert_eq!(
        hosts[0]
            .ledger
            .read_key(&format!("{}/family/required", r.namespace))
            .await
            .unwrap(),
        original
    );
    for case in [
        "missing",
        "duplicate",
        "cycle",
        "self",
        "unknown",
        "operation",
        "namespace",
        "role",
        "owner",
        "window",
        "profile",
        "null",
    ] {
        let mut v = json!(r);
        match case {
            "missing" => {
                v["composition"]["nodes"].as_array_mut().unwrap().pop();
            }
            "duplicate" => v["composition"]["nodes"][1] = v["composition"]["nodes"][0].clone(),
            "cycle" => v["composition"]["nodes"][0]["depends_on"] = json!(["child-1"]),
            "self" => v["composition"]["nodes"][0]["depends_on"] = json!(["child-0"]),
            "unknown" => v["composition"]["nodes"][1]["depends_on"] = json!(["unapproved"]),
            "operation" => v["composition"]["nodes"][1]["operation_key"] = json!("a".repeat(64)),
            "namespace" => {
                v["composition"]["nodes"][1]["forward_trust"]["namespace"] = json!("/elsewhere")
            }
            "role" => v["composition"]["observer"] = json!(observer(5)),
            "owner" => v["composition"]["family_observer"] = json!(observer(31)),
            "window" => v["expires_at"] = json!(NOW + 60001),
            "profile" => v["profile"] = json!(kedgeflow::family::PROFILE),
            "null" => v["composition"] = Value::Null,
            _ => unreachable!(),
        }
        assert!(
            Registration::decode(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{case}"
        );
    }
    let mut legacy = r.clone();
    legacy.profile = kedgeflow::family::PROFILE.into();
    legacy.composition = None;
    let v = json!(legacy);
    assert!(v.get("composition").is_none());
    assert_eq!(
        Registration::decode(&canonical(&v).unwrap())
            .unwrap()
            .digest()
            .unwrap(),
        legacy.digest().unwrap()
    );
}

#[tokio::test]
async fn family_saga_draft_intents_pin_owner_proof_and_original_window() {
    let Some((_, r)) = draft().await else { return };
    let p = IntentPayload {
        family_digest: r.digest().unwrap(),
        operation_key: "a".repeat(64),
        expected_head: "b".repeat(64),
        issued_at: NOW,
        expires_at: NOW + 1000,
        action: IntentAction::Quiesce,
        proof_digest: None,
    };
    let c = Intent::sign(p.clone(), "owner", &SigningKey::from_bytes(&[31; 32])).unwrap();
    assert_eq!(Intent::decode(&canonical(&json!(c)).unwrap()).unwrap(), c);
    c.validate_at(&r, NOW).unwrap();
    assert!(c.validate_at(&r, NOW - 1).is_err());
    assert!(c.validate_at(&r, NOW + 1000).is_err());
    let wrong = Intent::sign(p.clone(), "delegate", &SigningKey::from_bytes(&[32; 32])).unwrap();
    assert!(wrong.verify_owner(&r).is_err());
    let mut changed = c.clone();
    changed.payload.expected_head = "c".repeat(64);
    assert!(changed.verify_owner(&r).is_err());
    let mut p = p.clone();
    p.action = IntentAction::Observe;
    p.proof_digest = Some("c".repeat(64));
    p.issued_at = r.expires_at + 1;
    p.expires_at = p.issued_at + 1000;
    let observe = Intent::sign(p.clone(), "owner", &SigningKey::from_bytes(&[31; 32])).unwrap();
    observe.validate_at(&r, p.issued_at).unwrap();
    p.action = IntentAction::PrepareCompensation;
    assert!(
        Intent::sign(p.clone(), "owner", &SigningKey::from_bytes(&[31; 32]))
            .unwrap()
            .validate_at(&r, p.issued_at)
            .is_err()
    );
    p.proof_digest = None;
    assert!(Intent::sign(p, "owner", &SigningKey::from_bytes(&[31; 32])).is_err());
    let mut v = json!(c);
    v["authority"] = json!(true);
    assert!(Intent::decode(&canonical(&v).unwrap()).is_err());
    let duplicate = String::from_utf8(canonical(&json!(c)).unwrap())
        .unwrap()
        .replacen('{', "{\"profile\":\"duplicate\",", 1);
    assert!(Intent::decode(duplicate.as_bytes()).is_err());
}

#[tokio::test]
async fn family_saga_draft_native_inventory_cannot_omit_claim_or_original_authority() {
    let Some((mut hosts, r)) = draft().await else {
        return;
    };
    let mut members = BTreeMap::new();
    for (n, h) in hosts.iter_mut().enumerate() {
        let child = &r.children[n];
        h.ledger = h
            .ledger
            .clone()
            .with_reservation(child.reservation.clone())
            .unwrap();
        h.ledger.enroll_reservation().await.unwrap();
        members.insert(child.id.clone(), inventory(h, &child.reservation).await);
    }
    let s = Snapshot {
        profile: PROFILE.into(),
        registration_digest: r.digest().unwrap(),
        phase_head: "a".repeat(64),
        epoch: "b".repeat(64),
        captured_at: NOW,
        members,
    };
    assert!(
        s.verify(&r)
            .unwrap()
            .values()
            .all(|m| m.forward == ForwardState::Unissued)
    );
    Snapshot::decode(&canonical(&json!(s)).unwrap())
        .unwrap()
        .verify(&r)
        .unwrap();
    let mut missing = s.clone();
    missing.members.remove("child-1");
    assert!(missing.verify(&r).is_err());
    let mut forged = s.clone();
    forged.members.get_mut("child-0").unwrap().events[0]
        .after
        .allocations
        .clear();
    assert!(forged.verify(&r).is_err());
    let mut empty = s.clone();
    empty.members.get_mut("child-0").unwrap().events.clear();
    assert!(empty.verify(&r).is_err());
    let h = &hosts[0];
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let record = h.issue().await.unwrap().record;
    let mut issued = s.clone();
    issued.members.insert(
        "child-0".into(),
        inventory(h, &r.children[0].reservation).await,
    );
    issued.verify_successor(&s, &r).unwrap();
    assert_eq!(
        issued.verify(&r).unwrap()["child-0"].forward,
        ForwardState::Unclaimed
    );
    assert!(s.verify_successor(&issued, &r).is_err());
    let mut omitted = issued.clone();
    omitted
        .members
        .get_mut("child-0")
        .unwrap()
        .authorizations
        .clear();
    assert!(omitted.verify(&r).is_err());
    let candidate = reserved_history::claim(h, &record, "draft-original-attempt").await;
    let mut claimed = issued.clone();
    claimed.members.insert(
        "child-0".into(),
        inventory(h, &r.children[0].reservation).await,
    );
    assert!(claimed.verify(&r).is_err());
    h.ledger
        .authorize_dispatch(
            &candidate.grant,
            &record.grant_digest,
            &candidate.attempt_id,
        )
        .await
        .unwrap();
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    reserved_history::worker(
        h,
        &candidate,
        &record.grant_digest,
        "unknown",
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .recover(&candidate)
    .await
    .unwrap();
    claimed.members.insert(
        "child-0".into(),
        inventory(h, &r.children[0].reservation).await,
    );
    claimed.captured_at = NOW + 6000;
    let op = &r.composition.as_ref().unwrap().nodes[0].operation_key;
    let evidence = h
        .ledger
        .export_reserved_lineage(
            &candidate,
            op,
            &kedgeflow::control_history::HistoryObserver::new(
                "budget-observer".into(),
                "key-15".into(),
                SigningKey::from_bytes(&[15; 32]),
            )
            .unwrap(),
            &reserved_history::trust(h, &r.children[0].reservation),
        )
        .await
        .unwrap();
    let member = claimed.members.get_mut("child-0").unwrap();
    member.unclaimed = false;
    member.executions.insert(op.clone(), evidence);
    claimed.verify_successor(&issued, &r).unwrap();
    assert_eq!(
        claimed.verify(&r).unwrap()["child-0"].forward,
        ForwardState::Unknown
    );
    let mut old = claimed.clone();
    old.captured_at = NOW - 1;
    assert!(old.verify_successor(&claimed, &r).is_err());
    let mut substituted = claimed.clone();
    let mut n = r.clone();
    n.composition.as_mut().unwrap().nodes[0].forward_trust["namespace"] = json!("/substituted");
    substituted.registration_digest = "c".repeat(64);
    assert!(substituted.verify(&n).is_err());
}
