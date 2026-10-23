//! Draft composition validation over native inventories; execution stays closed.
use super::*;
use kedgeflow::{
    contracts::digest,
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
            physical: None,
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
        physical: None,
        captured_at: kedgeflow::clock::Clock::now_ms(h.clock.as_ref()),
        events,
        authorizations,
        executions: BTreeMap::new(),
        unclaimed: true,
        inverse_absent: true,
        compound: None,
        qualification_absent: None,
        composition_bindings: None,
    }
}

#[tokio::test]
async fn family_saga_explicit_opt_in_and_exact_public_plan() {
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
    assert!(Family::new(hosts[0].ledger.clone(), r.clone()).is_ok());
    assert!(
        Selection {
            registration: r.clone(),
            child_id: "child-0".into()
        }
        .attach(hosts[0].ledger.clone())
        .is_ok()
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

async fn model_inventory() -> Option<(Registration, Snapshot)> {
    let (mut hosts, r) = draft().await?;
    let mut members = BTreeMap::new();
    for (n, h) in hosts.iter_mut().enumerate() {
        let c = &r.children[n];
        h.ledger = h
            .ledger
            .clone()
            .with_reservation(c.reservation.clone())
            .unwrap();
        h.ledger.enroll_reservation().await.unwrap();
        members.insert(c.id.clone(), inventory(h, &c.reservation).await);
    }
    let head = kedgeflow::family_saga::PhaseState::genesis(&r)
        .unwrap()
        .head;
    Some((
        r.clone(),
        Snapshot {
            profile: PROFILE.into(),
            registration_digest: r.digest().unwrap(),
            phase_head: head,
            epoch: "d".repeat(64),
            captured_at: NOW,
            members,
        },
    ))
}
fn model_event(
    r: &Registration,
    head: &str,
    action: IntentAction,
    proof: Option<&Snapshot>,
    n: u64,
    at: i64,
) -> kedgeflow::family_saga::PhaseEvent {
    kedgeflow::family_saga::PhaseEvent::Owner {
        at,
        family_head: (action != IntentAction::Observe).then(|| "a".repeat(64)),
        intent: Intent::sign(
            IntentPayload {
                family_digest: r.digest().unwrap(),
                operation_key: format!("{n:064x}"),
                expected_head: head.into(),
                issued_at: at,
                expires_at: at + 1000,
                action,
                proof_digest: proof.map(|p| p.digest().unwrap()),
            },
            "owner",
            &SigningKey::from_bytes(&[31; 32]),
        )
        .unwrap(),
    }
}
#[tokio::test]
async fn family_saga_model_permanent_quiescing_and_complete_preparation_replay() {
    use kedgeflow::family_saga::{Phase, PhaseState};
    let Some((r, p)) = model_inventory().await else {
        return;
    };
    let mut proofs = BTreeMap::from([(p.digest().unwrap(), p.clone())]);
    let first = model_event(&r, &p.phase_head, IntentAction::Observe, Some(&p), 1, NOW);
    let mut events = vec![first];
    let before = PhaseState::from_events(&r, &events, &proofs).unwrap();
    assert_eq!(before.phase, Phase::Forward);
    assert_eq!(before.members.len(), 2);
    let mut premature = p.clone();
    premature.phase_head = before.head.clone();
    proofs.insert(premature.digest().unwrap(), premature.clone());
    let bad = model_event(
        &r,
        &before.head,
        IntentAction::PrepareCompensation,
        Some(&premature),
        2,
        NOW,
    );
    assert!(PhaseState::from_events(&r, &[events[0].clone(), bad], &proofs).is_err());
    events.push(model_event(
        &r,
        &before.head,
        IntentAction::Quiesce,
        None,
        3,
        NOW,
    ));
    let closed = PhaseState::from_events(&r, &events, &proofs).unwrap();
    assert_eq!(closed.phase, Phase::Quiescing);
    let mut complete = p.clone();
    complete.phase_head = closed.head.clone();
    complete.epoch = "e".repeat(64);
    complete.captured_at = NOW + 1;
    proofs.insert(complete.digest().unwrap(), complete.clone());
    events.push(model_event(
        &r,
        &closed.head,
        IntentAction::PrepareCompensation,
        Some(&complete),
        4,
        NOW + 1,
    ));
    let prepared = PhaseState::from_events(&r, &events, &proofs).unwrap();
    assert_eq!(prepared.phase, Phase::Compensating);
    assert!(prepared.in_flight.is_none());
    prepared.verify(&r, &proofs).unwrap();
    let mut missing = proofs.clone();
    missing.remove(&p.digest().unwrap());
    assert!(prepared.verify(&r, &missing).is_err());
    let mut altered = prepared.clone();
    altered.phase = Phase::Forward;
    assert!(altered.verify(&r, &proofs).is_err());
    let mut duplicate = events.clone();
    duplicate.push(events[0].clone());
    assert!(PhaseState::from_events(&r, &duplicate, &proofs).is_err());
}
#[tokio::test]
async fn family_saga_model_rejects_noop_polling_and_rebound_owner_operation() {
    use kedgeflow::family_saga::PhaseState;
    let Some((r, p)) = model_inventory().await else {
        return;
    };
    let mut proofs = BTreeMap::from([(p.digest().unwrap(), p.clone())]);
    let first = model_event(&r, &p.phase_head, IntentAction::Observe, Some(&p), 1, NOW);
    let state = PhaseState::from_events(&r, std::slice::from_ref(&first), &proofs).unwrap();
    let mut newer = p.clone();
    newer.phase_head = state.head.clone();
    newer.epoch = "f".repeat(64);
    newer.captured_at = NOW + 1;
    proofs.insert(newer.digest().unwrap(), newer.clone());
    let noop = model_event(
        &r,
        &state.head,
        IntentAction::Observe,
        Some(&newer),
        2,
        NOW + 1,
    );
    assert!(PhaseState::from_events(&r, &[first.clone(), noop], &proofs).is_err());
    let rebound = model_event(&r, &state.head, IntentAction::Quiesce, None, 1, NOW + 1);
    assert!(PhaseState::from_events(&r, &[first.clone(), rebound], &proofs).is_err());
    let wrong = model_event(&r, &"c".repeat(64), IntentAction::Quiesce, None, 3, NOW + 1);
    assert!(PhaseState::from_events(&r, &[first, wrong], &proofs).is_err());
}
pub(super) fn model_seal(
    r: &Registration,
    snapshot: Snapshot,
    signer: u8,
) -> kedgeflow::family_saga::Collected {
    let mut seal = kedgeflow::family_saga::CaptureSeal {
        profile: PROFILE.into(),
        observer_id: r.composition.as_ref().unwrap().observer.id.clone(),
        key_id: "key-34".into(),
        namespace: r.namespace.clone(),
        registration_digest: r.digest().unwrap(),
        snapshot_digest: snapshot.digest().unwrap(),
        signature: String::new(),
    };
    let mut value = json!(seal);
    value.as_object_mut().unwrap().remove("signature");
    let mut message = format!("KedgeFlow:{PROFILE}:native-capture\0").into_bytes();
    message.extend(canonical(&value).unwrap());
    seal.signature = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[signer; 32])
            .sign(&message)
            .to_bytes(),
    );
    kedgeflow::family_saga::Collected { snapshot, seal }
}
#[tokio::test]
async fn family_saga_model_capture_requires_separate_collector_and_complete_frames() {
    let Some((r, mut p)) = model_inventory().await else {
        return;
    };
    assert!(model_seal(&r, p.clone(), 34).verify(&r).is_err());
    for m in p.members.values_mut() {
        m.composition_bindings = Some(BTreeMap::new());
    }
    let c = model_seal(&r, p.clone(), 34);
    c.verify(&r).unwrap();
    assert!(model_seal(&r, p.clone(), 31).verify(&r).is_err());
    let mut changed = c.clone();
    changed.snapshot.epoch = "b".repeat(64);
    assert!(changed.verify(&r).is_err());
    let mut missing = p.clone();
    missing.members.remove("child-1");
    assert!(model_seal(&r, missing, 34).verify(&r).is_err());
    let mut wrong = p.clone();
    wrong.registration_digest = "a".repeat(64);
    assert!(model_seal(&r, wrong, 34).verify(&r).is_err());
    let mut value = json!(c);
    value["snapshot"]["members"]["child-0"]["composition_bindings"] = Value::Null;
    assert!(kedgeflow::family_saga::Collected::decode(&canonical(&value).unwrap()).is_err());
}

fn sign_model_checkpoint(value: &mut Value, domain: &str, signer: u8) {
    value["signature"] = json!("");
    let mut unsigned = value.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let mut message = format!("KedgeFlow:{domain}\0").into_bytes();
    message.extend(canonical(&unsigned).unwrap());
    value["signature"] = json!(
        URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[signer; 32])
                .sign(&message)
                .to_bytes()
        )
    );
}
pub(super) fn sign_model_aggregate(b: &mut kedgeflow::family_saga::AggregateBundle, signer: u8) {
    b.checkpoint.evidence_digest =
        digest("family-saga-complete-evidence", &json!(b.evidence)).unwrap();
    let mut cp = json!(b.checkpoint);
    sign_model_checkpoint(&mut cp, &format!("{PROFILE}:aggregate-history"), signer);
    b.checkpoint = serde_json::from_value(cp).unwrap();
}

#[tokio::test]
async fn family_saga_model_aggregate_rejects_resigned_omission_and_wrong_original_heads() {
    use kedgeflow::{
        family,
        family_saga::{
            AggregateBundle, AggregateCheckpoint, AggregateEvidence, AuditTrust, PhaseState,
            verify_aggregate,
        },
    };
    let Some((r, mut p)) = model_inventory().await else {
        return;
    };
    for m in p.members.values_mut() {
        m.composition_bindings = Some(BTreeMap::new());
    }
    let mut events = vec![];
    let mut family = family::State::from_events(&r, &events).unwrap();
    for (n, child) in r.children.iter().enumerate() {
        let command = family_tests::command(
            &r,
            &family,
            100 + n as u64,
            family::Action::Attach {
                parent: "root".into(),
                child_id: child.id.clone(),
            },
            false,
        );
        events.push(family::Event { at: NOW, command });
        family = family::State::from_events(&r, &events).unwrap();
    }
    let mut cp = json!({"profile":family::PROFILE,"observer_id":"observer-33","key_id":"key-33","namespace":r.namespace,"captured_at":NOW,"state_digest":digest("family-state", &json!(family)).unwrap(),"signature":""});
    sign_model_checkpoint(&mut cp, &format!("{}:checkpoint", family::PROFILE), 33);
    let family = family::Bundle {
        state: family,
        checkpoint: serde_json::from_value(cp).unwrap(),
    };
    let proof = model_seal(&r, p.clone(), 34);
    let event = model_event(&r, &p.phase_head, IntentAction::Observe, Some(&p), 1, NOW);
    let phase = PhaseState::from_events(
        &r,
        &[event],
        &BTreeMap::from([(p.digest().unwrap(), p.clone())]),
    )
    .unwrap();
    p.phase_head = phase.head.clone();
    p.captured_at = NOW + 1;
    let mut b = AggregateBundle {
        profile: PROFILE.into(),
        evidence: AggregateEvidence {
            family,
            phase,
            proofs: BTreeMap::from([(proof.snapshot.digest().unwrap(), proof)]),
            current: model_seal(&r, p, 34),
        },
        checkpoint: AggregateCheckpoint {
            profile: PROFILE.into(),
            observer_id: "observer-34".into(),
            key_id: "key-34".into(),
            namespace: r.namespace.clone(),
            registration_digest: r.digest().unwrap(),
            evidence_digest: String::new(),
            captured_at: NOW + 1,
            signature: String::new(),
        },
    };
    sign_model_aggregate(&mut b, 34);
    let t = AuditTrust {
        registration: r.clone(),
    };
    let v = verify_aggregate(&b, &t).unwrap();
    assert!(v.complete_evidence);
    assert!(!v.execution_authority);
    assert!(!v.observation_required);
    assert_eq!(v.status, "forward_partial");
    AggregateBundle::decode(&canonical(&json!(b)).unwrap()).unwrap();
    for case in [
        "missing-proof",
        "extra-proof",
        "phase",
        "current-head",
        "missing-member",
        "missing-frame",
        "missing-attachment",
        "owner-signature",
        "namespace",
    ] {
        let mut changed = b.clone();
        match case {
            "missing-proof" => changed.evidence.proofs.clear(),
            "extra-proof" => {
                changed
                    .evidence
                    .proofs
                    .insert("b".repeat(64), b.evidence.current.clone());
            }
            "phase" => changed.evidence.phase.phase = kedgeflow::family_saga::Phase::Compensating,
            "current-head" => {
                let mut p = changed.evidence.current.snapshot.clone();
                p.phase_head = "b".repeat(64);
                changed.evidence.current = model_seal(&r, p, 34);
            }
            "missing-member" => {
                let mut p = changed.evidence.current.snapshot.clone();
                p.members.remove("child-1");
                changed.evidence.current = model_seal(&r, p, 34);
            }
            "missing-frame" => {
                let mut p = changed.evidence.current.snapshot.clone();
                p.members.get_mut("child-0").unwrap().composition_bindings = None;
                changed.evidence.current = model_seal(&r, p, 34);
            }
            "missing-attachment" => {
                changed.evidence.family.state.attachments.remove("child-1");
            }
            "owner-signature" => {}
            "namespace" => changed.checkpoint.namespace = "/other".into(),
            _ => unreachable!(),
        }
        sign_model_aggregate(
            &mut changed,
            if case == "owner-signature" { 31 } else { 34 },
        );
        assert!(verify_aggregate(&changed, &t).is_err(), "{case}");
    }
    // The shipping verifier accepts public trust without private config or etcd.
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("aggregate.json");
    let trust = dir.path().join("trust.json");
    std::fs::write(&bundle, canonical(&json!(b)).unwrap()).unwrap();
    std::fs::write(&trust, canonical(&json!(t)).unwrap()).unwrap();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-family-saga"))
        .args(["verify", "--bundle"])
        .arg(bundle)
        .arg("--trust")
        .arg(trust)
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["execution_authority"],
        false
    );
}

#[tokio::test]
async fn family_saga_prepared_command_survives_restart_without_replacement() {
    use kedgeflow::family_saga::{PhaseEvent, Prepared};
    let Some((r, mut p)) = model_inventory().await else {
        return;
    };
    for m in p.members.values_mut() {
        m.composition_bindings = Some(BTreeMap::new());
    }
    let PhaseEvent::Owner { intent, .. } =
        model_event(&r, &p.phase_head, IntentAction::Observe, Some(&p), 1, NOW)
    else {
        unreachable!()
    };
    let prepared = Prepared {
        intent,
        capture: Some(model_seal(&r, p, 34)),
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.json");
    prepared.retain(&path, &r).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert_eq!(Prepared::read(&path).unwrap().intent, prepared.intent);
    assert!(prepared.retain(&path, &r).is_err());
    let mut changed = prepared.clone();
    changed.capture.as_mut().unwrap().snapshot.epoch = "a".repeat(64);
    assert!(changed.retain(&path, &r).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let partial = dir.path().join("partial.json");
    std::fs::write(&partial, b"{\"intent\":").unwrap();
    assert!(Prepared::read(&partial).is_err());
    assert!(prepared.retain(&partial, &r).is_err());
    // An authentic historical original remains readable; only online new
    // application checks its current expiry. Recovery does not re-sign it.
    let recovered = Prepared::read(&path).unwrap();
    recovered.verify(&r).unwrap();
    assert!(recovered.intent.validate_at(&r, NOW + 60001).is_err());
}

#[tokio::test]
async fn family_saga_protected_config_requires_exact_catalog_namespace_and_observer_roles() {
    let Some((_, r)) = draft().await else { return };
    let file = |id: &str, key: &str| json!({"id":id,"key_id":key,"signing_key_file":"/protected/observer.key"});
    let value = json!({
        "family":{"registration":r,"etcd_endpoint":"https://etcd.test:2379","etcd_prefix":r.namespace,"etcd_ca":"/protected/ca.pem","etcd_certificate":"/protected/client.pem","etcd_private_key":"/protected/client.key","etcd_token_file":"/protected/token","restore_gate":null},
        "members":{"child-0":{"forward":file("budget-observer","key-15"),"compound":null},"child-1":{"forward":file("budget-observer","key-15"),"compound":null}},
        "collector":file("observer-34","key-34"),"family_observer":file("observer-33","key-33")
    });
    kedgeflow::family_saga_config::Config::decode(&canonical(&value).unwrap()).unwrap();
    for case in [
        "namespace",
        "endpoint",
        "missing-member",
        "extra-member",
        "collector",
        "observer-key",
        "compound",
        "credential-in-command",
    ] {
        let mut bad = value.clone();
        match case {
            "namespace" => bad["family"]["etcd_prefix"] = json!("/elsewhere"),
            "endpoint" => bad["family"]["etcd_endpoint"] = json!("http://etcd.test:2379"),
            "missing-member" => {
                bad["members"].as_object_mut().unwrap().remove("child-1");
            }
            "extra-member" => bad["members"]["other"] = bad["members"]["child-0"].clone(),
            "collector" => bad["collector"] = bad["family_observer"].clone(),
            "observer-key" => bad["members"]["child-0"]["forward"]["key_id"] = json!("owner"),
            "compound" => bad["members"]["child-0"]["compound"] = file("budget-observer", "key-15"),
            "credential-in-command" => bad["target_token"] = json!("not-supported"),
            _ => unreachable!(),
        }
        assert!(
            kedgeflow::family_saga_config::Config::decode(&canonical(&bad).unwrap()).is_err(),
            "{case}"
        );
    }
}
