//! Real-etcd family authority combined with managed native leaf control.
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    coordination::{Coordination, ReservationState},
    family::{
        self, Action, AuditTrust, Branch, Command, CommandPayload, Family, Registration, Selection,
        SignerPin, State,
    },
    hierarchical_leaf::Principal,
};
fn configure(f: &mut Fixture, n: usize) {
    let old = f.proposal["resources"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    fn replace(v: &mut Value, old: &str, new: &str) {
        match v {
            Value::String(s) => *s = s.replace(old, new),
            Value::Array(a) => a.iter_mut().for_each(|v| replace(v, old, new)),
            Value::Object(o) => o.values_mut().for_each(|v| replace(v, old, new)),
            _ => {}
        }
    }
    for v in [&mut f.proposal, &mut f.descriptor, &mut f.evidence] {
        replace(v, &old, &format!("family-resource-{n}"));
    }
    f.proposal["qid"] = json!(format!("family-proposal-{n}"));
    f.descriptor["concurrency"]["conflict_domain"] = json!(format!("family-domain-{n}"));
    f.identity.delegation_digest =
        kedgeflow::contracts::digest("delegation", &f.proposal["delegation"]).unwrap();
    f.repin_descriptor();
}
fn principal(h: &Harness) -> Principal {
    Principal {
        subject: h.f.identity.subject.clone(),
        workload_id: h.f.identity.workload_id.clone(),
    }
}
fn worker(r: &Registration) -> Principal {
    r.signers["delegate"].principal.clone()
}
pub(super) fn command(
    r: &Registration,
    s: &State,
    n: u64,
    action: Action,
    delegated: bool,
) -> Command {
    Command::sign(
        CommandPayload {
            family_digest: r.digest().unwrap(),
            operation_key: format!("{n:064x}"),
            expected_head: s.head.clone(),
            issued_at: NOW,
            expires_at: NOW + 30000,
            action,
        },
        if delegated { "delegate" } else { "owner" },
        &SigningKey::from_bytes(&[if delegated { 32 } else { 31 }; 32]),
    )
    .unwrap()
}
pub(super) fn branch(r: &Registration, parent: &str) -> Branch {
    Branch {
        parent: parent.into(),
        owner: worker(r),
        principals: r.principals.clone(),
        scope: r.scope.clone(),
        forward: r.forward,
        compensation: r.compensation,
        valid_from: NOW - 500,
        expires_at: NOW + 40000,
        active: true,
    }
}
pub(super) async fn setup(children: usize, units: u64) -> Option<(Harness, Registration, Family)> {
    let h = Harness::with_setup(None, NOW, |f| configure(f, 0)).await?;
    let mut catalog = Vec::new();
    for n in 0..children {
        let other = Harness::with_setup(None, NOW, |f| configure(f, n))
            .await
            .unwrap();
        let mut r = hierarchical_leaf::registration_named(&other, 1, &format!("family-root-{n}"));
        r.profile = kedgeflow::reservation_history::HIERARCHICAL_LEAF_PROFILE.into();
        catalog.push(family::Child {
            id: format!("child-{n}"),
            reservation: r,
            topology: None,
            inverse: None,
        });
    }
    let r = registration_from_children(&h, catalog, units);
    let family = Family::new(h.ledger.clone(), r.clone()).unwrap();
    family.enroll().await.unwrap();
    Some((h, r, family))
}
pub(super) fn registration_from_children(
    h: &Harness,
    catalog: Vec<family::Child>,
    units: u64,
) -> Registration {
    let owner = principal(h);
    let mut delegate = owner.clone();
    delegate.subject.sub = "family-delegate".into();
    let mut scope = catalog[0].reservation.enrollment.scope.clone();
    for c in &catalog {
        scope
            .actions
            .extend(c.reservation.enrollment.scope.actions.clone());
        scope
            .resources
            .extend(c.reservation.enrollment.scope.resources.clone());
        if let Some(i) = &c.inverse {
            scope.actions.insert(i.inverse_scope.action.id.clone());
            scope.resources.insert(i.inverse_scope.resource.id.clone());
        }
    }
    let r = Registration {
        profile: family::PROFILE.into(),
        namespace: h.prefix.clone(),
        family_id: "family-native-test".into(),
        tenant: h.registration.tenant.clone(),
        owner: owner.clone(),
        principals: vec![owner.clone(), delegate.clone()],
        scope,
        forward: units,
        compensation: units,
        valid_from: NOW - 1000,
        expires_at: NOW + 60000,
        signers: BTreeMap::from([
            (
                "owner".into(),
                SignerPin {
                    principal: owner,
                    public_key: STANDARD
                        .encode(SigningKey::from_bytes(&[31; 32]).verifying_key().as_bytes()),
                },
            ),
            (
                "delegate".into(),
                SignerPin {
                    principal: delegate,
                    public_key: STANDARD
                        .encode(SigningKey::from_bytes(&[32; 32]).verifying_key().as_bytes()),
                },
            ),
        ]),
        children: catalog,
    };
    r.validate().unwrap();
    r
}
pub(super) async fn child(seed: &Harness, r: &Registration, n: usize) -> Harness {
    let h = Harness::with_family_options(
        None,
        NOW,
        |f| configure(f, n),
        None,
        None,
        None,
        None,
        None,
        Some((
            seed.prefix.clone(),
            Selection {
                registration: r.clone(),
                child_id: format!("child-{n}"),
            },
        )),
    )
    .await
    .unwrap();
    h.ledger.enroll_reservation().await.unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    h
}
pub(super) async fn attach(
    f: &Family,
    r: &Registration,
    n: u64,
    parent: &str,
    id: &str,
    delegated: bool,
) -> State {
    f.apply(command(
        r,
        &f.status().await.unwrap(),
        n,
        Action::Attach {
            parent: parent.into(),
            child_id: id.into(),
        },
        delegated,
    ))
    .await
    .unwrap()
}
pub(super) async fn stop(f: &Family, r: &Registration, n: u64, id: &str) -> State {
    f.apply(command(
        r,
        &f.status().await.unwrap(),
        n,
        Action::Stop {
            branch_id: id.into(),
        },
        false,
    ))
    .await
    .unwrap()
}
pub(super) fn grant(h: &Harness, rec: &kedgeflow::ledger::IssuanceRecord) -> Grant {
    GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify_retained(rec.signed_grant.as_bytes())
    .unwrap()
    .grant
}
#[tokio::test]
async fn family_native_two_children_delegate_stop_and_hold_original_attempts() {
    let Some((seed, r, f)) = setup(2, 2).await else {
        return;
    };
    let cmd = command(
        &r,
        &f.status().await.unwrap(),
        1,
        Action::Delegate {
            parent: "root".into(),
            branch: branch(&r, "root"),
        },
        false,
    );
    let branch_id = cmd.payload.operation_key.clone();
    f.apply(cmd.clone()).await.unwrap();
    let s = attach(&f, &r, 2, &branch_id, "child-0", true).await;
    attach(&f, &r, 3, &branch_id, "child-1", true).await;
    assert_eq!(s.budget.allocations.len(), 2);
    let a = child(&seed, &r, 0).await;
    let b = child(&seed, &r, 1).await;
    let ar = a.issue().await.unwrap().record;
    let br = b.issue().await.unwrap().record;
    let ag = grant(&a, &ar);
    let bg = grant(&b, &br);
    let aa = a
        .ledger
        .claim(&ag, &ar.grant_digest, "family-a-original")
        .await
        .unwrap();
    let ba = b
        .ledger
        .claim(&bg, &br.grant_digest, "family-b-original")
        .await
        .unwrap();
    a.ledger
        .authorize_dispatch(&ag, &ar.grant_digest, &aa.id)
        .await
        .unwrap();
    stop(&f, &r, 4, &branch_id).await;
    assert!(
        b.ledger
            .authorize_dispatch(&bg, &br.grant_digest, &ba.id)
            .await
            .is_err()
    );
    assert!(a.issue().await.is_err());
    for (h, c, rec) in [(&a, &r.children[0], &ar), (&b, &r.children[1], &br)] {
        let state = Coordination::new(h.ledger.clone(), &c.reservation.root_id)
            .unwrap()
            .status()
            .await
            .unwrap();
        assert_eq!(
            state.allocations[&rec.issuance_key].state,
            ReservationState::Unknown
        );
        assert_eq!(state.enrollment.forward, 1);
    }
    let state = f.status().await.unwrap();
    assert_eq!(state.attachments.len(), 2);
    assert_eq!(state.budget.allocations.len(), 3);
    assert_eq!(f.apply(cmd).await.unwrap(), state); // Lost reply replay does not allocate again.
    let plain = EtcdLedger::new(
        reqwest::Client::new(),
        std::env::var("ETCD_ENDPOINT").unwrap(),
        &seed.prefix,
    )
    .unwrap();
    let historical = Selection {
        registration: r.clone(),
        child_id: "child-0".into(),
    }
    .attach(plain)
    .unwrap();
    assert!(
        historical
            .read_key(&format!("{}/family/state", seed.prefix))
            .await
            .unwrap()
            .is_some()
    );
    assert!(seed.issue().await.is_err()); // Same namespace, configuration omitted.
    assert!(
        Family::new(seed.ledger.clone(), r.clone())
            .unwrap()
            .enroll()
            .await
            .is_err()
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_last_slot_parallel_contract_attachment_has_one_winner() {
    let Some((_, r, f)) = setup(2, 1).await else {
        return;
    };
    let s = f.status().await.unwrap();
    let a = command(
        &r,
        &s,
        1,
        Action::Attach {
            parent: "root".into(),
            child_id: "child-0".into(),
        },
        false,
    );
    let b = command(
        &r,
        &s,
        2,
        Action::Attach {
            parent: "root".into(),
            child_id: "child-1".into(),
        },
        false,
    );
    let (a, b) = tokio::join!(f.apply(a), f.apply(b));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let s = f.status().await.unwrap();
    assert_eq!(s.attachments.len(), 1);
    let loser = if s.attachments.contains_key("child-0") {
        "child-1"
    } else {
        "child-0"
    };
    assert!(
        f.apply(command(
            &r,
            &s,
            3,
            Action::Attach {
                parent: "root".into(),
                child_id: loser.into()
            },
            false
        ))
        .await
        .is_err()
    );
    assert_eq!(f.status().await.unwrap(), s);
}
#[tokio::test]
async fn family_signed_widening_roles_reissue_expiry_and_stopped_replacement_refuse() {
    let Some((_, r, f)) = setup(1, 1).await else {
        return;
    };
    let original = f.status().await.unwrap();
    for n in 0..7 {
        let mut b = branch(&r, "root");
        match n {
            0 => b.forward += 1,
            1 => b.compensation += 1,
            2 => {
                b.scope.actions.insert("unapproved".into());
            }
            3 => {
                b.principals.push(Principal {
                    subject: kedgeflow::contracts::Subject {
                        iss: "bad".into(),
                        sub: "bad".into(),
                    },
                    workload_id: "spiffe://bad/agent".into(),
                });
            }
            4 => b.expires_at = r.expires_at + 1,
            5 => b.parent = "other".into(),
            _ => {}
        }
        assert!(
            f.apply(command(
                &r,
                &original,
                n + 1,
                Action::Delegate {
                    parent: "root".into(),
                    branch: b
                },
                n == 6
            ))
            .await
            .is_err()
        );
        assert_eq!(f.status().await.unwrap(), original);
    }
    let cmd = command(
        &r,
        &original,
        20,
        Action::Attach {
            parent: "root".into(),
            child_id: "child-0".into(),
        },
        false,
    );
    let accepted = f.apply(cmd.clone()).await.unwrap();
    let mut changed = cmd.clone();
    changed.payload.expected_head = accepted.head.clone();
    let changed =
        Command::sign(changed.payload, "owner", &SigningKey::from_bytes(&[31; 32])).unwrap();
    assert!(f.apply(changed).await.is_err());
    let stopped = stop(&f, &r, 21, "root").await;
    assert_eq!(f.apply(cmd).await.unwrap(), stopped);
    assert!(
        f.apply(command(
            &r,
            &stopped,
            22,
            Action::Attach {
                parent: "root".into(),
                child_id: "child-0".into()
            },
            false
        ))
        .await
        .is_err()
    );
    let mut alias = r.clone();
    alias.children.push(alias.children[0].clone());
    alias.children[1].id = "alias".into();
    assert!(alias.validate().is_err());
    let raw =
        serde_json::to_vec(&json!({"registration":r,"child_id":"child-0","extra":true})).unwrap();
    assert!(serde_json::from_slice::<Selection>(&raw).is_err());
}
#[tokio::test]
async fn family_export_separate_observer_closed_replay_and_tampering_refuse() {
    let Some((h, r, f)) = setup(1, 1).await else {
        return;
    };
    attach(&f, &r, 1, "root", "child-0", false).await;
    stop(&f, &r, 2, "root").await;
    let trust = AuditTrust {
        registration: r.clone(),
        namespace: h.prefix.clone(),
        observer_id: "family-observer".into(),
        observer_keys: BTreeMap::from([(
            "key-33".into(),
            STANDARD.encode(SigningKey::from_bytes(&[33; 32]).verifying_key().as_bytes()),
        )]),
    };
    let observer = kedgeflow::control_history::HistoryObserver::new(
        "family-observer".into(),
        "key-33".into(),
        SigningKey::from_bytes(&[33; 32]),
    )
    .unwrap();
    let b = f.export(&observer, &trust).await.unwrap();
    family::verify(&b, &trust).unwrap();
    for n in 0..5 {
        let mut bad = b.clone();
        match n {
            0 => bad.state.active = true,
            1 => bad.state.events.clear(),
            2 => bad.state.budget.allocations.clear(),
            3 => bad.state.attachments.clear(),
            _ => bad.checkpoint.namespace.push_str("/elsewhere"),
        }
        if n < 4 {
            // An observer cannot legitimize a structurally inconsistent history.
            bad.checkpoint.state_digest =
                kedgeflow::contracts::digest("family-state", &json!(bad.state)).unwrap();
            let mut checkpoint = json!(bad.checkpoint);
            checkpoint.as_object_mut().unwrap().remove("signature");
            let mut message = format!("KedgeFlow:{}:checkpoint\0", family::PROFILE).into_bytes();
            message.extend(canonical(&checkpoint).unwrap());
            bad.checkpoint.signature =
                URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[33; 32]).sign(&message).to_bytes());
        }
        assert!(family::verify(&bad, &trust).is_err());
    }
    let mut bad = trust.clone();
    bad.observer_keys = BTreeMap::from([("owner".into(), r.signers["owner"].public_key.clone())]);
    assert!(family::verify(&b, &bad).is_err());
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.json");
    let bundle = dir.path().join("bundle.json");
    let pins = dir.path().join("trust.json");
    std::fs::write(&config,serde_json::to_vec(&json!({"registration":r,"etcd_endpoint":"https://unreachable.example","etcd_prefix":h.prefix,"etcd_ca":"absent","etcd_certificate":"absent","etcd_private_key":"absent","etcd_token_file":"absent","restore_gate":null})).unwrap()).unwrap();
    std::fs::write(&bundle, serde_json::to_vec(&b).unwrap()).unwrap();
    std::fs::write(&pins, serde_json::to_vec(&trust).unwrap()).unwrap();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-family"))
        .arg("--config")
        .arg(config)
        .arg("--verify")
        .arg("--bundle")
        .arg(bundle)
        .arg("--trust")
        .arg(pins)
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_stop_races_native_allocation_issuance_claim_and_dispatch() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use std::sync::atomic::AtomicBool;
    for phase in ["fence-allocation", "issuance", "attempts", "dispatch"] {
        let Some((seed, r, f)) = setup(1, 1).await else {
            return;
        };
        attach(&f, &r, 1, "root", "child-0", false).await;
        let mut h = child(&seed, &r, 0).await;
        let direct = h.ledger.clone();
        let issued = if matches!(phase, "attempts" | "dispatch") {
            Some(h.issue().await.unwrap().record)
        } else {
            None
        };
        let attempt = if phase == "dispatch" {
            let rec = issued.as_ref().unwrap();
            Some(
                direct
                    .claim(&grant(&h, rec), &rec.grant_digest, "race-original")
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let block = Arc::new(AtomicBool::new(true));
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post({
                let entered = entered.clone();
                let release = release.clone();
                move |Json(value): Json<Value>| {
                    let entered = entered.clone();
                    let release = release.clone();
                    let block = block.clone();
                    let endpoint = endpoint.clone();
                    async move {
                        let selected = value["success"].as_array().is_some_and(|ops| {
                            ops.iter().any(|op| {
                                if phase == "dispatch" {
                                    op["request_put"]["value"]
                                        .as_str()
                                        .and_then(|s| STANDARD.decode(s).ok())
                                        .is_some_and(|v| v == b"dispatch_authorized")
                                } else {
                                    op["request_put"]["key"]
                                        .as_str()
                                        .and_then(|s| STANDARD.decode(s).ok())
                                        .is_some_and(|key| {
                                            String::from_utf8_lossy(&key)
                                                .contains(&format!("/{phase}/"))
                                        })
                                }
                            })
                        });
                        if selected && block.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
                        let response = reqwest::Client::new()
                            .post(format!("{endpoint}/v3/kv/txn"))
                            .json(&value)
                            .send()
                            .await
                            .unwrap();
                        let code = response.status();
                        let bytes = response.bytes().await.unwrap();
                        (code, [("content-type", "application/json")], bytes).into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let proxy = live_agent::Running(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }));
        h.ledger = Selection {
            registration: r.clone(),
            child_id: "child-0".into(),
        }
        .attach(
            EtcdLedger::new(reqwest::Client::new(), endpoint, &h.prefix)
                .unwrap()
                .with_clock(h.clock.clone())
                .requiring_control(Some(h.registration.trust_digest.clone()))
                .with_reservation(r.children[0].reservation.clone())
                .unwrap(),
        )
        .unwrap();
        let operation = tokio::spawn(async move {
            match phase {
                "attempts" => {
                    let rec = issued.unwrap();
                    h.ledger
                        .claim(&grant(&h, &rec), &rec.grant_digest, "raced")
                        .await
                        .map(|_| ())
                }
                "dispatch" => {
                    let rec = issued.unwrap();
                    h.ledger
                        .authorize_dispatch(
                            &grant(&h, &rec),
                            &rec.grant_digest,
                            &attempt.unwrap().id,
                        )
                        .await
                }
                _ => h.issue().await.map(|_| ()),
            }
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect(phase);
        stop(&f, &r, 2, "root").await;
        release.notify_one();
        assert!(operation.await.unwrap().is_err(), "{phase}");
        let state = Coordination::new(direct.clone(), &r.children[0].reservation.root_id)
            .unwrap()
            .status()
            .await
            .unwrap();
        assert!(!f.status().await.unwrap().active);
        assert!(state.active); // Local state is retained, global authority is stopped.
        let leaf: Vec<_> = state
            .allocations
            .values()
            .filter(|a| a.state != ReservationState::Composite)
            .collect();
        match phase {
            "fence-allocation" | "issuance" => assert!(leaf.is_empty()),
            "attempts" => assert_eq!(leaf[0].state, ReservationState::Allocated),
            _ => assert_eq!(leaf[0].state, ReservationState::Unknown),
        }
        drop(proxy);
    }
}

#[tokio::test]
async fn family_nested_bounds_expiry_and_reserved_root_stop_slot() {
    let Some((h, r, f)) = setup(1, 1).await else {
        return;
    };
    let first = command(
        &r,
        &f.status().await.unwrap(),
        1,
        Action::Delegate {
            parent: "root".into(),
            branch: branch(&r, "root"),
        },
        false,
    );
    let parent = first.payload.operation_key.clone();
    f.apply(first).await.unwrap();
    let mut nested = branch(&r, &parent);
    nested.expires_at = NOW + 20000;
    let second = command(
        &r,
        &f.status().await.unwrap(),
        2,
        Action::Delegate {
            parent: parent.clone(),
            branch: nested,
        },
        true,
    );
    let nested = second.payload.operation_key.clone();
    f.apply(second).await.unwrap();
    attach(&f, &r, 3, &nested, "child-0", true).await;
    let c = child(&h, &r, 0).await;
    let rec = c.issue().await.unwrap().record;
    h.clock.0.store(NOW + 25000, Ordering::SeqCst);
    let s = f.status().await.unwrap();
    assert!(
        f.apply(command(
            &r,
            &s,
            4,
            Action::Delegate {
                parent: nested.clone(),
                branch: branch(&r, &nested)
            },
            true
        ))
        .await
        .is_err()
    );
    // Expiry cannot create another descendant or renew an attachment.
    assert!(
        f.apply(command(
            &r,
            &s,
            5,
            Action::Attach {
                parent: nested.clone(),
                child_id: "child-0".into()
            },
            true
        ))
        .await
        .is_err()
    );
    assert_eq!(f.status().await.unwrap(), s);
    h.clock.0.store(NOW, Ordering::SeqCst);
    for n in 4..64 {
        stop(&f, &r, n, &parent).await;
    }
    let full = f.status().await.unwrap();
    assert_eq!(full.events.len(), 63);
    assert!(
        f.apply(command(
            &r,
            &full,
            64,
            Action::Stop { branch_id: nested },
            false
        ))
        .await
        .is_err()
    );
    let stopped = stop(&f, &r, 65, "root").await;
    assert_eq!(stopped.events.len(), 64);
    assert!(!stopped.active);
    assert_eq!(stopped.attachments.len(), 1);
    assert_eq!(
        Coordination::new(c.ledger.clone(), &r.children[0].reservation.root_id)
            .unwrap()
            .status()
            .await
            .unwrap()
            .allocations[&rec.issuance_key]
            .state,
        ReservationState::Allocated
    );
}
#[tokio::test]
async fn family_missing_corrupt_state_context_alias_and_legacy_enrollment_refuse() {
    let Some((h, r, f)) = setup(1, 1).await else {
        return;
    };
    attach(&f, &r, 1, "root", "child-0", false).await;
    let c = child(&h, &r, 0).await;
    let rec = c.issue().await.unwrap().record;
    let g = grant(&c, &rec);
    let key = format!("{}/family/state", h.prefix);
    let original = serde_json::to_vec(&f.status().await.unwrap()).unwrap();
    for raw in [
        None,
        Some(b"{}".as_slice()),
        Some(b"{\"profile\":null}".as_slice()),
    ] {
        let endpoint = format!(
            "{}/v3/kv/{}",
            std::env::var("ETCD_ENDPOINT").unwrap(),
            if raw.is_some() { "put" } else { "deleterange" }
        );
        let mut request = json!({"key":STANDARD.encode(&key)});
        if let Some(raw) = raw {
            request["value"] = json!(STANDARD.encode(raw));
        }
        assert!(
            reqwest::Client::new()
                .post(endpoint)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert!(f.status().await.is_err());
        assert!(
            c.ledger
                .claim(&g, &rec.grant_digest, "corrupt-state")
                .await
                .is_err()
        );
    }
    reqwest::Client::new()
        .post(format!(
            "{}/v3/kv/put",
            std::env::var("ETCD_ENDPOINT").unwrap()
        ))
        .json(&json!({"key":STANDARD.encode(key),"value":STANDARD.encode(original)}))
        .send()
        .await
        .unwrap();
    let mut wrong = r.clone();
    wrong.family_id = "different-family".into();
    let configured = Selection {
        registration: wrong,
        child_id: "child-0".into(),
    }
    .attach(h.ledger.clone())
    .unwrap();
    assert!(
        configured
            .claim(&g, &rec.grant_digest, "alias-family")
            .await
            .is_err()
    );
    let legacy = Harness::new().await.unwrap();
    let installed = legacy.bootstrap().await;
    assert!(
        legacy
            .post(&legacy.ack(&installed), true)
            .await
            .0
            .is_success()
    );
    let mut legacy_registration = r.clone();
    legacy_registration.namespace = legacy.prefix.clone();
    assert!(
        Family::new(legacy.ledger.clone(), legacy_registration)
            .unwrap()
            .enroll()
            .await
            .is_err()
    );
    assert_eq!(f.status().await.unwrap().attachments.len(), 1);
}
#[tokio::test]
async fn family_shipping_cli_mtls_enroll_apply_replay_export_and_verify() {
    use axum::{Json, Router, routing::post};
    use kedgeflow::clock::{Clock, SystemClock};
    let Some((h, mut r, _)) = setup(1, 1).await else {
        return;
    };
    let now = SystemClock.now_ms();
    r.valid_from = now - 1000;
    r.expires_at = now + 60000;
    let namespace = format!("{}-cli", h.prefix);
    r.namespace = namespace.clone();
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let proxy = support::serve_tls(
        &h.agent_pki,
        Router::new().route(
            "/v3/kv/txn",
            post(move |Json(v): Json<Value>| {
                let endpoint = endpoint.clone();
                async move {
                    Json(
                        reqwest::Client::new()
                            .post(format!("{endpoint}/v3/kv/txn"))
                            .json(&v)
                            .send()
                            .await
                            .unwrap()
                            .json::<Value>()
                            .await
                            .unwrap(),
                    )
                }
            }),
        ),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, raw: &[u8]| {
        let p = dir.path().join(name);
        std::fs::write(&p, raw).unwrap();
        p
    };
    let ca = write("ca.pem", h.agent_pki.ca.as_bytes());
    let cert = write("cert.pem", h.agent_pki.client.as_bytes());
    let key = write("key.pem", h.agent_pki.client_key.as_bytes());
    let token = write("token", b"generated-fixture-token");
    let cfg=write("config.json",&serde_json::to_vec(&json!({"registration":r,"etcd_endpoint":proxy.url,"etcd_prefix":namespace,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":token})).unwrap());
    let cli = || {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-family"));
        c.arg("--config").arg(&cfg);
        c
    };
    assert!(
        cli()
            .arg("--check")
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    let out = cli().arg("--enroll").output().await.unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !cli()
            .arg("--enroll")
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    assert!(
        !cli()
            .arg("--enroll-witness")
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    let out = cli().arg("--status").output().await.unwrap();
    assert!(out.status.success());
    let initial: State = serde_json::from_slice(&out.stdout).unwrap();
    let mut cmd = Command::sign(
        CommandPayload {
            family_digest: r.digest().unwrap(),
            operation_key: "1".repeat(64),
            expected_head: initial.head,
            issued_at: now,
            expires_at: now + 30000,
            action: Action::Attach {
                parent: "root".into(),
                child_id: "child-0".into(),
            },
        },
        "owner",
        &SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap();
    let signed = write("command.json", &serde_json::to_vec(&cmd).unwrap());
    for _ in 0..2 {
        let out = cli()
            .arg("--apply")
            .arg("--command")
            .arg(&signed)
            .output()
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    cmd.payload.operation_key = "9".repeat(64);
    let substituted = write("substituted.json", &serde_json::to_vec(&cmd).unwrap());
    assert!(
        !cli()
            .arg("--apply")
            .arg("--command")
            .arg(substituted)
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    let trust = AuditTrust {
        registration: r,
        namespace,
        observer_id: "family-observer".into(),
        observer_keys: BTreeMap::from([(
            "key-33".into(),
            STANDARD.encode(SigningKey::from_bytes(&[33; 32]).verifying_key().as_bytes()),
        )]),
    };
    let pins = write("trust.json", &serde_json::to_vec(&trust).unwrap());
    let seed = write("observer.key", STANDARD.encode([33; 32]).as_bytes());
    let out = cli()
        .arg("--export")
        .arg("--trust")
        .arg(&pins)
        .arg("--observer-id")
        .arg("family-observer")
        .arg("--observer-key-id")
        .arg("key-33")
        .arg("--observer-key")
        .arg(seed)
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bundle: family::Bundle = serde_json::from_slice(&out.stdout).unwrap();
    family::verify(&bundle, &trust).unwrap();
    assert_eq!(bundle.state.events.len(), 1);
    assert_eq!(bundle.state.attachments.len(), 1);
    let bundle = write("bundle.json", &out.stdout);
    assert!(
        cli()
            .arg("--verify")
            .arg("--bundle")
            .arg(bundle)
            .arg("--trust")
            .arg(pins)
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
}

#[tokio::test]
async fn family_signed_commands_and_selection_cannot_replay_into_another_namespace() {
    let Some((h, r, f)) = setup(1, 1).await else {
        return;
    };
    let original = command(
        &r,
        &f.status().await.unwrap(),
        1,
        Action::Attach {
            parent: "root".into(),
            child_id: "child-0".into(),
        },
        false,
    );
    let destination = EtcdLedger::new(
        reqwest::Client::new(),
        std::env::var("ETCD_ENDPOINT").unwrap(),
        format!("{}-copy", h.prefix),
    )
    .unwrap()
    .with_clock(h.clock.clone());
    assert!(Family::new(destination.clone(), r.clone()).is_err());
    assert!(
        Selection {
            registration: r.clone(),
            child_id: "child-0".into()
        }
        .attach(destination.clone())
        .is_err()
    );
    let mut other = r.clone();
    other.namespace = destination.namespace().into();
    let second = Family::new(destination, other.clone()).unwrap();
    second.enroll().await.unwrap();
    assert_ne!(r.digest().unwrap(), other.digest().unwrap());
    assert!(second.apply(original.clone()).await.is_err());
    f.apply(original).await.unwrap();
    assert_eq!(second.status().await.unwrap().attachments.len(), 0);
    assert_eq!(f.status().await.unwrap().attachments.len(), 1);
}
