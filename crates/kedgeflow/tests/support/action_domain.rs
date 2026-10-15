//! Fresh paired controls against native etcd; inverse execution stays closed.
use super::*;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::action_domain::{Lane, PROFILE as PAIR, Selection, Topology};
use kedgeflow::recovery::ExecutionRecord;
use std::sync::atomic::{AtomicBool, AtomicUsize};

fn inverse_fixture(f: &mut Fixture) {
    f.descriptor["action"] = json!("capacity.restore");
    f.proposal["action"]["id"] = f.descriptor["action"].clone();
    f.repin_descriptor();
}
fn other_forward_fixture(f: &mut Fixture) {
    f.descriptor["action"] = json!("capacity.replace");
    f.descriptor["concurrency"]["conflict_domain"] = json!("second-approved-domain");
    f.proposal["action"]["id"] = f.descriptor["action"].clone();
    f.repin_descriptor();
}
fn other_inverse_fixture(f: &mut Fixture) {
    inverse_fixture(f);
    f.descriptor["concurrency"]["conflict_domain"] = json!("second-approved-domain");
    f.repin_descriptor();
}
async fn topology() -> Option<Topology> {
    let f = Harness::new().await?;
    let i = Harness::with_setup(None, NOW, inverse_fixture).await?;
    Some(Topology {
        profile: PAIR.into(),
        forward: f.registration.clone(),
        inverse: i.registration.clone(),
    })
}
pub(super) async fn harness(t: &Topology, lane: Lane, prefix: Option<String>) -> Harness {
    Harness::with_environment_and_pair(
        None,
        NOW,
        if lane == Lane::Forward {
            |_| {}
        } else {
            inverse_fixture
        },
        None,
        None,
        Some((
            Selection {
                topology: t.clone(),
                lane,
            },
            prefix,
        )),
    )
    .await
    .unwrap()
}
fn raw(h: &Harness) -> EtcdLedger {
    EtcdLedger::new(
        reqwest::Client::new(),
        std::env::var("ETCD_ENDPOINT").unwrap(),
        &h.prefix,
    )
    .unwrap()
    .with_clock(h.clock.clone())
}
fn base(h: &Harness) -> String {
    format!(
        "{}/domains/{}",
        h.prefix,
        URL_SAFE_NO_PAD.encode(&h.registration.scope.conflict_domain)
    )
}
async fn ready() -> Option<(Topology, Harness, Harness)> {
    let t = topology().await?;
    let f = harness(&t, Lane::Forward, None).await;
    let i = harness(&t, Lane::Inverse, Some(f.prefix.clone())).await;
    for h in [&f, &i] {
        let installed = h.bootstrap().await;
        assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    }
    Some((t, f, i))
}
async fn write(_h: &Harness, key: &str, value: &str) {
    let reply = reqwest::Client::new()
        .post(format!(
            "{}/v3/kv/put",
            std::env::var("ETCD_ENDPOINT").unwrap()
        ))
        .json(&json!({"key":STANDARD.encode(key),"value":STANDARD.encode(value)}))
        .send()
        .await
        .unwrap();
    assert!(reply.status().is_success());
}

#[tokio::test]
async fn paired_domain_material_is_closed_bounded_and_physically_correlated() {
    let Some(t) = topology().await else {
        return;
    };
    let good = serde_json::to_value(&t).unwrap();
    assert_eq!(
        Topology::decode(&serde_json::to_vec(&good).unwrap()).unwrap(),
        t
    );
    for field in [
        "profile",
        "forward.tenant",
        "inverse.ownership_epoch",
        "inverse.scope.resource",
        "inverse.scope.conflict_domain",
        "inverse.scope.action",
        "inverse.scope.adapter_contract",
        "inverse.scope.predicate_descriptor",
        "forward.trust_digest",
        "inverse.issuer_keys",
        "inverse.acknowledger.public_key_hex",
    ] {
        let mut bad = good.clone();
        match field {
            "profile" => bad["profile"] = json!("unknown"),
            "forward.tenant" => bad["forward"]["tenant"] = json!("another-tenant"),
            "inverse.ownership_epoch" => bad["inverse"]["ownership_epoch"] = json!(999),
            "inverse.scope.resource" => {
                bad["inverse"]["scope"]["resource"]["incarnation"] = json!("replacement")
            }
            "inverse.scope.conflict_domain" => {
                bad["inverse"]["scope"]["conflict_domain"] = json!("other-domain")
            }
            "inverse.scope.action" => {
                bad["inverse"]["scope"]["action"] = good["forward"]["scope"]["action"].clone()
            }
            "inverse.scope.adapter_contract" => {
                bad["inverse"]["scope"]["adapter_contract"]["guard_scope"] =
                    json!(["another-resource"])
            }
            "inverse.scope.predicate_descriptor" => {
                bad["inverse"]["scope"]["predicate_descriptor"]["clauses"][0]["resource"]["id"] =
                    json!("another-resource")
            }
            "forward.trust_digest" => bad["forward"]["trust_digest"] = json!("invalid"),
            "inverse.issuer_keys" => bad["inverse"]["issuer_keys"] = json!({}),
            _ => bad["inverse"]["acknowledger"]["public_key_hex"] = json!("00"),
        }
        assert!(
            Topology::decode(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut bad = good.clone();
    bad["extra"] = json!(true);
    assert!(Topology::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    let duplicate = String::from_utf8(serde_json::to_vec(&good).unwrap())
        .unwrap()
        .replacen(
            '{',
            "{\"profile\":\"KF-PAIRED-ACTION-DOMAIN-0.1-draft\",",
            1,
        );
    assert!(Topology::decode(duplicate.as_bytes()).is_err());
    assert!(Topology::decode(&vec![b' '; (64 << 10) + 1]).is_err());
}

#[tokio::test]
async fn paired_domain_shipping_configuration_requires_explicit_valid_selection() {
    let Some(t) = topology().await else {
        return;
    };
    let config_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
    for (file, kind) in [
        ("control.example.json", 0),
        ("gateway.example.json", 1),
        ("recovery.example.json", 2),
        ("broker.example.json", 3),
        ("outcomes.example.json", 4),
        ("review.example.json", 5),
    ] {
        let original: Value =
            serde_json::from_slice(&std::fs::read(config_dir.join(file)).unwrap()).unwrap();
        let decode = |v: &Value| {
            let raw = serde_json::to_vec(v).unwrap();
            match kind {
                0 => kedgeflow::control_config::ControlConfig::decode(&raw).map(|_| ()),
                1 => kedgeflow::config::Config::decode(&raw).map(|_| ()),
                2 => kedgeflow::recovery_config::RecoveryConfig::decode(&raw).map(|_| ()),
                3 => kedgeflow::broker_config::BrokerConfig::decode(&raw).map(|_| ()),
                4 => {
                    kedgeflow::outcome_report_config::OutcomeReportConfig::decode(&raw).map(|_| ())
                }
                _ => serde_json::from_value::<kedgeflow::review_config::ReviewConfig>(v.clone())
                    .map(|_| ())
                    .map_err(kedgeflow::error::Error::from),
            }
        };
        assert!(decode(&original).is_ok(), "classic {file}");
        let mut paired = original.clone();
        paired["action_domain"] = json!(Selection {
            topology: t.clone(),
            lane: Lane::Forward
        });
        assert!(decode(&paired).is_ok(), "paired {file}");
        paired["action_domain"]["lane"] = json!("caller-selected");
        assert!(decode(&paired).is_err(), "lane {file}");
        paired["action_domain"] = Value::Null;
        assert!(decode(&paired).is_err(), "null {file}");
        paired["action_domain"] = json!(Selection {
            topology: t.clone(),
            lane: Lane::Forward
        });
        paired["action_domain"]["topology"]["forward"]["extra"] = json!("untrusted");
        assert!(decode(&paired).is_err(), "unknown {file}");
    }
    let example = std::fs::read(config_dir.join("action-domain.example.json")).unwrap();
    kedgeflow::action_domain_config::ActionDomainConfig::decode(&example).unwrap();
}

#[tokio::test]
async fn paired_domain_enrollment_is_create_only_and_cannot_adopt_legacy_or_stopped_state() {
    let Some(t) = topology().await else {
        return;
    };
    let h = harness(&t, Lane::Forward, None).await;
    let operator = raw(&h);
    t.enroll(&operator).await.unwrap();
    let mut changed = t.clone();
    changed.inverse.policy.epoch += 1;
    assert!(changed.enroll(&operator).await.is_err());
    assert!(t.enroll(&h.ledger).await.is_err());
    t.stop(&operator).await.unwrap();
    t.stop(&operator).await.unwrap();
    assert_eq!(t.status(&operator).await.unwrap()["stopped"], true);
    assert!(t.enroll(&operator).await.is_err());
    for suffix in [
        "policy",
        "ownership",
        "reservation-required",
        "control/installation",
        "control/history/head",
        "revocations/domain",
    ] {
        let legacy = Harness::new().await.unwrap();
        write(&legacy, &format!("{}/{suffix}", base(&legacy)), "legacy").await;
        assert!(t.enroll(&legacy.ledger).await.is_err(), "{suffix}");
        assert!(
            legacy
                .ledger
                .read_key(&format!("{}/paired-topology", base(&legacy)))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn paired_domain_controls_are_independent_and_inverse_port_cannot_spend() {
    let Some((t, mut f, i)) = ready().await else {
        return;
    };
    let first = f.issue().await.unwrap();
    assert!(f.issue().await.unwrap().reused);
    assert!(i.issue().await.is_err());
    let fs = f
        .ledger
        .control_snapshot(&f.registration.scope.conflict_domain)
        .await
        .unwrap();
    let is = i
        .ledger
        .control_snapshot(&i.registration.scope.conflict_domain)
        .await
        .unwrap();
    assert_ne!(fs.0.unwrap().digest, is.0.unwrap().digest);
    let g = reserved_history::grant(&f, &first.record);
    assert_eq!(g.fence, 1);
    assert!(raw(&f).publish_policy(&g).await.is_err());
    assert!(raw(&f).issue(&g, &first.record.grant_digest).await.is_err());
    assert!(f.ledger.publish_policy(&g).await.is_err());
    let mut legacy_f = Harness::new().await.unwrap();
    legacy_f.ledger = raw(&f);
    assert!(legacy_f.issue().await.is_err());
    // An inverse installation cannot revoke forward authority accidentally.
    i.revoke(RevocationTarget::Domain).await;
    f.f.proposal["qid"] = json!("another-forward-operation");
    let second = f.issue().await.unwrap();
    let next = reserved_history::grant(&f, &second.record);
    assert_eq!(next.fence, 2);
    assert_eq!(
        t.status(&raw(&f)).await.unwrap()["inverse_execution_available"],
        false
    );
    let counter = kedgeflow::contracts::digest(
        "fence-resource",
        &json!({"tenant":f.registration.tenant,"resource":g.resources[0]}),
    )
    .unwrap();
    assert_eq!(
        f.ledger
            .read_key(&format!("{}/fence-counter/{counter}", f.prefix))
            .await
            .unwrap()
            .unwrap(),
        b"2"
    );
}

#[tokio::test]
async fn paired_domain_global_operation_identity_and_resource_fences_span_distinct_action_controls()
{
    let Some((_, first, _)) = ready().await else {
        return;
    };
    let issued = first.issue().await.unwrap();
    let f = Harness::with_setup(None, NOW, other_forward_fixture)
        .await
        .unwrap();
    let i = Harness::with_setup(None, NOW, other_inverse_fixture)
        .await
        .unwrap();
    let t = Topology {
        profile: PAIR.into(),
        forward: f.registration.clone(),
        inverse: i.registration.clone(),
    };
    let mut second = Harness::with_environment_and_pair(
        None,
        NOW,
        other_forward_fixture,
        None,
        None,
        Some((
            Selection {
                topology: t,
                lane: Lane::Forward,
            },
            Some(first.prefix.clone()),
        )),
    )
    .await
    .unwrap();
    let install = second.bootstrap().await;
    assert!(
        second
            .post(&second.ack(&install), true)
            .await
            .0
            .is_success()
    );
    // Reusing the original QID under another installed action/domain cannot
    // replace its admission or obtain another fence/allocation.
    assert!(second.issue().await.is_err());
    second.f.proposal["qid"] = json!("second-action-operation");
    let next = second.issue().await.unwrap();
    let a = reserved_history::grant(&first, &issued.record);
    let b = reserved_history::grant(&second, &next.record);
    assert_eq!(a.resources, b.resources);
    assert_ne!(a.action, b.action);
    assert_ne!(a.conflict_domain, b.conflict_domain);
    assert_eq!((a.fence, b.fence), (1, 2));
    assert_eq!(first.issue().await.unwrap().record, issued.record);
}

#[tokio::test]
async fn paired_domain_topology_pins_cannot_be_switched_or_omitted() {
    let Some((t, h, i)) = ready().await else {
        return;
    };
    let selected = Selection {
        topology: t.clone(),
        lane: Lane::Inverse,
    };
    assert!(h.ledger.control_snapshot("wrong-domain").await.is_err());
    assert!(
        h.ledger
            .clone()
            .with_action_domain(selected.clone())
            .is_err()
    );
    let r = reserved_leaf::registration(&h, 1);
    assert!(
        raw(&h)
            .requiring_control(None)
            .with_reservation(r.clone())
            .unwrap()
            .with_action_domain(selected)
            .is_err()
    );
    assert!(i.ledger.clone().with_reservation(r).is_err());
    let record = h.issue().await.unwrap().record;
    let g = reserved_history::grant(&h, &record);
    assert!(
        i.ledger
            .claim(&g, &record.grant_digest, "wrong-lane")
            .await
            .is_err()
    );
    write(&h, &format!("{}/paired-topology", base(&h)), "{}").await;
    assert!(h.issue().await.is_err());
    assert!(t.status(&raw(&h)).await.is_err());
    assert!(t.enroll(&raw(&h)).await.is_err());
    assert!(
        h.ledger
            .execution_status(&g, &record.grant_digest)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn paired_domain_stop_blocks_fresh_authority_but_keeps_original_query_only_recovery() {
    let Some((t, mut h, i)) = ready().await else {
        return;
    };
    let record = h.issue().await.unwrap().record;
    let c = reserved_history::claim(&h, &record, "original-paired-attempt").await;
    h.ledger
        .authorize_dispatch(&c.grant, &record.grant_digest, &c.attempt_id)
        .await
        .unwrap();
    t.stop(&raw(&h)).await.unwrap();
    assert!(h.issue().await.is_err());
    assert!(i.issue().await.is_err());
    assert!(
        h.ledger
            .authorize_dispatch(&c.grant, &record.grant_digest, &c.attempt_id)
            .await
            .is_err()
    );
    assert!(
        h.ledger
            .claim(&c.grant, &record.grant_digest, "another-attempt")
            .await
            .is_err()
    );
    h.clock.0.store(NOW + 6000, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = reserved_history::worker(&h, &c, &record.grant_digest, "committed", calls.clone());
    let result = worker.recover(&c).await.unwrap();
    assert_eq!(
        result.receipt_digest,
        worker.recover(&c).await.unwrap().receipt_digest
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.ledger
            .execution_status(&c.grant, &record.grant_digest)
            .await
            .unwrap()
            .attempt_id
            .as_deref(),
        Some(c.attempt_id.as_str())
    );
    h.f.proposal["qid"] = json!("new-after-stop");
    assert!(h.issue().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paired_domain_stop_racing_claim_is_compared_in_native_consumption_cas() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    let Some((t, mut h, _)) = ready().await else {
        return;
    };
    let record = h.issue().await.unwrap().record;
    let g = reserved_history::grant(&h, &record);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let once = Arc::new(AtomicBool::new(true));
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let router = Router::new().route(
        "/v3/kv/txn",
        post({
            let entered = entered.clone();
            let release = release.clone();
            move |Json(v): Json<Value>| {
                let entered = entered.clone();
                let release = release.clone();
                let once = once.clone();
                let endpoint = endpoint.clone();
                async move {
                    let claiming = v["success"].as_array().is_some_and(|ops| {
                        ops.iter().any(|o| {
                            o["request_put"]["key"]
                                .as_str()
                                .and_then(|s| STANDARD.decode(s).ok())
                                .is_some_and(|b| {
                                    String::from_utf8_lossy(&b)
                                        .ends_with("/outbox/b3JpZ2luYWwtcmFjZQ")
                                })
                        })
                    });
                    if claiming && once.swap(false, Ordering::SeqCst) {
                        entered.notify_one();
                        release.notified().await;
                    }
                    let r = reqwest::Client::new()
                        .post(format!("{endpoint}/v3/kv/txn"))
                        .json(&v)
                        .send()
                        .await
                        .unwrap();
                    (
                        r.status(),
                        [("content-type", "application/json")],
                        r.bytes().await.unwrap(),
                    )
                        .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let proxy = live_agent::Running(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    let direct = raw(&h);
    h.ledger = EtcdLedger::new(reqwest::Client::new(), url, &h.prefix)
        .unwrap()
        .with_clock(h.clock.clone())
        .with_action_domain(Selection {
            topology: t.clone(),
            lane: Lane::Forward,
        })
        .unwrap();
    let execution = ExecutionRecord {
        signed_grant: record.signed_grant.clone(),
        tool: "node_drain".into(),
        parameters: h.f.proposal["parameters"].clone(),
    };
    let ledger = h.ledger.clone();
    let gd = record.grant_digest.clone();
    let grant = g.clone();
    let pending = tokio::spawn(async move {
        ledger
            .claim_recorded(&grant, &gd, "original-race", &execution)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    t.stop(&direct).await.unwrap();
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    assert!(
        h.ledger
            .execution_status(&g, &record.grant_digest)
            .await
            .unwrap()
            .attempt_id
            .is_none()
    );
    drop(proxy);
}

#[tokio::test]
async fn paired_domain_shipping_cli_uses_fixed_mtls_and_recovers_original_enrollment_and_stop() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    let Some(t) = topology().await else {
        return;
    };
    let h = Harness::new().await.unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let namespace = h.prefix.clone();
    let router = Router::new().route(
        "/v3/kv/txn",
        post({
            let requests = requests.clone();
            move |headers: http::HeaderMap, Json(v): Json<Value>| {
                let requests = requests.clone();
                let endpoint = endpoint.clone();
                let namespace = namespace.clone();
                async move {
                    assert_eq!(headers["authorization"], "paired-operator-token");
                    requests.fetch_add(1, Ordering::SeqCst);
                    for op in v["success"].as_array().unwrap() {
                        if let Some(k) = op["request_put"]["key"].as_str() {
                            let bytes = STANDARD.decode(k).unwrap();
                            let key = String::from_utf8(bytes).unwrap();
                            assert!(key.starts_with(&format!("{namespace}/domains/")));
                            assert!(
                                ["/paired-topology", "/control-required", "/paired-stop"]
                                    .iter()
                                    .any(|s| key.ends_with(s))
                            );
                        }
                    }
                    let r = reqwest::Client::new()
                        .post(format!("{endpoint}/v3/kv/txn"))
                        .json(&v)
                        .send()
                        .await
                        .unwrap();
                    (
                        r.status(),
                        [("content-type", "application/json")],
                        r.bytes().await.unwrap(),
                    )
                        .into_response()
                }
            }
        }),
    );
    let proxy = support::serve_tls(&h.agent_pki, router).await;
    let temp = tempfile::tempdir().unwrap();
    let ca = temp.path().join("ca.pem");
    let cert = temp.path().join("client.pem");
    let key = temp.path().join("client-key.pem");
    let token = temp.path().join("token");
    std::fs::write(&ca, &h.agent_pki.ca).unwrap();
    std::fs::write(&cert, &h.agent_pki.client).unwrap();
    std::fs::write(&key, &h.agent_pki.client_key).unwrap();
    std::fs::write(&token, "paired-operator-token").unwrap();
    let path = temp.path().join("operator.json");
    let config = json!({"topology":t,"etcd_endpoint":proxy.url,"etcd_prefix":h.prefix,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":token});
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let run = |op: &str| {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-action-domain"));
        c.arg("--config").arg(&path).arg(op);
        c
    };
    let checked = run("--check").output().await.unwrap();
    assert!(checked.status.success());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    for op in [
        "--enroll", "--enroll", "--status", "--stop", "--stop", "--status",
    ] {
        let out = run(op).output().await.unwrap();
        assert!(
            out.status.success(),
            "{op}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let status: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(status["execution_authority"], false);
        assert_eq!(status["inverse_execution_available"], false);
        if op == "--stop" {
            assert_eq!(status["stopped"], true);
        }
    }
    assert!(!run("--enroll").output().await.unwrap().status.success());
    let mut bad = config.clone();
    bad["etcd_endpoint"] = json!("http://127.0.0.1:2379");
    assert!(
        kedgeflow::action_domain_config::ActionDomainConfig::decode(
            &serde_json::to_vec(&bad).unwrap()
        )
        .is_err()
    );
    bad = config;
    bad["etcd_endpoint"] = json!("https://localhost:2379/subpath");
    assert!(
        kedgeflow::action_domain_config::ActionDomainConfig::decode(
            &serde_json::to_vec(&bad).unwrap()
        )
        .is_err()
    );
}
