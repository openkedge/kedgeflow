//! Actual official MCP agent -> admission/issuer -> broker/gateway -> shipping
//! managed controller/current SQL source; independent operating/physical audit.
use super::super::super::process::agent as common;
use super::*;
#[path = "kube_drain_acceptance_relay.rs"]
mod acceptance_relay;

#[derive(Clone, Copy)]
enum Deployment {
    TypedServices,
    TypedReplyLoss,
    ShippingGateway,
    ShippingServices,
    ShippingReplyLoss,
}

fn native_ledger(
    r: &Ready,
    source: &SourceProcess,
    pki: &support::Pki,
    credential: &str,
) -> kedgeflow::ledger::EtcdLedger {
    let client = kedgeflow::tls::pinned_client_pem(
        pki.ca.as_bytes(),
        pki.client.as_bytes(),
        pki.client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    kedgeflow::family::Selection {
        registration: r.r.clone(),
        child_id: "child-1".into(),
    }
    .attach(
        kedgeflow::ledger::EtcdLedger::new(
            client.client().clone(),
            &source._relay.url,
            &r.r.namespace,
        )
        .unwrap()
        .with_auth_token(credential)
        .unwrap(),
    )
    .unwrap()
}
async fn recover(
    r: &Ready,
    source: &SourceProcess,
    process: &Process,
    identity: &[support::Pki],
) -> Value {
    // This recovery root contains its own native/query credentials and outcome
    // signer only. It never imports the controller/source/observer signing keys.
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = directory.path().canonicalize().unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let native = &identity[7];
    let ca = write("native-ca.pem", native.ca.as_bytes());
    let cert = write("native.pem", native.client.as_bytes());
    let key = write("native.key", native.client_key.as_bytes());
    let native_token = write("native.token", OUTCOME_ETCD.as_bytes());
    let query_ca = write("query-ca.pem", process.query_tls.0.as_bytes());
    let query_cert = write("query.pem", process.query_tls.1.as_bytes());
    let query_key = write("query.key", process.query_tls.2.as_bytes());
    let query_token = write("query.token", OUTCOME.as_bytes());
    let signer = write("outcome.key", STANDARD.encode([14; 32]).as_bytes());
    let cfg = json!({"family":{"registration":r.r,"child_id":"child-1"},"reservation":r.r.child("child-1").unwrap().reservation,
      "etcd_endpoint":source._relay.url,"etcd_prefix":r.r.namespace,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":native_token,
      "gateway_audience":r.physical.registration.scope.audience,"grant_keys":public(5),"query_url":format!("{}/query",process.endpoint),"query_ca":query_ca,
      "query_certificate":query_cert,"query_private_key":query_key,"query_token_file":query_token,"receipt_key_id":"key-14","receipt_signing_key_file":signer,
      "source_id":"spiffe://test/outcome","page_size":8,"poll_interval_ms":100});
    let file = write("recovery.json", &canonical(&cfg).unwrap());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut attempts = Vec::new();
    loop {
        let out = tokio::time::timeout_at(
            deadline,
            tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-recover"))
                .arg("--config")
                .arg(&file)
                .arg("--once")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        let diagnostic = String::from_utf8_lossy(&out.stderr);
        let mut sweep: Value = serde_json::from_slice(&out.stdout).unwrap();
        attempts
            .push(json!({"success":out.status.success(),"sweep":sweep,"diagnostic":diagnostic}));
        assert_eq!(sweep["examined"], 1);
        if out.status.success() {
            assert_eq!(sweep["reported"], 1);
            assert_eq!(sweep["unavailable"], 0);
            sweep["attempts"] = json!(attempts);
            return sweep;
        }
        // A normal recovery service polls again after a guarded read loses its
        // epoch. Exercise that query-only behavior under one original bound;
        // retain every failed sweep and refuse all other failures. This never
        // changes a grant, exchanges credentials or repeats physical dispatch.
        assert_eq!(sweep["reported"], 0);
        assert_eq!(sweep["deferred"], 0);
        assert_eq!(sweep["unavailable"], 1);
        assert!(
            diagnostic.contains("reservation read epoch raced")
                || diagnostic.contains("native guarded read epoch raced")
                || diagnostic.contains("invalid guarded proof read"),
            "shipping managed recovery refused: {diagnostic}; sweep={sweep}"
        );
        assert!(
            attempts.len() < 3,
            "bounded recovery read races: {attempts:?}"
        );
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + Duration::from_millis(100)),
        )
        .await;
    }
}
async fn original_permit(
    r: &Ready,
    acceptance: &proof::Acceptance,
    context: &kedgeflow::managed_drain_store::Context,
) -> Value {
    // This physical child has the ordinary domain layout, not a paired SQL lane.
    assert!(r.r.child("child-1").unwrap().topology.is_none());
    let (grant, _) = context.validate_origin(&acceptance.origin).unwrap();
    let attempt = &acceptance.origin.original.attempt_id;
    let key = format!(
        "{}/domains/{}/roots/{}/attempts/{}/credential-permit",
        r.r.namespace,
        URL_SAFE_NO_PAD.encode(grant.conflict_domain.as_bytes()),
        URL_SAFE_NO_PAD.encode(grant.root_id.as_bytes()),
        URL_SAFE_NO_PAD.encode(attempt.as_bytes())
    );
    let raw = r.physical.ledger.read_key(&key).await.unwrap().unwrap();
    let permit = kedgeflow::contracts::strict_value(&raw).unwrap();
    kedgeflow::broker_authorization::validate_permit(&permit).unwrap();
    assert_eq!(canonical(&permit).unwrap(), raw);
    assert_eq!(
        permit["grant_digest"],
        acceptance.origin.original.grant_digest
    );
    assert_eq!(permit["root_id"], grant.root_id);
    assert_eq!(permit["attempt_id"], *attempt);
    assert_eq!(permit["gateway_workload"], "spiffe://test/gateway");
    assert_eq!(
        permit["target_audience"],
        context.enrollment.target_audience
    );
    assert_eq!(permit["target_scope"], context.enrollment.target_scope);
    assert!(permit["authorized_at"].as_i64().unwrap() < permit["expires_at"].as_i64().unwrap());
    assert!(permit["expires_at"].as_i64().unwrap() <= grant.expires_at);
    permit
}
async fn run_deployment(mode: Deployment) {
    let discard_reply = matches!(mode, Deployment::TypedReplyLoss);
    let transport_loss = matches!(mode, Deployment::ShippingReplyLoss);
    let unknown = discard_reply || transport_loss;
    let shipping_gateway = matches!(
        mode,
        Deployment::ShippingGateway | Deployment::ShippingServices | Deployment::ShippingReplyLoss
    );
    let shipping_authorities = matches!(
        mode,
        Deployment::ShippingServices | Deployment::ShippingReplyLoss
    );
    let links = common::Links::new().await;
    let gateway = links.gateway();
    let broker = links.broker();
    let sink = SinkServer::new(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let private_listener = if transport_loss {
        Some(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap())
    } else {
        None
    };
    let controller_listen = private_listener
        .as_ref()
        .map(|listener| listener.local_addr().unwrap())
        .unwrap_or(listen);
    let external = format!("https://{listen}");
    let (r, identity, source, mut source_child) = Box::pin(setup_source_deployment(
        Some(sink.policy(30000, 16)),
        format!("https://{listen}/accept"),
        Some(&gateway),
        shipping_authorities,
    ))
    .await;
    let process = Process::with_broker_endpoint(
        &r,
        &source,
        &identity,
        controller_listen,
        &broker,
        transport_loss.then_some(external.as_str()),
    );
    let supervisor = SupervisorProcess::new(&r, &source, &identity, &sink);
    process.json("check").await;
    let tls = kedgeflow::tls::server_config_pem(
        &std::fs::read(process.directory.path().join("server.pem")).unwrap(),
        &std::fs::read(process.directory.path().join("server.key")).unwrap(),
        &std::fs::read(process.directory.path().join("workload-ca.pem")).unwrap(),
    )
    .unwrap();
    let context = Store::new(r.physical.ledger.clone()).unwrap().context;
    let (relay, controller_listener) = if transport_loss {
        (
            Some(acceptance_relay::start(
                listener,
                format!("https://{controller_listen}"),
                context.clone(),
                &identity,
            )),
            private_listener.unwrap(),
        )
    } else {
        (None, listener)
    };
    let managed = common::ManagedServing {
        ledger: native_ledger(&r, &source, &identity[6], GATEWAY_ETCD),
        evidence: common::ManagedEvidence {
            client: source.assembler.clone(),
            endpoint: context.enrollment.current_sql.evidence_endpoint.clone(),
            token: EVIDENCE.into(),
            enrollment_digest: context.enrollment.digest().unwrap(),
        },
    };
    let mut serving = Box::pin(common::serve_deployment(
        &r,
        links,
        &process.endpoint,
        process.gateway_transport.clone(),
        tls,
        Some(managed),
        discard_reply,
        shipping_gateway.then(|| common::ShippingGateway {
            native_endpoint: source._relay.url.clone(),
            credential: GATEWAY_ETCD.into(),
            identity: identity[6].clone(),
        }),
        shipping_authorities.then(|| common::authorities::Material {
            native_endpoint: source._relay.url.clone(),
            control: identity[8].clone(),
            control_credential: CONTROL_ETCD.into(),
            broker: identity[9].clone(),
            broker_credential: BROKER_ETCD.into(),
        }),
    ))
    .await;
    serving.config["state"] = json!(r.saga.status().await.unwrap());
    serving.config["expectedState"] = json!(if unknown { "unknown" } else { "accepted" });
    let file = serving.directory.path().join("agent.json");
    std::fs::write(&file, canonical(&serving.config).unwrap()).unwrap();
    let before = sql_rows(&r).await;
    source.pending_pause.armed.store(true, Ordering::SeqCst);
    drop(controller_listener);
    let mut child = process.start().await;
    // Preparation may outlast the ordinary installation ACK. Refresh it before
    // SDK admission; the grant/source/dispatch validity bounds remain unchanged.
    Box::pin(refresh(&r.physical)).await;
    let first = common::run_node_with_log(
        file.clone(),
        if shipping_gateway {
            vec![
                serving.directory.path().join("gateway/gateway.log"),
                process.directory.path().join("controller.log"),
                serving.directory.path().join("control/service.log"),
                serving.directory.path().join("broker/service.log"),
            ]
        } else {
            vec![]
        },
    )
    .await;
    assert_eq!(
        serving.dispatch.discarded.load(Ordering::SeqCst),
        usize::from(discard_reply),
        "the loss case must discard an actual fully verified original adapter reply"
    );
    let acceptance = if transport_loss {
        assert!(
            first["managed_acceptance"].is_null(),
            "lost HTTP acceptance cannot be a full first SDK proof"
        );
        let relay = &relay.as_ref().unwrap().relay;
        assert_eq!(relay.accepts.load(Ordering::SeqCst), 1);
        assert_eq!(relay.discarded.load(Ordering::SeqCst), 1);
        None
    } else {
        let raw_acceptance = if shipping_gateway {
            // This is the full first reply parsed by the actual official SDK from
            // the separate shipping process, not an in-process adapter inspection.
            assert!(serving.dispatch.reply.lock().unwrap().is_none());
            first["managed_acceptance"].clone()
        } else {
            serving.dispatch.reply.lock().unwrap().clone().expect("original verified adapter reply")
            ["structuredContent"]["kedgeflow_managed_drain_acceptance"].clone()
        };
        let acceptance: kedgeflow::managed_drain_acceptance::Proof =
            serde_json::from_value(raw_acceptance).unwrap();
        acceptance.verify(&context).unwrap();
        Some(acceptance)
    };
    let original_acceptance = acceptance
        .as_ref()
        .map(|proof| proof.acceptance.clone())
        .unwrap_or_else(|| relay.as_ref().unwrap().relay.acceptance());
    let broker_permit = if shipping_authorities {
        Some(Box::pin(original_permit(&r, &original_acceptance, &context)).await)
    } else {
        None
    };
    eprintln!(
        "managed SDK: original {} attempt={}",
        first["state"], first["attempt_id"]
    );
    assert_eq!(
        serving.minter.1.load(Ordering::SeqCst),
        usize::from(!shipping_authorities)
    );
    assert_eq!(
        serving.dispatch.calls.load(Ordering::SeqCst),
        usize::from(!shipping_gateway)
    );
    let until = std::time::Instant::now() + Duration::from_secs(5);
    while source.pending_pause.intercepted.load(Ordering::SeqCst) == 0 {
        assert!(child.try_wait().unwrap().is_none(), "{}", process.log());
        assert!(
            std::time::Instant::now() < until,
            "first actual Pending CAS not reached: {}",
            process.log()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    source.pending_pause.release.notify_one();
    let accepted = r.controller.state().await.unwrap().unwrap();
    assert!(accepted.body.steps.is_empty());
    let attempt = first["attempt_id"].as_str().unwrap();
    assert_eq!(accepted.body.accepted.attempt_id, attempt);
    let mut traces = vec![first.clone()];
    if unknown {
        // Stop the original root before any Pending/send; status recovery cannot
        // authorize the stopped work or replace its original grant/attempt.
        Box::pin(common::stop_root(&r, 601)).await;
    } else {
        let proof: kedgeflow::managed_drain_acceptance::Proof =
            serde_json::from_value(first["managed_acceptance"].clone())
                .expect("SDK must retain actual complete gateway acceptance proof");
        let report = proof.verify(&context).unwrap();
        assert_eq!(report["complete_acceptance_sources"], true);
        assert_eq!(report["physical_status"], "unresolved");
        assert_eq!(proof.sources.claims.len(), 1);
    }
    Box::pin(refresh(&r.physical)).await;
    child = process.start().await;
    if !unknown {
        let until = std::time::Instant::now() + Duration::from_secs(28);
        loop {
            assert!(child.try_wait().unwrap().is_none(), "{}", process.log());
            let state = match r.controller.state().await {
                Ok(s) => s,
                Err(kedgeflow::error::Error::Unavailable(message))
                    if message == "invalid guarded proof read"
                        || message == "native guarded read epoch raced" =>
                {
                    None
                }
                other => panic!("original controller query: {other:?}"),
            };
            if state.as_ref().is_some_and(|s| {
                s.body.steps.len() == 2
                    && s.body.steps.iter().all(|step| {
                        step.response
                            .as_ref()
                            .is_some_and(|p| (200..300).contains(&p.http_status))
                    })
            }) {
                break;
            }
            assert!(
                std::time::Instant::now() < until,
                "original managed physical work did not complete: {}; {}",
                process.log(),
                json!(state)
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
    let sweep = recover(&r, &source, &process, &identity).await;
    serving.config["mode"] = json!("resume");
    serving.config["expectedState"] = json!("accepted");
    serving.config["physical"]["token"] = json!(common::token(&r.physical));
    std::fs::write(&file, canonical(&serving.config).unwrap()).unwrap();
    let resumed = common::run_node(file).await;
    assert_eq!(resumed["attempt_id"], attempt);
    assert_eq!(resumed["grant_digest"], first["grant_digest"]);
    traces.push(resumed);
    if let Some(permit) = &broker_permit {
        assert_eq!(
            &Box::pin(original_permit(&r, &original_acceptance, &context)).await,
            permit,
            "query-only recovery must retain the identical original one-shot credential permit"
        );
    }
    let state = r.controller.state().await.unwrap().unwrap();
    if unknown {
        assert!(state.body.steps.is_empty());
        assert!(
            !r.api
                .inventory(&r.contract)
                .await
                .unwrap()
                .target(&r.contract)
                .unwrap()
                .unschedulable
        );
    }
    assert_eq!(
        serving.minter.1.load(Ordering::SeqCst),
        usize::from(!shipping_authorities)
    );
    assert_eq!(
        serving.dispatch.calls.load(Ordering::SeqCst),
        usize::from(!shipping_gateway)
    );
    assert_eq!(serving.source.baselines.load(Ordering::SeqCst), 1);
    assert_eq!(serving.source.collections.load(Ordering::SeqCst), 1);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    if let Some(slot) = Store::new(r.physical.ledger.clone())
        .unwrap()
        .status()
        .await
        .unwrap()
        .unwrap()
        .pending
    {
        // The read-only supervisor cannot steal the original consumed source
        // slot. Wait for that exact recorded expiry; never align or extend a
        // grant/token/deadline, refund a slot, or repeat an execution request.
        let remaining = slot.expires_at.saturating_sub(now());
        if remaining > 0 {
            assert!(remaining <= 5000);
            tokio::time::sleep(Duration::from_millis(remaining as u64 + 1)).await;
        }
    }
    let observation = supervisor.json("observe").await;
    assert_eq!(
        observation["observed"], true,
        "complete audit requires an actual retained observation"
    );
    if !unknown {
        assert_eq!(
            observation["operating"]["observation"]["resolution"],
            "observed_completed"
        );
    }
    let (bundle, trust) = supervisor::export(&supervisor, &r).await;
    let report = bundle.verify(&trust).unwrap();
    assert_eq!(before, sql_rows(&r).await);
    assert_eq!(report["held_forward"], 2);
    assert_eq!(report["held_compensation"], 1);
    if !unknown {
        assert_eq!(report["physical"]["physical_status"], "observed_completed");
        assert_eq!(report["operating"]["send_checks"], 2);
        assert_eq!(report["source_claims"], 4);
    } else {
        assert_eq!(report["source_claims"], 2);
        assert_eq!(report["controller_proofs"], 1);
        assert_eq!(report["operating"]["send_checks"], 0);
    }
    let acceptance = if let Some(proof) = acceptance {
        proof
    } else {
        // Reconstruct the explicitly historical accepted prefix only after the
        // complete independent current operating/physical audit has verified.
        let mut sources = bundle.evidence.source.clone();
        assert_eq!(sources.origin, original_acceptance.origin);
        assert_eq!(
            sources.events.get(..original_acceptance.events.len()),
            Some(original_acceptance.events.as_slice())
        );
        sources.events = original_acceptance.events.clone();
        let heads = sources
            .events
            .iter()
            .map(|event| event.digest().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        sources
            .claims
            .retain(|_, claim| heads.contains(&claim.operating_head_digest));
        let accepted = original_acceptance.proof.digest().unwrap();
        sources.controls.retain(|key, _| *key == accepted);
        let kedgeflow::managed_drain_store::Material::Aggregate(aggregate) =
            &bundle.evidence.materials[&bundle.evidence.current_aggregate_digest]
        else {
            panic!("complete independently verified aggregate required");
        };
        let authorization = aggregate.evidence.current.snapshot.members["child-1"].authorizations
            [&context.enrollment.operation_key]
            .clone();
        kedgeflow::managed_drain_acceptance::Proof {
            profile: kedgeflow::managed_drain_acceptance::PROFILE.into(),
            enrollment_digest: context.enrollment.digest().unwrap(),
            authorization,
            acceptance: original_acceptance,
            sources,
        }
    };
    acceptance.verify(&context).unwrap();
    if let Some(relay) = &relay {
        assert_eq!(
            relay.relay.accepts.load(Ordering::SeqCst),
            1,
            "query-only recovery cannot repeat original HTTP acceptance"
        );
        assert_eq!(relay.relay.discarded.load(Ordering::SeqCst), 1);
    }
    let name = if transport_loss {
        "managed-gateway-all-services-unknown"
    } else if shipping_authorities {
        "managed-gateway-all-services"
    } else if shipping_gateway {
        "managed-gateway-shipping"
    } else if discard_reply {
        "managed-gateway-unknown"
    } else {
        "managed-gateway-completed"
    };
    let broker_observations = if shipping_authorities {
        let log =
            std::fs::read_to_string(serving.directory.path().join("broker/service.log")).unwrap();
        let requests = log
            .matches("managed broker original exchange request decoded")
            .count();
        let responses = log
            .matches("managed broker original exchange issued;")
            .count();
        assert_eq!(
            (requests, responses),
            (1, 1),
            "actual broker process exchange observations: {log}"
        );
        Some(
            json!({"decoded_requests":requests,"issued_responses":responses,
            "scope":"actual protected process diagnostics; not an external mint-provider invocation counter"}),
        )
    } else {
        None
    };
    supervisor::save(
        name,
        &bundle,
        &trust,
        json!({"shipping_gateway":shipping_gateway,"shipping_controller":true,"shipping_source":true,"shipping_supervisor":true,"official_mcp_sdk":true,"native_admission_issuer_broker_gateway":true,
      "native_broker_mints":if shipping_authorities {Value::Null} else {json!(1)},
      "typed_broker_mints":serving.minter.1.load(Ordering::SeqCst),
      "broker_process_observations":broker_observations,
      "native_credential_permit":broker_permit,
      "shipping_admission_issuer":shipping_authorities,"shipping_broker":shipping_authorities,"in_process_adapter_dispatches":serving.dispatch.calls.load(Ordering::SeqCst),"provider_baselines":1,"provider_collections":1,"actual_preflight_witnesses":1,"restart_same_original":true,
      "lost_original_acceptance_reply":unknown,"discarded_verified_replies":serving.dispatch.discarded.load(Ordering::SeqCst),
      "actual_http_reply_loss":transport_loss,"discarded_signed_target_replies":relay.as_ref().map(|relay|relay.relay.discarded.load(Ordering::SeqCst)),
      "target_http_accept_requests":relay.as_ref().map(|relay|relay.relay.accepts.load(Ordering::SeqCst)),
      "acceptance_proof_origin":if transport_loss {"complete native reconstruction after signed original HTTP reply loss"} else if discard_reply {"original fully verified adapter reply before loss"} else {"original full first SDK reply"},
      "native_committed_is_acceptance":true,"interrupted_query_claim_remains_consumed":true,"sql_rows_unchanged":true,"shipping_recovery":sweep,"traces":traces,
      "controller_diagnostics":process.log(),"gateway_diagnostics":if shipping_gateway {std::fs::read_to_string(serving.directory.path().join("gateway/gateway.log")).unwrap()} else {String::new()},
      "authority_diagnostics":if shipping_authorities { ["control", "broker"].into_iter().map(|name| std::fs::read_to_string(serving.directory.path().join(name).join("service.log")).unwrap()).collect::<Vec<_>>().join("\n") } else {String::new()},
      "scope":if shipping_authorities {"generated co-located identities; actual protected kf-control, kf-broker, kf-proxy, managed controller/current SQL source/supervisor/recovery; official SDK and real SQL/etcd/Kubernetes; availability provider/manifest assembly remains an authenticated fixture using actual read-only Kubernetes and shipping SQL evidence; no independent custody/production RBAC claim"} else {"generated co-located fixture identities; actual SQL/native/Kubernetes and shipping managed source/controller/supervisor/recovery with official SDK/native services; optional shipping gateway; admission/issuer/broker hosted as typed services; no independent deployment/custody claim"}}),
    );
    if let Some(output) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
        let folder = PathBuf::from(output).join(name);
        if let Some(permit) = &broker_permit {
            std::fs::write(
                folder.join("broker-permit.json"),
                canonical(permit).unwrap(),
            )
            .unwrap();
        }
        std::fs::write(
            folder.join("acceptance.json"),
            canonical(&json!(acceptance)).unwrap(),
        )
        .unwrap();
        std::fs::write(
            folder.join("acceptance-verification.json"),
            canonical(&acceptance.verify(&context).unwrap()).unwrap(),
        )
        .unwrap();
    }
    serving.stop_shipping().await;
    source_child.kill().await.unwrap();
    source_child.wait().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_official_sdk_native_gateway_complete_sources_and_physical_audit() {
    Box::pin(run_deployment(Deployment::TypedServices)).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_official_sdk_lost_reply_query_only_recovery_after_root_stop() {
    Box::pin(run_deployment(Deployment::TypedReplyLoss)).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_official_sdk_shipping_gateway_protected_runtime_and_complete_audit()
 {
    Box::pin(run_deployment(Deployment::ShippingGateway)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_official_sdk_all_service_protected_configs_and_complete_audit() {
    Box::pin(run_deployment(Deployment::ShippingServices)).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kube_drain_real_managed_official_sdk_all_service_reply_loss_original_query_only_recovery()
{
    Box::pin(run_deployment(Deployment::ShippingReplyLoss)).await;
}
