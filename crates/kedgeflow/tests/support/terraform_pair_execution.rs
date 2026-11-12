//! Native compound authority and real metadata audit; no fabricated target result.
use super::terraform_apply::{Provider, configure_binding, write};
use super::*;
use axum::{Extension, Json, Router, extract::State, http::HeaderMap, routing::post};
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    auth::WorkloadIdentity,
    broker_authorization::{BrokerAuthorizer, BrokerRegistration, ExchangeRequest},
    clock::{Clock, SystemClock},
    contracts::{GrantVerifier, digest},
    recovery::ExecutionRecord,
    target_token::{ReferenceTokenMinter, TargetTokenMinter},
    terraform_apply as apply, terraform_pair, terraform_pair_apply as pair, tls,
};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::AtomicUsize,
};

struct Native {
    origin: String,
    counts: [AtomicUsize; 6],
}
async fn relay(
    State(n): State<Arc<Native>>,
    Extension(w): Extension<WorkloadIdentity>,
    headers: HeaderMap,
    Json(v): Json<Value>,
) -> Json<Value> {
    assert_eq!(w.as_str(), "spiffe://test/gateway");
    assert_eq!(headers["authorization"], "fixture-terraform-ledger-token");
    let answer: Value = reqwest::Client::new()
        .post(format!("{}/v3/kv/txn", n.origin))
        .json(&v)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    if answer["succeeded"] == true {
        for row in v["success"].as_array().into_iter().flatten() {
            if let Some(p) = row.get("request_put") {
                let key = String::from_utf8(STANDARD.decode(p["key"].as_str().unwrap()).unwrap())
                    .unwrap();
                let value = STANDARD.decode(p["value"].as_str().unwrap()).unwrap();
                let index = if key.contains("/nonces/") {
                    Some(0)
                } else if key.ends_with("/credential-permit") {
                    Some(1)
                } else if key.contains("/outbox/") && value == b"dispatch_authorized" {
                    Some(2)
                } else if key.contains("/terraform-pair/") && key.ends_with("/intent") {
                    Some(
                        if serde_json::from_slice::<Value>(&value).unwrap()["state"] == "started" {
                            3
                        } else {
                            4
                        },
                    )
                } else if key.contains("/outbox/")
                    && [b"committed".as_slice(), b"unknown"].contains(&value.as_slice())
                {
                    Some(5)
                } else {
                    None
                };
                if let Some(index) = index {
                    n.counts[index].fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }
    Json(answer)
}
fn counts(n: &Native) -> Vec<usize> {
    n.counts.iter().map(|n| n.load(Ordering::SeqCst)).collect()
}
async fn cli(root: &Path, config: &Path, command: &[&str], discard: bool) -> std::process::Output {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-terraform-pair-apply"));
    child
        .args([
            "--material-root",
            root.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .args(command)
        .kill_on_drop(true);
    child
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .stdout(if discard {
            std::process::Stdio::null()
        } else {
            std::process::Stdio::piped()
        });
    let child = child.spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(45), child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}
pub(crate) async fn audit(m: &terraform_pair::Manifest) -> Vec<Value> {
    audit_namespace(&m.members[0].target.namespace).await
}
pub(crate) async fn audit_namespace(namespace: &str) -> Vec<Value> {
    let node = std::env::var("KF_TERRAFORM_AUDIT_NODE").unwrap();
    assert!(node.starts_with("kf8-tfpa") && node.ends_with("-control-plane"));
    let output = tokio::process::Command::new(std::env::var("KF_TERRAFORM_DOCKER").unwrap())
        .args([
            "exec",
            &node,
            "cat",
            "/var/log/kubernetes/kube-apiserver-audit.log",
        ])
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "audit log unavailable");
    let user = format!("system:serviceaccount:{namespace}:runner");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|v| {
            v["stage"] == "ResponseComplete"
                && v["objectRef"]["namespace"] == *namespace
                && v["user"]["username"] == user
                && ["patch", "update"].contains(&v["verb"].as_str().unwrap_or(""))
        })
        .collect()
}
pub(crate) fn certify_audit(m: &terraform_pair::Manifest, events: &[Value], partial: bool) {
    let rows = |name: &str| {
        events
            .iter()
            .filter(|v| v["objectRef"]["name"] == name)
            .collect::<Vec<_>>()
    };
    let first = rows(&m.members[0].target.name);
    let second = rows(&m.members[1].target.name);
    assert!(
        !first.is_empty() && !second.is_empty(),
        "both physical requests must occur"
    );
    assert_eq!(first.len() + second.len(), events.len());
    assert!(first.iter().all(|v| {
        v["responseStatus"]["code"]
            .as_u64()
            .is_some_and(|c| (200..300).contains(&c))
    }));
    assert!(second.iter().all(|v| if partial {
        v["responseStatus"]["code"] == 403
    } else {
        v["responseStatus"]["code"]
            .as_u64()
            .is_some_and(|c| (200..300).contains(&c))
    }));
    let completed = first
        .iter()
        .map(|v| {
            chrono::DateTime::parse_from_rfc3339(v["stageTimestamp"].as_str().unwrap()).unwrap()
        })
        .max()
        .unwrap();
    let received = second
        .iter()
        .map(|v| {
            chrono::DateTime::parse_from_rfc3339(v["requestReceivedTimestamp"].as_str().unwrap())
                .unwrap()
        })
        .min()
        .unwrap();
    assert!(
        completed <= received,
        "first must finish before the second request starts"
    );
}
pub(crate) async fn restore_second_write(m: &terraform_pair::Manifest) {
    let rules = json!({"rules":[{"apiGroups":[""],"resources":["configmaps"],"resourceNames":[m.members[0].target.name,m.members[1].target.name],"verbs":["get","patch","update"]}]});
    let context = std::env::var("KF_TERRAFORM_CONTEXT").unwrap();
    assert!(context.starts_with("kind-kf8-tfpa"));
    let output = tokio::process::Command::new(std::env::var("KF_TERRAFORM_KUBECTL").unwrap())
        .args([
            "--kubeconfig",
            &std::env::var("KF_TERRAFORM_KUBECONFIG").unwrap(),
            "--context",
            &context,
            "patch",
            "role",
            "runner",
            "-n",
            &m.members[0].target.namespace,
            "--type=merge",
            "-p",
            &rules.to_string(),
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let user = format!(
        "system:serviceaccount:{}:runner",
        m.members[0].target.namespace
    );
    let mut permitted = false;
    for _ in 0..40 {
        let output = tokio::process::Command::new(std::env::var("KF_TERRAFORM_KUBECTL").unwrap())
            .args([
                "--kubeconfig",
                &std::env::var("KF_TERRAFORM_KUBECONFIG").unwrap(),
                "--context",
                &context,
                "--as",
                &user,
                "auth",
                "can-i",
                "patch",
                &format!("configmaps/{}", m.members[1].target.name),
                "-n",
                &m.members[1].target.namespace,
                "--quiet",
            ])
            .output()
            .await
            .unwrap();
        if output.status.success() {
            permitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        permitted,
        "restored writer permission was not independently observed"
    );
}
async fn run(mode: &str) {
    let Ok(capsule) = std::env::var("KF_TERRAFORM_CAPSULE") else {
        assert_ne!(std::env::var("KF_REQUIRE_TERRAFORM").as_deref(), Ok("1"));
        eprintln!("SKIP pair execution: owned fixture absent");
        return;
    };
    let partial = mode != "normal";
    let capsule = PathBuf::from(capsule);
    let manifest_file = capsule.join("manifest.json");
    let m = terraform_pair::Manifest::decode(&std::fs::read(&manifest_file).unwrap()).unwrap();
    let inspection = terraform_pair::inspect(&capsule, &manifest_file)
        .await
        .unwrap();
    let resource = pair::resource(&m, &inspection.manifest_digest).unwrap();
    let now = SystemClock.now_ms();
    let Some(mut h) = Harness::with_native_timing(
        None,
        now,
        |f| {
            configure_binding(
                f,
                json!(resource),
                &inspection.manifest_digest,
                &inspection.effect_digest,
                pair::ACTION,
                pair::adapter_contract(),
                pair::SCOPE,
            )
        },
        None,
        None,
        None,
        None,
        Some(30000),
    )
    .await
    else {
        return;
    };
    h.f.identity.delegation_digest = digest("delegation", &h.f.proposal["delegation"]).unwrap();
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let tool = h.tool();
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let native = Arc::new(Native {
        origin: std::env::var("ETCD_ENDPOINT").unwrap(),
        counts: std::array::from_fn(|_| AtomicUsize::new(0)),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/v3/kv/txn", post(relay))
        .with_state(native.clone());
    let server = tls::server_config_pem(
        h.gateway_pki.server.as_bytes(),
        h.gateway_pki.server_key.as_bytes(),
        h.gateway_pki.ca.as_bytes(),
    )
    .unwrap();
    let _server = live_agent::Running(tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, server, router)
            .await
            .unwrap()
    }));
    let ca = write(&root, "ca.pem", &h.gateway_pki.ca);
    let cert = write(&root, "gateway.pem", &h.gateway_pki.client);
    let key = write(&root, "gateway.key", &h.gateway_pki.client_key);
    let ledger_token = write(&root, "ledger.token", "fixture-terraform-ledger-token");
    let identity = reqwest::Identity::from_pem(
        format!("{}\n{}", h.gateway_pki.client, h.gateway_pki.client_key).as_bytes(),
    )
    .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(h.gateway_pki.ca.as_bytes()).unwrap())
        .identity(identity)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    h.ledger = EtcdLedger::new(client, &endpoint, h.ledger.namespace())
        .unwrap()
        .with_auth_token("fixture-terraform-ledger-token")
        .unwrap()
        .requiring_control(None);
    let secret = PathBuf::from(std::env::var("KF_TERRAFORM_SECRET_ROOT").unwrap());
    let pins = apply::Pins {
        profile: pair::PROFILE.into(),
        material_root: capsule.clone(),
        manifest_file,
        backend_root: PathBuf::from(std::env::var("KF_TERRAFORM_BACKEND_ROOT").unwrap()),
        secret_root: secret.clone(),
        writer_token_file: secret.join("writer.token"),
        observer_token_file: secret.join("observer.token"),
        manifest_digest: inspection.manifest_digest.clone(),
        inspection_sha256: inspection.inspection_sha256.clone(),
        effect_digest: inspection.effect_digest.clone(),
        tool: tool.clone(),
        parameter_schema: h.f.descriptor["parameter_schema"].clone(),
        gateway_workload: "spiffe://test/gateway".into(),
        target_audience: "https://terraform-pair-runner.test/apply".into(),
        target_scope: pair::SCOPE.into(),
    };
    let public = |n: u8| json!({format!("key-{n}"):STANDARD.encode(SigningKey::from_bytes(&[n;32]).verifying_key().as_bytes())});
    let config=write(&root,"config.json",serde_json::to_vec(&json!({"pins":pins,"ledger":{"endpoint":endpoint,"prefix":h.ledger.namespace(),"ca":ca,"certificate":cert,"private_key":key,"token_file":ledger_token,"restore_gate":null},"gateway_audience":h.registration.scope.audience,"grant_keys":public(5),"token_issuer":"https://terraform-pair-broker.test/exchange","target_keys":public(29)})).unwrap());
    let issued = h.issue().await.unwrap();
    h.clock.0.store(0, Ordering::SeqCst);
    let grants = GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    };
    let verified = grants
        .verify(issued.record.signed_grant.as_bytes(), SystemClock.now_ms())
        .unwrap();
    let g = &verified.grant;
    let id = "terraform-pair-original";
    h.ledger
        .claim_recorded(
            g,
            &verified.digest,
            id,
            &ExecutionRecord {
                signed_grant: issued.record.signed_grant.clone(),
                tool: tool.name.clone(),
                parameters: h.f.proposal["parameters"].clone(),
            },
        )
        .await
        .unwrap();
    let broker = BrokerAuthorizer::new(
        BrokerRegistration {
            gateway_workload: pins.gateway_workload.clone(),
            target_audience: pins.target_audience.clone(),
            target_scope: pins.target_scope.clone(),
            max_lifetime_ms: 30000,
            tool: tool.clone(),
        },
        grants.clone(),
        h.ledger.clone(),
        Arc::new(Provider(h.f.identity.clone())),
        Arc::new(SystemClock),
    )
    .unwrap();
    let der = rustls_pemfile::certs(&mut std::io::Cursor::new(h.gateway_pki.client.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    let gateway = WorkloadIdentity::from_verified_cert_der(&der).unwrap();
    let exchange = ExchangeRequest {
        subject_token: h.f.identity.access_token.clone(),
        actor_token: "fixture-actor".into(),
        signed_grant: issued.record.signed_grant.clone(),
        grant_digest: verified.digest.clone(),
        attempt_id: id.into(),
        audience: pins.target_audience.clone(),
        scope: pins.target_scope.clone(),
    };
    let permit = broker.authorize(&exchange, &gateway).await.unwrap();
    let credential = ReferenceTokenMinter::new(
        "https://terraform-pair-broker.test/exchange".into(),
        "key-29".into(),
        SigningKey::from_bytes(&[29; 32]),
    )
    .unwrap()
    .mint(&permit, SystemClock.now_ms())
    .await
    .unwrap();
    h.ledger
        .authorize_dispatch(g, &verified.digest, id)
        .await
        .unwrap();
    let request = apply::Request {
        profile: pair::PROFILE.into(),
        signed_grant: issued.record.signed_grant.clone(),
        attempt_id: id.into(),
        parameters: h.f.proposal["parameters"].clone(),
        target_credential: credential,
    };
    let path = write(&root, "request.json", serde_json::to_vec(&request).unwrap());
    let before = std::fs::read(&m.backend_state_path).unwrap();
    let lost = mode == "partial-lost";
    let legacy = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-terraform-apply"))
        .args([
            "--material-root",
            root.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "query",
            "--attempt-id",
            id,
        ])
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        !legacy.status.success(),
        "single-resource loader accepted a pair profile"
    );
    assert_eq!(counts(&native), vec![1, 1, 1, 0, 0, 0]);
    let first = cli(
        &root,
        &config,
        &["execute", "--request", path.to_str().unwrap()],
        lost,
    )
    .await;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    if lost {
        assert!(first.stdout.is_empty());
    }
    let query = cli(&root, &config, &["query", "--attempt-id", id], false).await;
    assert!(
        query.status.success(),
        "{}",
        String::from_utf8_lossy(&query.stderr)
    );
    let report: Value = serde_json::from_slice(&query.stdout).unwrap();
    assert_eq!(report["profile"], pair::PROFILE);
    assert_eq!(
        report["intent"]["state"],
        if partial {
            "partial_observed"
        } else {
            "applied"
        }
    );
    assert_eq!(
        report["status"],
        if partial { "unknown" } else { "committed" }
    );
    assert_eq!(report["intent"]["pair"]["members"][0]["state"], "desired");
    assert_eq!(
        report["intent"]["pair"]["members"][1]["state"],
        if partial {
            "original_observed"
        } else {
            "desired"
        }
    );
    let status = h
        .ledger
        .execution_status(g, &verified.digest)
        .await
        .unwrap();
    assert_eq!(status.state, report["status"]);
    assert_eq!(report["intent"]["grant_digest"], verified.digest);
    assert_eq!(report["intent"]["attempt_id"], id);
    let stable = std::fs::read(&m.backend_state_path).unwrap();
    assert_ne!(before, stable);
    assert_eq!(counts(&native), vec![1; 6]);
    let events = audit(&m).await;
    certify_audit(&m, &events, partial);
    if partial {
        restore_second_write(&m).await;
    }
    let replay = cli(
        &root,
        &config,
        &["execute", "--request", path.to_str().unwrap()],
        false,
    )
    .await;
    assert!(replay.status.success());
    let replay: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["intent"], report["intent"]);
    assert_eq!(replay["replayed"], true);
    assert!(broker.authorize(&exchange, &gateway).await.is_err());
    assert!(
        h.ledger
            .claim(g, &verified.digest, "replacement")
            .await
            .is_err()
    );
    h.revoke(RevocationTarget::Domain).await;
    std::fs::rename(secret.join("writer.token"), secret.join("writer.saved")).unwrap();
    drop(broker);
    let delay = (g.expires_at - SystemClock.now_ms()).max(0) as u64 + 25;
    assert!(delay < 35000);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    let cold = cli(
        &root,
        &config,
        &["execute", "--request", path.to_str().unwrap()],
        false,
    )
    .await;
    assert!(
        cold.status.success(),
        "{}",
        String::from_utf8_lossy(&cold.stderr)
    );
    let cold: Value = serde_json::from_slice(&cold.stdout).unwrap();
    assert_eq!(cold["intent"], report["intent"]);
    assert_eq!(cold["replayed"], true);
    assert_eq!(cold["status"], report["status"]);
    assert_eq!(std::fs::read(&m.backend_state_path).unwrap(), stable);
    assert_eq!(counts(&native), vec![1; 6]);
    assert_eq!(audit(&m).await, events);
    let mut changed = request;
    changed.parameters["effect_digest"] = json!("a".repeat(64));
    let changed_path = write(&root, "changed.json", serde_json::to_vec(&changed).unwrap());
    assert!(
        !cli(
            &root,
            &config,
            &["execute", "--request", changed_path.to_str().unwrap()],
            false
        )
        .await
        .status
        .success()
    );
    let out = PathBuf::from(std::env::var("KF_TERRAFORM_TEST_PUBLIC_OUTPUT").unwrap());
    std::fs::write(out.join("pair-native-report.json"),serde_json::to_vec_pretty(&json!({"mode":mode,"report":report,"cold":cold,"native_state":status.state,"counts":counts(&native),"lost_reply":lost,"first_reply_bytes":first.stdout.len(),"grant_expired_at_query":SystemClock.now_ms()>=g.expires_at,"domain_revoked_at_query":true,"writer_absent_at_query":true,"broker_unavailable_at_query":true,"second_permission_restored":partial,"legacy_loader_refused":true,"backend_before_sha256":hex::encode(Sha256::digest(before)),"backend_after_sha256":hex::encode(Sha256::digest(stable))})).unwrap()).unwrap();
    std::fs::write(
        out.join("audit-events.json"),
        serde_json::to_vec_pretty(&events).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("audit-events-after-query.json"),
        serde_json::to_vec_pretty(&audit(&m).await).unwrap(),
    )
    .unwrap();
    println!(
        "TERRAFORM PAIR PASS: {mode}; actual ordered writes; original compound authority; cold query-only; {}",
        status.state
    );
}
#[tokio::test]
async fn normal_pair_apply_and_original_cold_query() {
    run("normal").await;
}
#[tokio::test]
async fn partial_pair_keeps_unknown_after_permission_restored() {
    run("partial").await;
}
#[tokio::test]
async fn partial_pair_lost_reply_recovers_without_reapply() {
    run("partial-lost").await;
}
