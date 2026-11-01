//! Shipping collector: listener activity must not imply authority readiness.
#![cfg(unix)]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, process::Stdio, time::Duration};
#[tokio::test]
async fn shipping_protected_listener_reports_unavailable_authority_only_to_monitor() {
    let temp = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let pkis = support::pki_for_workloads(&["spiffe://test/monitor", "spiffe://test/agent"]);
    let pki = &pkis[0];
    let mut config: Value =
        serde_json::from_str(include_str!("../../../config/outcomes.example.json")).unwrap();
    for (field, bytes) in [
        ("certificate", pki.server.clone()),
        ("private_key", pki.server_key.clone()),
        ("workload_ca", pki.ca.clone()),
        ("etcd_ca", pki.ca.clone()),
        ("etcd_certificate", pki.client.clone()),
        ("etcd_private_key", pki.client_key.clone()),
        ("etcd_token_file", "fixture-namespace-token".into()),
        (
            "acknowledgement_signing_key_file",
            STANDARD.encode([15; 32]),
        ),
    ] {
        let path = temp.path().join(field);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        config[field] = json!(path);
    }
    let public = |seed| {
        STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
    };
    config["oidc_public_key_base64"] = json!(public(7));
    config["grant_keys"] = json!({"grant":public(5)});
    config["outcome_keys"] = json!({"outcome":public(14)});
    config["shared_auth"] = json!({"capacity":16,"registrations":[{"subject":config["reporter_subject"],"workload_id":config["source_id"],"allowed_scopes":[config["report_scope"]]}]});
    // Bound but deliberately unaccepted sockets reserve both fixture origins.
    // No real authority receives a transaction or credential.
    let primary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let witness = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config["etcd_endpoint"] = json!(format!("https://{}", primary.local_addr().unwrap()));
    config["restore_gate"] = json!({"endpoint":format!("https://{}",witness.local_addr().unwrap()),"prefix":"/independent-witness","ca":config["etcd_ca"],"certificate":config["etcd_certificate"],"private_key":config["etcd_private_key"],"token_file":config["etcd_token_file"]});
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    config["listen"] = json!(address.to_string());
    config["external_url"] = json!(format!("https://{address}/outcomes"));
    let monitor_url = format!("https://{address}/ops/ready");
    let path = temp.path().join("config.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log = temp.path().join("stderr");
    let log_file = fs::File::create(&log).unwrap();
    drop(reservation);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-outcomes"))
        .kill_on_drop(true)
        .arg("--config")
        .arg(&path)
        .arg("--custody-root")
        .arg(temp.path())
        .args([
            "--require-managed",
            "--operations-url",
            &monitor_url,
            "--operations-workload",
            "spiffe://test/monitor",
        ])
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
        .unwrap();
    let client = |p: &support::Pki| {
        kedgeflow::tls::pinned_http_client_pem(
            p.ca.as_bytes(),
            p.client.as_bytes(),
            p.client_key.as_bytes(),
            Duration::from_secs(8),
        )
        .unwrap()
    };
    let monitor = client(pki);
    let agent = client(&pkis[1]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let response = loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(&log).unwrap()
        );
        match monitor.get(&monitor_url).send().await {
            Ok(response) => break response,
            Err(_) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "collector failed to listen"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let report: kedgeflow::operations::Report = response.json().await.unwrap();
    assert!(!report.ready);
    assert!(!report.execution_authority);
    assert_eq!(report.role, kedgeflow::operations::Role::Collector);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.condition == kedgeflow::operations::Condition::Unavailable)
    );
    assert_eq!(agent.get(&monitor_url).send().await.unwrap().status(), 403);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    assert!(
        monitor.get(&monitor_url).send().await.is_err(),
        "stopped process retained a readiness reply"
    );
}

#[tokio::test]
async fn shipping_recovery_monitor_is_scoped_and_stops_with_bounded_query_worker() {
    let temp = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let mut config: Value =
        serde_json::from_str(include_str!("../../../config/recovery.example.json")).unwrap();
    let source = config["source_id"].as_str().unwrap().to_owned();
    let pkis =
        support::pki_for_workloads(&[&source, "spiffe://test/monitor", "spiffe://test/agent"]);
    let pki = &pkis[0];
    for (field, bytes) in [
        ("etcd_ca", pki.ca.clone()),
        ("etcd_certificate", pki.client.clone()),
        ("etcd_private_key", pki.client_key.clone()),
        ("etcd_token_file", "fixture-token".into()),
        ("query_ca", pki.ca.clone()),
        ("query_certificate", pki.client.clone()),
        ("query_private_key", pki.client_key.clone()),
        ("query_token_file", "fixture-query-token".into()),
        ("receipt_signing_key_file", STANDARD.encode([14; 32])),
    ] {
        let path = temp.path().join(field);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        config[field] = json!(path);
    }
    config["grant_keys"] = json!({"grant":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[5;32]).verifying_key().as_bytes())});
    let primary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let witness = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let query = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config["etcd_endpoint"] = json!(format!("https://{}", primary.local_addr().unwrap()));
    config["query_url"] = json!(format!("https://{}/query", query.local_addr().unwrap()));
    config["restore_gate"] = json!({"endpoint":format!("https://{}",witness.local_addr().unwrap()),"prefix":"/witness","ca":config["etcd_ca"],"certificate":config["etcd_certificate"],"private_key":config["etcd_private_key"],"token_file":config["etcd_token_file"]});
    for (name, bytes) in [
        ("server-cert", &pki.server),
        ("server-key", &pki.server_key),
    ] {
        let path = temp.path().join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let url = format!("https://{address}/ops");
    config["operations"] = json!({"listen":address.to_string(),"external_url":url,"monitor_workload":"spiffe://test/monitor","certificate":temp.path().join("server-cert"),"private_key":temp.path().join("server-key"),"workload_ca":config["etcd_ca"]});
    let path = temp.path().join("recovery.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log = temp.path().join("worker.log");
    drop(reserved);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-recover"))
        .kill_on_drop(true)
        .arg("--config")
        .arg(&path)
        .arg("--custody-root")
        .arg(temp.path())
        .arg("--require-managed")
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let client = |p: &support::Pki| {
        kedgeflow::tls::pinned_http_client_pem(
            p.ca.as_bytes(),
            p.client.as_bytes(),
            p.client_key.as_bytes(),
            Duration::from_secs(8),
        )
        .unwrap()
    };
    let monitor = client(&pkis[1]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let response = loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(&log).unwrap()
        );
        match monitor.get(&url).send().await {
            Ok(response) => break response,
            Err(_) => {
                assert!(tokio::time::Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    assert_eq!(response.status(), 503);
    let report: kedgeflow::operations::Report = response.json().await.unwrap();
    assert_eq!(report.role, kedgeflow::operations::Role::Recovery);
    assert!(!report.ready && !report.execution_authority);
    assert_eq!(
        client(&pkis[2]).get(&url).send().await.unwrap().status(),
        403
    );
    assert!(
        tokio::process::Command::new("/bin/kill")
            .args(["-TERM", &child.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(12), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(monitor.get(&url).send().await.is_err());
}
