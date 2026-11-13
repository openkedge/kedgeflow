//! Descriptor policy through service entry points; no separate-UID claim.
#![cfg(unix)]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use kedgeflow::{
    broker::{ServiceFileAssertion, WorkloadAssertion},
    service_files::ServiceFiles,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap())
        .unwrap()
}

#[tokio::test]
async fn live_assertion_keeps_workload_scope_and_rechecks_atomic_replacement_custody() {
    let temp = directory();
    let path = temp.path().join("actor.jwt");
    fs::write(&path, "old-assertion\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let assertion = ServiceFileAssertion {
        workload_id: "spiffe://test/agent".into(),
        path: path.clone(),
        files: ServiceFiles::protected(temp.path()).unwrap(),
    };
    assert!(assertion.assertion("spiffe://test/other").await.is_err());
    assert_eq!(
        assertion.assertion("spiffe://test/agent").await.unwrap(),
        "old-assertion"
    );
    let next = temp.path().join("next");
    fs::write(&next, "new-assertion").unwrap();
    fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&next, &path).unwrap();
    assert_eq!(
        assertion.assertion("spiffe://test/agent").await.unwrap(),
        "new-assertion"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(assertion.assertion("spiffe://test/agent").await.is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&path, &next).unwrap();
    symlink(&next, &path).unwrap();
    assert!(assertion.assertion("spiffe://test/agent").await.is_err());
    fs::remove_file(&path).unwrap();
    assert!(assertion.assertion("spiffe://test/agent").await.is_err());
}

#[test]
fn protected_control_preflight_covers_signers_tls_witness_and_config_without_network() {
    let temp = directory();
    let pki = support::pki();
    let mut config: Value =
        serde_json::from_str(include_str!("../../../config/control.example.json")).unwrap();
    for (field, bytes) in [
        ("certificate", pki.server),
        ("private_key", pki.server_key),
        ("workload_ca", pki.ca.clone()),
        ("etcd_ca", pki.ca),
        ("etcd_certificate", pki.client),
        ("etcd_private_key", pki.client_key),
        ("etcd_token_file", "namespace-token".into()),
        ("admission_signing_key_file", STANDARD.encode([6; 32])),
        ("issuer_signing_key_file", STANDARD.encode([5; 32])),
    ] {
        let path = temp.path().join(field);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        config[field] = json!(path);
    }
    config["restore_gate"] = json!({"endpoint":"https://localhost:9001","prefix":"/witness",
        "ca":config["etcd_ca"],"certificate":config["etcd_certificate"],
        "private_key":config["etcd_private_key"],"token_file":config["etcd_token_file"]});
    let path = temp.path().join("control.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let run = |mode| {
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-control"))
            .arg("--config")
            .arg(&path)
            .arg("--custody-root")
            .arg(temp.path())
            .arg(mode)
            .args([
                "--operations-url",
                "https://localhost:9443/ops/ready",
                "--operations-workload",
                "spiffe://test/monitor",
            ])
            .output()
            .unwrap()
    };
    let out = run("--check");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("no remote installation"));
    for (url, workload) in [
        ("https://localhost:9443/ops/ready", "spiffe://test/agent"),
        ("https://localhost:9443/admission", "spiffe://test/monitor"),
        ("https://alias.test/ops/ready", "spiffe://test/monitor"),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_kf-control"))
            .arg("--config")
            .arg(&path)
            .arg("--custody-root")
            .arg(temp.path())
            .args([
                "--check",
                "--operations-url",
                url,
                "--operations-workload",
                workload,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "unsafe monitor endpoint accepted");
    }
    for field in [
        "certificate",
        "private_key",
        "workload_ca",
        "etcd_ca",
        "etcd_certificate",
        "etcd_private_key",
        "etcd_token_file",
        "admission_signing_key_file",
        "issuer_signing_key_file",
    ] {
        let material = temp.path().join(field);
        fs::set_permissions(&material, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            !run("--check").status.success(),
            "unsafe control role {field}"
        );
        fs::set_permissions(&material, fs::Permissions::from_mode(0o600)).unwrap();
    }
    config["shared_auth"] = json!({"capacity":16,"registrations":[{
        "subject":config["subjects"][0],"workload_id":config["workload_id"],
        "allowed_scopes":[config["action_scope"]]}]});
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let managed = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-control"))
            .arg("--config")
            .arg(&path)
            .arg("--custody-root")
            .arg(temp.path())
            .arg("--require-managed")
            .arg("--check")
            .output()
            .unwrap()
    };
    let out = managed();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    config["require_control"] = json!(false);
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!managed().status.success());
    config["require_control"] = json!(true);
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(!run("--check").status.success());
    // Registration-only modes also use protected configuration reads.
    assert!(!run("--print-pins").status.success());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(run("--print-pins").status.success());
    config["restore_gate"]["token_file"] = json!(temp.path().join("../outside"));
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run("--check").status.success());
}

#[test]
fn managed_launch_mode_requires_protected_roots_and_database_peer_pin() {
    for binary in [
        env!("CARGO_BIN_EXE_kf-proxy"),
        env!("CARGO_BIN_EXE_kf-control"),
        env!("CARGO_BIN_EXE_kf-broker"),
        env!("CARGO_BIN_EXE_kf-postgres-target"),
        env!("CARGO_BIN_EXE_kf-recover"),
        env!("CARGO_BIN_EXE_kf-supervise"),
        env!("CARGO_BIN_EXE_kf-outcomes"),
        env!("CARGO_BIN_EXE_kf-governance"),
        env!("CARGO_BIN_EXE_kf-restore"),
    ] {
        let out = std::process::Command::new(binary)
            .args(["--config", "/not-opened", "--require-managed", "--check"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("--custody-root"));
    }
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
        .args([
            "--config",
            "/not-opened",
            "--custody-root",
            "/not-opened",
            "--require-managed",
            "--check",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--postgres-peer-uid"));
}

#[test]
fn managed_launch_controls_cannot_be_omitted_from_library_configurations() {
    use kedgeflow::{
        broker_config::BrokerConfig, config::Config, control_config::ControlConfig, deployment,
    };
    let witness = json!({"endpoint":"https://witness.test","prefix":"/witness","ca":"/ca",
        "certificate":"/cert","private_key":"/key","token_file":"/token"});
    let shared = json!({"capacity":16,"registrations":[]});
    let mut gateway: Value =
        serde_json::from_str(include_str!("../../../config/gateway.example.json")).unwrap();
    gateway["restore_gate"] = witness.clone();
    gateway["shared_auth"] = shared.clone();
    assert!(
        deployment::gateway(&Config::decode(&serde_json::to_vec(&gateway).unwrap()).unwrap())
            .is_ok()
    );
    for (field, value) in [
        ("require_control", json!(false)),
        ("restore_gate", json!(null)),
        ("shared_auth", json!(null)),
        ("enforcement", json!(null)),
        ("etcd_token_file", json!("")),
    ] {
        let mut bad = gateway.clone();
        bad[field] = value;
        assert!(
            deployment::gateway(&Config::decode(&serde_json::to_vec(&bad).unwrap()).unwrap())
                .is_err(),
            "{field}"
        );
    }
    let mut control: Value =
        serde_json::from_str(include_str!("../../../config/control.example.json")).unwrap();
    control["restore_gate"] = witness.clone();
    control["shared_auth"] = shared;
    assert!(
        deployment::control(
            &ControlConfig::decode(&serde_json::to_vec(&control).unwrap()).unwrap()
        )
        .is_ok()
    );
    for (field, value) in [
        ("require_control", json!(false)),
        ("restore_gate", json!(null)),
        ("shared_auth", json!(null)),
    ] {
        let mut bad = control.clone();
        bad[field] = value;
        assert!(
            deployment::control(
                &ControlConfig::decode(&serde_json::to_vec(&bad).unwrap()).unwrap()
            )
            .is_err(),
            "{field}"
        );
    }
    let mut broker: Value =
        serde_json::from_str(include_str!("../../../config/broker-refresh.example.json")).unwrap();
    broker["restore_gate"] = witness;
    assert!(
        deployment::broker(&BrokerConfig::decode(&serde_json::to_vec(&broker).unwrap()).unwrap())
            .is_ok()
    );
    for (field, value) in [
        ("allow_unmanaged_fixture", json!(true)),
        ("restore_gate", json!(null)),
        ("identity_refresh", json!(null)),
    ] {
        let mut bad = broker.clone();
        bad[field] = value;
        assert!(
            deployment::broker(&BrokerConfig::decode(&serde_json::to_vec(&bad).unwrap()).unwrap())
                .is_err(),
            "{field}"
        );
    }
}
