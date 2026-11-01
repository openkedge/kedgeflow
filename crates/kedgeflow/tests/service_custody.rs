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
    tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
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
