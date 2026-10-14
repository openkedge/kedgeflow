//! Shipping opt-in consumes protected file bytes, not checked paths reopened later.
use super::*;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};
fn save(root: &Path, name: &str, bytes: impl AsRef<[u8]>, mode: u32) -> std::path::PathBuf {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}
#[tokio::test]
async fn shipping_sql_custody_checks_and_retained_startup_snapshot() {
    let Some(mut h) = Harness::new("sql-custody", false).await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let mut config = PostgresTargetConfig {
        listen: format!(
            "127.0.0.1:{}",
            reqwest::Url::parse(&h.url).unwrap().port().unwrap()
        )
        .parse()
        .unwrap(),
        dispatch_url: h.url.clone(),
        query_url: h.query_url.clone(),
        certificate: save(&root, "server.pem", &h.pki[0].server, 0o644),
        private_key: save(&root, "server.key", &h.pki[0].server_key, 0o600),
        workload_ca: save(&root, "ca.pem", &h.pki[0].ca, 0o644),
        database: h.database.clone(),
        gateway_audience: h.grants.audience.clone(),
        grant_keys: BTreeMap::from([(
            "test-key".into(),
            STANDARD.encode(SigningKey::from_bytes(&[6; 32]).verifying_key().as_bytes()),
        )]),
        token_issuer: ISSUER.into(),
        target_keys: BTreeMap::from([(
            "target".into(),
            STANDARD.encode(SigningKey::from_bytes(&[29; 32]).verifying_key().as_bytes()),
        )]),
        query_token_file: save(&root, "query.token", QUERY_TOKEN, 0o600),
        registration: h.registration.clone(),
    };
    let path = save(
        &root,
        "target.json",
        serde_json::to_vec(&config).unwrap(),
        0o644,
    );
    config.database.socket_directory =
        std::fs::canonicalize(&config.database.socket_directory).unwrap();
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let peer_uid = rustix::process::geteuid().as_raw().to_string();
    let run = |flags: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
            .arg("--config")
            .arg(&path)
            .arg("--custody-root")
            .arg(&root)
            .args(flags)
            .output()
            .unwrap()
    };
    let first = run(&["--check-custody"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(
        report,
        json!({"profile":kedgeflow::postgres_custody::PROFILE,"operation":"check_custody","effective_uid":rustix::process::geteuid().as_raw(),"files_checked":5,"status":"passed","scope":"uid_mode_descriptor_snapshot"})
    );
    assert!(run(&["--check-database"]).status.success());
    assert!(
        run(&["--check-database", "--postgres-peer-uid", &peer_uid])
            .status
            .success()
    );
    assert!(
        !run(&[
            "--check-database",
            "--postgres-peer-uid",
            &(rustix::process::geteuid().as_raw() + 1).to_string()
        ])
        .status
        .success()
    );
    assert_eq!(h.state().await, (1, "free".into()));
    assert!(
        !run(&["--check-custody", "--check-database"])
            .status
            .success()
    );
    let missing_root = std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
        .arg("--config")
        .arg(&path)
        .arg("--check-custody")
        .output()
        .unwrap();
    assert!(!missing_root.status.success());
    let database = config.database.clone();
    config.database.socket_directory = root.join("absent-socket");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(run(&["--check-custody"]).status.success());
    assert!(run(&["--check"]).status.success());
    assert!(!run(&["--check-database"]).status.success());
    config.database = database;
    for (file, mode) in [
        (&config.private_key, 0o644),
        (&config.query_token_file, 0o640),
        (&path, 0o666),
    ] {
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(!run(&["--check-custody"]).status.success());
        std::fs::set_permissions(
            file,
            std::fs::Permissions::from_mode(if file == &path { 0o644 } else { 0o600 }),
        )
        .unwrap();
    }
    let certificate = config.certificate.clone();
    symlink(&certificate, root.join("linked.pem")).unwrap();
    config.certificate = root.join("linked.pem");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run(&["--check-custody"]).status.success());
    config.certificate = certificate;
    let outside = dir.path().with_extension("outside.pem");
    config.workload_ca = outside;
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(!run(&["--check-custody"]).status.success());
    config.workload_ca = root.join("ca.pem");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert_eq!(h.state().await, (1, "free".into()));
    h.task.abort();
    let _ = (&mut h.task).await;
    struct Shipping(std::process::Child);
    impl Drop for Shipping {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Shipping(
        std::process::Command::new(env!("CARGO_BIN_EXE_kf-postgres-target"))
            .arg("--config")
            .arg(&path)
            .arg("--custody-root")
            .arg(&root)
            .arg("--postgres-peer-uid")
            .arg(&peer_uid)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    async fn query_missing(h: &Harness) -> bool {
        h.client(1).client().post(&h.query_url).bearer_auth(QUERY_TOKEN)
            .json(&json!({"profile":kedgeflow::recovery::PROFILE,"operation":"query","attempt_id":"custody-missing"}))
            .send().await.is_ok_and(|response|response.status()==404)
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(child.0.try_wait().unwrap().is_none());
        if query_missing(&h).await {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let replacement = root.join("replacement.token");
    save(
        &root,
        "replacement.token",
        "unsafe-replacement-00000000000000000000000000",
        0o644,
    );
    std::fs::rename(replacement, &config.query_token_file).unwrap();
    assert!(query_missing(&h).await);
    assert!(!run(&["--check-custody"]).status.success());
    assert_eq!(
        h.adapter()
            .dispatch(&h.call, &h.credential)
            .await
            .unwrap()
            .status,
        "committed"
    );
    assert_eq!(
        h.query().query(&h.call.attempt_id).await.unwrap().status,
        "committed"
    );
    assert_eq!(h.state().await, (2, "booking-native".into()));
    println!(
        "SQL custody PASS: five verified files; offline/active modes separated, unsafe modes/symlink/root escape refused before effect; shipping protected startup retains original token snapshot under path replacement and commits/queries once"
    );
}
