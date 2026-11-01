//! Isolated real-etcd RBAC and token expiry; never enable auth on a shared fixture.
use super::*;
use crate::{restore::RestoreGate, service_files::ServiceFiles};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Child, Command, Stdio},
};

struct Node {
    child: Child,
    endpoint: String,
    client: Client,
    _directory: tempfile::TempDir,
}
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Node {
    async fn start(binary: &std::ffi::OsStr) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let client_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", client_port.local_addr().unwrap());
        let peer = format!("http://{}", peer_port.local_addr().unwrap());
        drop((client_port, peer_port));
        let child = Command::new(binary)
            .arg("--name=auth-test")
            .arg(format!("--data-dir={}", directory.path().display()))
            .arg(format!("--listen-client-urls={endpoint}"))
            .arg(format!("--advertise-client-urls={endpoint}"))
            .arg(format!("--listen-peer-urls={peer}"))
            .arg(format!("--initial-advertise-peer-urls={peer}"))
            .arg(format!("--initial-cluster=auth-test={peer}"))
            .arg(format!("--initial-cluster-token={}", rand::random::<u64>()))
            .args(["--auth-token-ttl=5", "--bcrypt-cost=4", "--log-level=error"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut node = Self {
            child,
            endpoint,
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            _directory: directory,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            assert!(node.child.try_wait().unwrap().is_none(), "etcd exited");
            if node
                .client
                .get(format!("{}/health", node.endpoint))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "etcd startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        node
    }
    async fn api(&self, route: &str, body: Value, token: Option<&str>) -> Value {
        let mut request = self
            .client
            .post(format!("{}{route}", self.endpoint))
            .json(&body);
        if let Some(token) = token {
            request = request.header(reqwest::header::AUTHORIZATION, token);
        }
        let response = request.send().await.unwrap();
        assert!(
            response.status().is_success(),
            "fixture API refused {route}"
        );
        response.json().await.unwrap()
    }
    async fn token(&self, name: &str) -> String {
        self.api(
            "/v3/auth/authenticate",
            json!({"name":name,"password":"fixture-only-password"}),
            None,
        )
        .await["token"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    async fn secure(&self, prefix: &str) {
        for name in ["root", "service"] {
            self.api(
                "/v3/auth/user/add",
                json!({"name":name,"password":"fixture-only-password"}),
                None,
            )
            .await;
            self.api("/v3/auth/role/add", json!({"name":name}), None)
                .await;
            self.api(
                "/v3/auth/user/grant",
                json!({"user":name,"role":name}),
                None,
            )
            .await;
        }
        // Only this namespace, including the restore/family absence markers.
        self.api("/v3/auth/role/grant", json!({"name":"service","perm":{"permType":"READWRITE","key":STANDARD.encode(format!("{prefix}/")),"range_end":STANDARD.encode(format!("{prefix}0"))}}), None).await;
        self.api("/v3/auth/enable", json!({}), None).await;
    }
    fn ledger(&self, prefix: &str) -> EtcdLedger {
        EtcdLedger::new(self.client.clone(), &self.endpoint, prefix).unwrap()
    }
}
fn publish(path: &Path, token: &[u8]) {
    let next = path.with_extension("next");
    fs::write(&next, token).unwrap();
    fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(next, path).unwrap();
}

#[tokio::test]
async fn protected_primary_and_witness_credentials_renew_without_restarting() {
    let Some(binary) = std::env::var_os("ETCD_BINARY") else {
        assert_ne!(
            std::env::var("KF_REQUIRE_ETCD").as_deref(),
            Ok("1"),
            "ETCD_BINARY required"
        );
        eprintln!("SKIP isolated real-etcd auth test: ETCD_BINARY absent");
        return;
    };
    let version = Command::new(&binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("etcd Version: 3.6.5\n"));
    let (primary, witness) = tokio::join!(Node::start(&binary), Node::start(&binary));
    primary.secure("/authority").await;
    witness.secure("/witness").await;
    let directory = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let files = ServiceFiles::protected(directory.path()).unwrap();
    let primary_path = directory.path().join("primary.token");
    let witness_path = directory.path().join("witness.token");
    let first = primary.token("service").await;
    let first_witness = witness.token("service").await;
    publish(&primary_path, first.as_bytes());
    publish(&witness_path, first_witness.as_bytes());
    let base = primary
        .ledger("/authority")
        .with_auth_token_file(&files, &primary_path)
        .await
        .unwrap();
    let gate = RestoreGate::new(
        witness
            .ledger("/witness")
            .with_auth_token_file(&files, &witness_path)
            .await
            .unwrap(),
    )
    .unwrap();
    gate.enroll_empty(&base).await.unwrap();
    let ledger = base.clone().with_restore_gate(gate.clone()).unwrap();
    let key = "/authority/original-attempt";
    let original = "consumed-original-never-reissued";
    assert!(
        ledger
            .txn(vec![], vec![put(key, original)], vec![])
            .await
            .unwrap()
            .succeeded
    );
    let head = gate.check(&base).await.unwrap();
    let fixed = primary
        .ledger("/authority")
        .with_auth_token(&first)
        .unwrap()
        .with_restore_gate(
            RestoreGate::new(
                witness
                    .ledger("/witness")
                    .with_auth_token(&first_witness)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let legacy = primary
        .ledger("/authority")
        .with_auth_token_file(&ServiceFiles::default(), &primary_path)
        .await
        .unwrap();
    assert_eq!(
        ledger.read_key(key).await.unwrap().unwrap(),
        original.as_bytes()
    );

    // No calls refresh simple-token lifetime during this wait. The static
    // negative control must fail against the real authenticated gateway.
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(
        fixed.read_key(key).await.is_err(),
        "real token did not expire"
    );
    assert!(ledger.read_key(key).await.is_err());
    assert!(legacy.read_key(key).await.is_err());
    let next = primary.token("service").await;
    publish(&primary_path, next.as_bytes());
    assert!(
        ledger.read_key(key).await.is_err(),
        "expired witness must refuse"
    );
    let next_witness = witness.token("service").await;
    publish(&witness_path, next_witness.as_bytes());
    let replica = ledger.clone();
    assert_eq!(
        replica.read_key(key).await.unwrap().unwrap(),
        original.as_bytes()
    );
    assert_eq!(
        gate.check(&base).await.unwrap(),
        head,
        "renewal/read advanced authority"
    );
    assert!(fixed.read_key(key).await.is_err());
    assert!(
        legacy.read_key(key).await.is_err(),
        "unprotected source became live"
    );
    assert!(base.read_key("/outside/no-access").await.is_err());
    // RBAC is exercised directly too; a namespace-scoped source is not root.
    let unauthorized = primary.ledger("/outside").with_auth_token(&next).unwrap();
    assert!(unauthorized.read_key("/outside/no-access").await.is_err());

    // A missing, unsafe, malformed or symlinked current source never falls
    // back to the token that worked earlier. Each source is independent.
    for path in [&primary_path, &witness_path] {
        let valid = fs::read(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(replica.read_key(key).await.is_err());
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(path).unwrap();
        assert!(replica.read_key(key).await.is_err());
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), &valid).unwrap();
        symlink(outside.path(), path).unwrap();
        assert!(replica.read_key(key).await.is_err());
        fs::remove_file(path).unwrap();
        for bad in [b"".as_slice(), b"bad\nheader", &[0xff], &vec![b'a'; 16385]] {
            publish(path, bad);
            assert!(replica.read_key(key).await.is_err());
        }
        publish(path, &valid);
    }
    assert_eq!(
        ledger.read_key(key).await.unwrap().unwrap(),
        original.as_bytes()
    );
    assert_eq!(gate.check(&base).await.unwrap(), head);

    // Role withdrawal is enforced by etcd; a fresh replacement token does
    // not manufacture permission. Regrant permits the same original lookup.
    let root = primary.token("root").await;
    primary
        .api(
            "/v3/auth/user/revoke",
            json!({"name":"service","role":"service"}),
            Some(&root),
        )
        .await;
    publish(&primary_path, primary.token("service").await.as_bytes());
    assert!(ledger.read_key(key).await.is_err());
    let root = primary.token("root").await;
    primary
        .api(
            "/v3/auth/user/grant",
            json!({"user":"service","role":"service"}),
            Some(&root),
        )
        .await;
    publish(&primary_path, primary.token("service").await.as_bytes());
    publish(&witness_path, witness.token("service").await.as_bytes());
    assert_eq!(
        ledger.read_key(key).await.unwrap().unwrap(),
        original.as_bytes()
    );
    assert_eq!(gate.check(&base).await.unwrap(), head);
    eprintln!(
        "real etcd 3.6.5 RBAC: primary/witness expiry, independent protected renewal, unsafe-source refusal, role withdrawal/regrant; original attempt and restore head unchanged"
    );
}

#[tokio::test]
async fn lost_authenticated_mutation_reply_never_refreshes_or_retries() {
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let Some(binary) = std::env::var_os("ETCD_BINARY") else {
        assert_ne!(
            std::env::var("KF_REQUIRE_ETCD").as_deref(),
            Ok("1"),
            "ETCD_BINARY required"
        );
        eprintln!("SKIP isolated real-etcd auth test: ETCD_BINARY absent");
        return;
    };
    let node = Node::start(&binary).await;
    node.secure("/authority").await;
    let directory = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let path = directory.path().join("ledger.token");
    publish(&path, node.token("service").await.as_bytes());
    struct Relay {
        client: Client,
        backend: String,
        path: std::path::PathBuf,
        replacement: String,
        writes: AtomicUsize,
    }
    async fn forward(
        State(s): State<Arc<Relay>>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> (axum::http::StatusCode, Json<Value>) {
        let mut builder = s
            .client
            .post(format!("{}/v3/kv/txn", s.backend))
            .json(&request);
        if let Some(header) = headers.get(reqwest::header::AUTHORIZATION) {
            builder = builder.header(reqwest::header::AUTHORIZATION, header.clone());
        }
        let response = builder.send().await.unwrap();
        let status = response.status();
        let reply: Value = response.json().await.unwrap();
        if request["success"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.get("request_put").is_some())
        {
            assert!(status.is_success());
            if s.writes.fetch_add(1, Ordering::SeqCst) == 0 {
                assert_eq!(
                    reply["succeeded"], true,
                    "real etcd accepted the original write"
                );
                publish(&s.path, s.replacement.as_bytes());
                // The accepted write's reply is lost, then the relay reports an
                // auth failure. Publishing a valid replacement permits no retry.
                return (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(json!({"message":"reply unavailable"})),
                );
            }
        }
        (status, Json(reply))
    }
    struct Task(tokio::task::JoinHandle<()>);
    impl Drop for Task {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let state = Arc::new(Relay {
        client: node.client.clone(),
        backend: node.endpoint.clone(),
        path: path.clone(),
        replacement: node.token("service").await,
        writes: AtomicUsize::new(0),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/v3/kv/txn", post(forward))
        .with_state(state.clone());
    let _task = Task(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap()
    }));
    let ledger = EtcdLedger::new(node.client.clone(), endpoint, "/authority")
        .unwrap()
        .with_auth_token_file(&ServiceFiles::protected(directory.path()).unwrap(), &path)
        .await
        .unwrap();
    let key = "/authority/consumed-attempt";
    let error = ledger
        .raw_txn(vec![version_zero(key)], vec![put(key, "original")], vec![])
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unavailable(_)));
    assert_eq!(
        state.writes.load(Ordering::SeqCst),
        1,
        "ambiguous mutation retried"
    );
    assert_eq!(ledger.read_key(key).await.unwrap().unwrap(), b"original");
    // An explicit new operation still cannot replace the consumed original.
    let next = ledger
        .raw_txn(
            vec![version_zero(key)],
            vec![put(key, "replacement")],
            vec![],
        )
        .await
        .unwrap();
    assert!(!next.succeeded);
    assert_eq!(ledger.read_key(key).await.unwrap().unwrap(), b"original");
    assert_eq!(state.writes.load(Ordering::SeqCst), 2);
    eprintln!(
        "real etcd accepted original CAS; lost reply plus credential renewal caused one request and no retry; original consumption preserved"
    );
}
