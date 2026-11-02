//! Real etcd authentication over verified mTLS; generated PKI is a software fixture.
#![cfg(unix)]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use kedgeflow::{ledger_credentials::Config, service_files::ServiceFiles};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Etcd(Child);
impl Drop for Etcd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn write(root: &Path, name: &str, raw: &[u8]) {
    fs::write(root.join(name), raw).unwrap();
    fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
}
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap().join("protected");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(root.join("stage")).unwrap();
    fs::set_permissions(root.join("stage"), fs::Permissions::from_mode(0o750)).unwrap();
    (temp, root)
}
fn configuration(root: &Path, endpoint: &str) -> Value {
    json!({"profile":"KF-LEDGER-CREDENTIALS-0.1", "staging_root":root.join("stage"),
        "issuers":[{"name":"primary-control", "endpoint":endpoint,
            "ca":root.join("ca.pem"), "certificate":root.join("client.pem"),
            "private_key":root.join("client.key"), "username":"ordinary",
            "password_file":root.join("password"), "scope_prefix":"/authority",
            "permissions":[{"permission":"READWRITE","key":"/authority/","range_end":"/authority0"}]}]})
}
fn config(value: &Value) -> Config {
    Config::decode(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn configuration_refuses_ambiguous_endpoints_admins_and_escaping_permissions() {
    let (_temp, root) = fixture();
    let valid = configuration(&root, "https://127.0.0.1:2379");
    config(&valid);
    for (field, bad) in [
        ("endpoint", json!("http://127.0.0.1:2379")),
        ("endpoint", json!("https://user:pass@127.0.0.1:2379")),
        ("endpoint", json!("https://127.0.0.1:2379/path")),
        ("endpoint", json!("https://127.0.0.1:2379?query")),
        ("endpoint", json!("https://127.0.0.1:2379/")),
        ("username", json!("root")),
        ("scope_prefix", json!("/authority/../other")),
        (
            "permissions",
            json!([{"permission":"READWRITE","key":"/other/","range_end":"/other0"}]),
        ),
        (
            "permissions",
            json!([{"permission":"READWRITE","key":"/authority/","range_end":"\0"}]),
        ),
        (
            "permissions",
            json!([{"permission":"READWRITE","key":"/authority/","range_end":"/authority1"}]),
        ),
    ] {
        let mut value = valid.clone();
        value["issuers"][0][field] = bad;
        assert!(
            Config::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut duplicate = valid.clone();
    duplicate["issuers"]
        .as_array_mut()
        .unwrap()
        .push(valid["issuers"][0].clone());
    assert!(Config::decode(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    assert!(Config::decode(br#"{"profile":"a","profile":"b"}"#).is_err());
}

#[test]
fn staging_preserves_atomic_custody_and_refuses_links_or_widening() {
    let (_temp, root) = fixture();
    let stage = root.join("stage");
    let opened = kedgeflow::file_custody::Root::open(&stage).unwrap();
    opened.stage_batch(b"original").unwrap();
    let retained = fs::File::open(stage.join("batch.json")).unwrap();
    opened.stage_batch(b"replacement").unwrap();
    assert_ne!(
        retained.metadata().unwrap().ino(),
        fs::metadata(stage.join("batch.json")).unwrap().ino()
    );
    assert_eq!(
        fs::metadata(stage.join("batch.json")).unwrap().mode() & 0o7777,
        0o440
    );
    fs::hard_link(stage.join("batch.json"), stage.join("alias")).unwrap();
    assert!(opened.stage_batch(b"unsafe").is_err());
    fs::remove_file(stage.join("alias")).unwrap();
    fs::remove_file(stage.join("batch.json")).unwrap();
    write(&root, "outside", b"unchanged");
    symlink(root.join("outside"), stage.join("batch.json")).unwrap();
    assert!(opened.stage_batch(b"unsafe").is_err());
    assert_eq!(fs::read(root.join("outside")).unwrap(), b"unchanged");
    fs::remove_file(stage.join("batch.json")).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(opened.stage_batch(b"unsafe").is_err());
}

async fn api(
    client: &reqwest::Client,
    endpoint: &str,
    route: &str,
    body: Value,
    token: Option<&str>,
) -> (u16, Value) {
    let mut request = client.post(format!("{endpoint}/v3/{route}")).json(&body);
    if let Some(token) = token {
        request = request.header("authorization", token);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let raw = response.bytes().await.unwrap();
    let parsed = serde_json::from_slice(&raw).unwrap_or_else(|_| {
        panic!(
            "non-JSON fixture response: route={route} status={status} bytes={}",
            raw.len()
        )
    });
    (status, parsed)
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn ordinary_principal_audit_stages_only_a_fully_approved_batch() {
    let binary = match std::env::var("ETCD_BINARY") {
        Ok(path) => path,
        Err(_) => {
            assert_ne!(
                std::env::var("KF_REQUIRE_ETCD").as_deref(),
                Ok("1"),
                "ETCD_BINARY required"
            );
            eprintln!(
                "SKIP credential issuance: set ETCD_BINARY; KF_REQUIRE_ETCD=1 prohibits skip"
            );
            return;
        }
    };
    let (_temp, root) = fixture();
    // etcd's embedded JSON gateway also dials its own gRPC listener using this
    // certificate, so the fixture leaf must permit both server and client auth.
    let pki = support::etcd_gateway_pki(&["spiffe://test/credentials"])
        .pop()
        .unwrap();
    for (name, raw) in [
        ("ca.pem", &pki.ca),
        ("server.pem", &pki.server),
        ("server.key", &pki.server_key),
        ("client.pem", &pki.client),
        ("client.key", &pki.client_key),
    ] {
        write(&root, name, raw.as_bytes());
    }
    let password = format!("disposable-credential-test-{:032x}", rand::random::<u128>());
    write(&root, "password", password.as_bytes());
    let endpoint = format!("https://127.0.0.1:{}", port());
    let peer = format!("http://127.0.0.1:{}", port());
    let mut command = Command::new(binary);
    command
        .args([
            "--name=credentials",
            "--log-level=error",
            "--client-cert-auth",
        ])
        .arg(format!("--data-dir={}", root.join("etcd").display()))
        .arg(format!("--listen-client-urls={endpoint}"))
        .arg(format!("--advertise-client-urls={endpoint}"))
        .arg(format!("--listen-peer-urls={peer}"))
        .arg(format!("--initial-advertise-peer-urls={peer}"))
        .arg(format!("--initial-cluster=credentials={peer}"))
        .arg(format!(
            "--trusted-ca-file={}",
            root.join("ca.pem").display()
        ))
        .arg(format!("--cert-file={}", root.join("server.pem").display()))
        .arg(format!("--key-file={}", root.join("server.key").display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut etcd = Etcd(command.spawn().unwrap());
    let files = ServiceFiles::protected(&root).unwrap();
    let client = files
        .http_client(
            &root.join("ca.pem"),
            &root.join("client.pem"),
            &root.join("client.key"),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    let mut ready = false;
    for _ in 0..100 {
        assert!(etcd.0.try_wait().unwrap().is_none(), "fixture etcd exited");
        if client
            .get(format!("{endpoint}/health"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "fixture etcd unavailable");
    for user in ["root", "ordinary", "admin-alias", "reader"] {
        assert_eq!(
            api(
                &client,
                &endpoint,
                "auth/user/add",
                json!({"name":user,"password":password}),
                None
            )
            .await
            .0,
            200
        );
    }
    for role in ["root", "ordinary", "reader"] {
        assert_eq!(
            api(
                &client,
                &endpoint,
                "auth/role/add",
                json!({"name":role}),
                None
            )
            .await
            .0,
            200
        );
        assert_eq!(
            api(
                &client,
                &endpoint,
                "auth/user/grant",
                json!({"user":role,"role":role}),
                None
            )
            .await
            .0,
            200
        );
    }
    assert_eq!(
        api(
            &client,
            &endpoint,
            "auth/user/grant",
            json!({"user":"admin-alias","role":"root"}),
            None
        )
        .await
        .0,
        200
    );
    let grant = |key: &str, end: &str| json!({"name":"ordinary", "perm":{"permType":"READWRITE","key":STANDARD.encode(key),"range_end":STANDARD.encode(end)}});
    let mut read_permission = grant("/authority/", "/authority0");
    read_permission["name"] = json!("reader");
    read_permission["perm"]["permType"] = json!("READ");
    assert_eq!(
        api(&client, &endpoint, "auth/role/grant", read_permission, None)
            .await
            .0,
        200
    );
    assert_eq!(
        api(
            &client,
            &endpoint,
            "auth/role/grant",
            grant("/authority/", "/authority0"),
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        api(&client, &endpoint, "auth/enable", json!({}), None)
            .await
            .0,
        200
    );
    let value = configuration(&root, &endpoint);
    config(&value).check(&files).await.unwrap();
    assert!(!root.join("stage/batch.json").exists());
    assert!(
        config(&value)
            .issue(&ServiceFiles::default())
            .await
            .is_err()
    );
    let (status, authenticated) = api(
        &client,
        &endpoint,
        "auth/authenticate",
        json!({"name":"ordinary","password":password}),
        None,
    )
    .await;
    assert_eq!(status, 200, "ordinary authentication status");
    assert!(
        authenticated.get("token").and_then(Value::as_str).is_some(),
        "ordinary authentication token absent"
    );
    let mut readonly = value.clone();
    readonly["issuers"][0]["username"] = json!("reader");
    readonly["issuers"][0]["permissions"][0]["permission"] = json!("READ");
    readonly["issuers"][0]["endpoint"] = json!(endpoint.replacen("https", "HTTPS", 1));
    assert_eq!(config(&readonly).issue(&files).await.unwrap(), 1);
    let read_batch: Value =
        serde_json::from_slice(&fs::read(root.join("stage/batch.json")).unwrap()).unwrap();
    let read_token = read_batch["credentials"][0]["token"].as_str().unwrap();
    assert_eq!(
        api(
            &client,
            &endpoint,
            "kv/range",
            json!({"key":STANDARD.encode("/authority/test")}),
            Some(read_token)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        api(
            &client,
            &endpoint,
            "kv/put",
            json!({"key":STANDARD.encode("/authority/test"),"value":STANDARD.encode("forbidden")}),
            Some(read_token)
        )
        .await
        .0,
        403
    );
    assert_eq!(config(&value).issue(&files).await.unwrap(), 1);
    let original = fs::read(root.join("stage/batch.json")).unwrap();
    let batch: Value = serde_json::from_slice(&original).unwrap();
    let token = batch["credentials"][0]["token"].as_str().unwrap();
    assert_eq!(
        api(
            &client,
            &endpoint,
            "kv/range",
            json!({"key":STANDARD.encode("/authority/test")}),
            Some(token)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        api(
            &client,
            &endpoint,
            "kv/range",
            json!({"key":STANDARD.encode("/outside/test")}),
            Some(token)
        )
        .await
        .0,
        403
    );
    assert_eq!(
        api(
            &client,
            &endpoint,
            "auth/user/add",
            json!({"name":"forbidden","password":password}),
            Some(token)
        )
        .await
        .0,
        403
    );
    let mut alias = value.clone();
    alias["issuers"][0]["username"] = json!("admin-alias");
    assert!(config(&alias).issue(&files).await.is_err());
    let mut second = value.clone();
    let mut bad = value["issuers"][0].clone();
    bad["name"] = json!("second");
    bad["username"] = json!("nonexistent");
    second["issuers"].as_array_mut().unwrap().push(bad);
    assert!(config(&second).issue(&files).await.is_err());
    assert!(fs::read(root.join("stage/batch.json")).unwrap() == original);
    let root_token = api(
        &client,
        &endpoint,
        "auth/authenticate",
        json!({"name":"root","password":password}),
        None,
    )
    .await
    .1;
    let root_token = root_token["token"].as_str().unwrap();
    assert_eq!(
        api(
            &client,
            &endpoint,
            "auth/role/grant",
            grant("/outside/", "/outside0"),
            Some(root_token)
        )
        .await
        .0,
        200
    );
    assert!(config(&value).issue(&files).await.is_err());
    assert!(fs::read(root.join("stage/batch.json")).unwrap() == original);
    write(
        &root,
        "password",
        b"wrong-password-with-at-least-32-characters",
    );
    write(&root, "issuer.json", &serde_json::to_vec(&value).unwrap());
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-ledger-credentials"))
        .arg("--config")
        .arg(root.join("issuer.json"))
        .arg("--custody-root")
        .arg(&root)
        .arg("--issue")
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    for raw in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(raw);
        assert!(
            !text.contains(&password) && !text.contains(token) && !text.contains("wrong-password")
        );
    }
    let incompatible = support::pki();
    write(&root, "client.pem", incompatible.client.as_bytes());
    assert!(config(&value).check(&files).await.is_err());
}
