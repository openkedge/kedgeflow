//! Core A2A v1 over real mTLS/DPoP and retained etcd family events.
use super::*;
use kedgeflow::{
    family::{Action, Command, Family, Registration},
    family_peer::{EXTENSION, Peer},
};
struct TaskPeer {
    h: Harness,
    r: Registration,
    f: Family,
    url: String,
    client: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TaskPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TaskPeer {
    async fn new() -> Option<Self> {
        let (h, r, f) = family_tests::setup(2, 2).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/a2a", listener.local_addr().unwrap());
        let task = Self::serve(&h, &r, &url, listener);
        let client = kedgeflow::tls::pinned_http_client_pem(
            h.agent_pki.ca.as_bytes(),
            h.agent_pki.client.as_bytes(),
            h.agent_pki.client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap();
        Some(Self {
            h,
            r,
            f,
            url,
            client,
            task,
        })
    }
    fn serve(
        h: &Harness,
        r: &Registration,
        url: &str,
        listener: tokio::net::TcpListener,
    ) -> tokio::task::JoinHandle<()> {
        let auth = DualAuthenticator::new(
            &h.f.identity.subject.iss,
            AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let peer = Arc::new(
            Peer::new(
                Family::new(h.ledger.clone(), r.clone()).unwrap(),
                auth,
                url,
                "kf.family.coordinate".into(),
                h.clock.clone(),
            )
            .unwrap(),
        );
        let tls = kedgeflow::tls::server_config_pem(
            h.agent_pki.server.as_bytes(),
            h.agent_pki.server_key.as_bytes(),
            h.agent_pki.ca.as_bytes(),
        )
        .unwrap();
        tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, tls, peer.router())
                .await
                .unwrap();
        })
    }
    fn token(&self, subject: &str, scope: &str) -> String {
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&self.h.jwk).unwrap()));
        jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":self.h.f.identity.subject.iss,"sub":subject,"aud":AUD,"exp":NOW/1000+60,"iat":NOW/1000,"scope":scope,"cnf":{"jkt":jkt}}),
            7,
        )
    }
    fn headers(&self, subject: &str, scope: &str) -> http::HeaderMap {
        let token = self.token(subject, scope);
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":self.h.jwk}),
            json!({"jti":format!("family-peer-{}",self.h.jti.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":self.url,"iat":self.h.clock.0.load(Ordering::SeqCst)/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}),
            8,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("DPoP {token}").parse().unwrap());
        headers.insert("dpop", proof.parse().unwrap());
        headers.insert("a2a-version", "1.0".parse().unwrap());
        headers.insert("a2a-extensions", EXTENSION.parse().unwrap());
        headers
    }
    async fn post_headers(&self, v: &Value, headers: http::HeaderMap) -> (u16, Value) {
        let r = self
            .client
            .post(&self.url)
            .headers(headers)
            .json(v)
            .send()
            .await
            .unwrap();
        assert_eq!(r.headers()["cache-control"], "no-store");
        (r.status().as_u16(), r.json().await.unwrap())
    }
    async fn post(&self, v: &Value, delegated: bool) -> Value {
        let who = if delegated {
            "family-delegate"
        } else {
            &self.h.f.identity.subject.sub
        };
        let (status, v) = self
            .post_headers(v, self.headers(who, "kf.family.coordinate"))
            .await;
        assert_eq!(status, 200);
        v
    }
    async fn command(&self, n: u64, a: Action, delegated: bool) -> Command {
        family_tests::command(&self.r, &self.f.status().await.unwrap(), n, a, delegated)
    }
}
fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"transport-correlation","method":method,"params":params})
}
fn send(command: &Command) -> Value {
    rpc(
        "SendMessage",
        json!({"message":{"messageId":"message-correlation","role":"ROLE_USER","extensions":[EXTENSION],"parts":[{"data":command,"mediaType":"application/json"}]}}),
    )
}
#[tokio::test]
async fn family_tasks_durable_ids_nested_owner_acl_and_native_child_authority() {
    let Some(mut p) = TaskPeer::new().await else {
        return;
    };
    let b = family_tests::branch(&p.r, "root");
    let delegate = p
        .command(
            1,
            Action::Delegate {
                parent: "root".into(),
                branch: b,
            },
            false,
        )
        .await;
    let d = p.post(&send(&delegate), false).await;
    assert!(d.get("error").is_none(), "{d}");
    let delegated_task = d["result"]["task"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        p.post(&rpc("GetTask", json!({"id":delegated_task})), true)
            .await["result"]["id"],
        delegated_task
    );
    let attach = p
        .command(
            2,
            Action::Attach {
                parent: delegate.payload.operation_key.clone(),
                child_id: "child-0".into(),
            },
            true,
        )
        .await;
    assert_eq!(p.post(&send(&attach), false).await["error"]["code"], -32602);
    let a = p.post(&send(&attach), true).await;
    assert!(a.get("error").is_none(), "{a}");
    let id = a["result"]["task"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        a["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
    assert_eq!(
        a["result"]["task"]["artifacts"][0]["parts"][0]["data"]["executionAuthority"],
        false
    );
    let before = p.f.status().await.unwrap();
    let mut retry = send(&attach);
    retry["id"] = json!("new-rpc");
    retry["params"]["message"]["messageId"] = json!("new-message");
    assert_eq!(
        p.post(&retry, true).await["result"]["task"],
        a["result"]["task"]
    );
    let mut fresh = attach.clone();
    fresh.payload.operation_key = "9".repeat(64);
    fresh.payload.expected_head = before.head.clone();
    fresh = Command::sign(
        fresh.payload,
        "delegate",
        &SigningKey::from_bytes(&[32; 32]),
    )
    .unwrap();
    assert_eq!(p.post(&send(&fresh), true).await["error"]["code"], -32602);
    assert_eq!(p.f.status().await.unwrap(), before);
    assert_eq!(
        p.post(&rpc("CancelTask", json!({"id":id})), true).await["error"]["code"],
        -32002
    );
    // Completed coordination grants neither child admission nor execution. The
    // independently enrolled native child must still obtain its own signed grant.
    let c = family_tests::child(&p.h, &p.r, 0).await;
    let record = c.issue().await.unwrap().record;
    let grant = family_tests::grant(&c, &record);
    assert_ne!(record.grant_digest, id);
    assert!(
        c.ledger
            .claim(&grant, &id, "task-id-is-not-a-grant")
            .await
            .is_err()
    );
    let attempt = c
        .ledger
        .claim(&grant, &record.grant_digest, "native-only")
        .await
        .unwrap();
    c.ledger
        .authorize_dispatch(&grant, &record.grant_digest, &attempt.id)
        .await
        .unwrap();
    // An actual listener restart reconstructs tasks from the original retained
    // signed events, not process memory, message IDs or a new allocation.
    p.task.abort();
    let _ = (&mut p.task).await;
    let addr = p
        .url
        .trim_start_matches("https://")
        .trim_end_matches("/a2a");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    p.task = TaskPeer::serve(&p.h, &p.r, &p.url, listener);
    assert_eq!(
        p.post(&rpc("GetTask", json!({"id":id})), true).await["result"],
        a["result"]["task"]
    );
    family_tests::stop(&p.f, &p.r, 3, "root").await;
    assert_eq!(
        p.post(&rpc("GetTask", json!({"id":id})), true).await["result"]["id"],
        id
    );
    assert!(c.issue().await.is_err());
    assert_eq!(p.f.status().await.unwrap().attachments.len(), 1);
}
#[tokio::test]
async fn family_tasks_closed_protocol_pagination_identity_and_unsupported_features() {
    let Some(p) = TaskPeer::new().await else {
        return;
    };
    let owner = &p.h.f.identity.subject.sub;
    let command = p
        .command(
            1,
            Action::Attach {
                parent: "root".into(),
                child_id: "child-0".into(),
            },
            false,
        )
        .await;
    let original = send(&command);
    for (version, extension, code) in [
        (Some("0.3"), Some(EXTENSION), -32009),
        (None, Some(EXTENSION), -32009),
        (Some("1.0"), None, -32008),
    ] {
        let mut h = p.headers(owner, "kf.family.coordinate");
        h.remove("a2a-version");
        h.remove("a2a-extensions");
        if let Some(v) = version {
            h.insert("a2a-version", v.parse().unwrap());
        }
        if let Some(v) = extension {
            h.insert("a2a-extensions", v.parse().unwrap());
        }
        assert_eq!(p.post_headers(&original, h).await.1["error"]["code"], code);
    }
    for (path, value) in [
        ("contextId", json!("client-selected-context")),
        ("taskId", json!("new-client-task")),
        ("referenceTaskIds", json!(["external-task"])),
        ("unexpected", json!(true)),
    ] {
        let mut q = original.clone();
        q["params"]["message"][path] = value;
        assert!(p.post(&q, false).await.get("error").is_some(), "{path}");
    }
    let mut q = original.clone();
    q["params"]["message"]["parts"][0] = json!({"url":"https://elsewhere.invalid/object"});
    assert!(p.post(&q, false).await.get("error").is_some());
    assert_eq!(
        p.post_headers(&original, p.headers(owner, "unrelated.scope"))
            .await
            .0,
        403
    );
    assert_eq!(
        p.post_headers(&original, p.headers("unapproved", "kf.family.coordinate"))
            .await
            .0,
        403
    );
    assert_eq!(
        p.post(&json!([original]), false).await["error"]["code"],
        -32600
    );
    assert_eq!(
        p.post(&rpc("ListTasks", json!({"pageSize":1.0})), false)
            .await["error"]["code"],
        -32700
    );
    let mut utf8 = p.headers(owner, "kf.family.coordinate");
    utf8.insert(
        "content-type",
        "application/json; charset=utf-8".parse().unwrap(),
    );
    assert_eq!(
        p.post_headers(&rpc("ListTasks", json!({})), utf8).await.0,
        200
    );
    assert!(p.f.status().await.unwrap().events.is_empty());
    p.post(&send(&command), false).await;
    p.h.clock.0.store(NOW + 1000, Ordering::SeqCst);
    let second = p
        .command(
            2,
            Action::Attach {
                parent: "root".into(),
                child_id: "child-1".into(),
            },
            false,
        )
        .await;
    p.post(&send(&second), false).await;
    let page = p
        .post(
            &rpc("ListTasks", json!({"pageSize":1,"includeArtifacts":true})),
            false,
        )
        .await;
    assert_eq!(page["result"]["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(page["result"]["totalSize"], 2);
    let token = page["result"]["nextPageToken"].clone();
    let next = p
        .post(
            &rpc(
                "ListTasks",
                json!({"pageSize":1,"pageToken":token,"includeArtifacts":true}),
            ),
            false,
        )
        .await;
    assert_eq!(next["result"]["nextPageToken"], "");
    assert!(next["result"]["tasks"][0].get("artifacts").is_some());
    let plain = p.post(&rpc("ListTasks", json!({})), false).await;
    assert!(plain["result"]["tasks"][0].get("artifacts").is_none());
    assert_eq!(
        plain["result"]["tasks"][0]["status"]["timestamp"],
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(NOW + 1000)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );
    let boundary = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(NOW + 1000)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(
        p.post(
            &rpc("ListTasks", json!({"statusTimestampAfter":boundary})),
            false
        )
        .await["result"]["totalSize"],
        1
    );
    assert_eq!(
        p.post(
            &rpc("ListTasks", json!({"statusTimestampAfter":"not-a-time"})),
            false
        )
        .await["error"]["code"],
        -32602
    );
    assert_eq!(
        p.post(&rpc("ListTasks", json!({})), true).await["result"]["totalSize"],
        0
    );
    for (method, code) in [
        ("SendStreamingMessage", -32004),
        ("SubscribeToTask", -32004),
        ("CreateTaskPushNotificationConfig", -32003),
        ("GetExtendedAgentCard", -32007),
        ("message/send", -32601),
    ] {
        assert_eq!(
            p.post(&rpc(method, json!({})), false).await["error"]["code"],
            code
        );
    }
    family_tests::stop(&p.f, &p.r, 3, "root").await;
    assert_eq!(
        p.post(&rpc("ListTasks", json!({"pageToken":token})), false)
            .await["error"]["code"],
        -32602
    );
    assert_eq!(p.f.status().await.unwrap().attachments.len(), 2);
}
#[tokio::test]
async fn family_tasks_shipping_peer_official_sdk_lost_reply_and_process_restart() {
    use axum::{Json, Router, routing::post};
    use kedgeflow::clock::{Clock, SystemClock};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !root
        .join("tests/sdk/node_modules/@a2a-js/sdk/package.json")
        .is_file()
    {
        assert_ne!(
            std::env::var("KF_REQUIRE_SDK").as_deref(),
            Ok("1"),
            "required pinned A2A SDK missing"
        );
        eprintln!("SKIP A2A SDK: npm ci --prefix tests/sdk");
        return;
    }
    let Some((h, mut r, _)) = family_tests::setup(1, 1).await else {
        return;
    };
    let now = SystemClock.now_ms();
    r.valid_from = now - 1000;
    r.expires_at = now + 60000;
    r.namespace = format!("{}-peer-cli", h.prefix);
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
        let path = dir.path().join(name);
        std::fs::write(&path, raw).unwrap();
        path
    };
    let ca = write("ca.pem", h.agent_pki.ca.as_bytes());
    let cert = write("client.pem", h.agent_pki.client.as_bytes());
    let key = write("client.key", h.agent_pki.client_key.as_bytes());
    let server_cert = write("server.pem", h.agent_pki.server.as_bytes());
    let server_key = write("server.key", h.agent_pki.server_key.as_bytes());
    let token_file = write("etcd.token", b"generated-etcd-test-token");
    let authority = json!({"registration":r,"etcd_endpoint":proxy.url,"etcd_prefix":r.namespace,"etcd_ca":ca,"etcd_certificate":cert,"etcd_private_key":key,"etcd_token_file":token_file});
    let authority_path = write("authority.json", &serde_json::to_vec(&authority).unwrap());
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-family"))
        .args(["--config"])
        .arg(authority_path)
        .arg("--enroll")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("https://{listen}/a2a");
    let config = json!({"authority":authority,"listen":listen.to_string(),"external_url":url,"certificate":server_cert,"private_key":server_key,"workload_ca":ca,"oidc_issuer":h.f.identity.subject.iss,"oidc_public_key_base64":base64::engine::general_purpose::STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),"delegation_audience":AUD,"shared_auth":{"capacity":128,"registrations":[{"subject":r.owner.subject,"workload_id":r.owner.workload_id,"allowed_scopes":["kf.family.coordinate"]}]}});
    let config_path = write("peer.json", &serde_json::to_vec(&config).unwrap());
    let cli = || {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-family-peer"));
        c.arg("--config").arg(&config_path).kill_on_drop(true);
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
    let start = || {
        let mut c = cli();
        c.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        c.spawn().unwrap()
    };
    let mut colliding = config.clone();
    colliding["oidc_public_key_base64"] = json!(
        base64::engine::general_purpose::STANDARD
            .encode(SigningKey::from_bytes(&[31; 32]).verifying_key().as_bytes())
    );
    let bad_path = write("bad-peer.json", &serde_json::to_vec(&colliding).unwrap());
    assert!(
        !tokio::process::Command::new(env!("CARGO_BIN_EXE_kf-family-peer"))
            .arg("--config")
            .arg(bad_path)
            .arg("--check")
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    let mut process = start();
    let client = kedgeflow::tls::pinned_http_client_pem(
        h.agent_pki.ca.as_bytes(),
        h.agent_pki.client.as_bytes(),
        h.agent_pki.client_key.as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap();
    async fn ready(client: &reqwest::Client, url: &str) {
        for _ in 0..100 {
            if client
                .get(format!(
                    "{}/.well-known/agent-card.json",
                    url.trim_end_matches("/a2a")
                ))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("shipping A2A peer not ready");
    }
    ready(&client, &url).await;
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&h.jwk).unwrap()));
    let token = jwt(
        json!({"alg":"EdDSA","typ":"at+jwt"}),
        json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":now/1000+60,"iat":now/1000,"scope":"kf.family.coordinate","cnf":{"jkt":jkt}}),
        7,
    );
    let mut fixture = json!({"mode":"lost","url":url,"registration":r,"now":now,"token":token,"tls":{"ca":h.agent_pki.ca,"cert":h.agent_pki.client,"key":h.agent_pki.client_key}});
    let path = write("node.json", &serde_json::to_vec(&fixture).unwrap());
    let output = tokio::process::Command::new("node")
        .arg(root.join("tests/sdk/family-tasks-live.mjs"))
        .arg(&path)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "PASS");
    let command = result["command"].clone();
    let task_id = result["taskId"].clone();
    process.kill().await.unwrap();
    process.wait().await.unwrap();
    let fconfig =
        kedgeflow::family::Config::decode(&serde_json::to_vec(&authority).unwrap()).unwrap();
    let family = fconfig.family().await.unwrap();
    let s = family.status().await.unwrap();
    assert_eq!(s.attachments.len(), 1);
    assert_eq!(s.events.len(), 1);
    family
        .apply(
            Command::sign(
                kedgeflow::family::CommandPayload {
                    family_digest: r.digest().unwrap(),
                    operation_key: "2".repeat(64),
                    expected_head: s.head,
                    issued_at: now,
                    expires_at: now + 30000,
                    action: Action::Stop {
                        branch_id: "root".into(),
                    },
                },
                "owner",
                &SigningKey::from_bytes(&[31; 32]),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    process = start();
    ready(&client, &url).await;
    fixture["mode"] = json!("query");
    fixture["command"] = command;
    std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    let output = tokio::process::Command::new("node")
        .arg(root.join("tests/sdk/family-tasks-live.mjs"))
        .arg(path)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["taskId"], task_id);
    process.kill().await.unwrap();
    process.wait().await.unwrap();
    let s = family.status().await.unwrap();
    assert_eq!(s.attachments.len(), 1);
    assert_eq!(s.events.len(), 2);
    assert!(!s.active);
    println!(
        "A2A SDK PASS: official 1.0.1 discovery/tasks, lost reply, exact signed replay, native peer process restart and original query after stop; no grant/target effect from task IDs"
    );
}
