//! Real issuer rollover, private publisher fixtures, shipping broker refusal before mint.
use super::*;
use kedgeflow::{
    contracts::canonical,
    exchange_identity::{ActorKey, SubjectKey, TrustSnapshot},
    identity_refresh::{FileRefreshSource, RealmPins, RefreshingIdentityProvider},
};
use sha2::Digest;
use std::{os::unix::fs::PermissionsExt, path::Path};

const AUTHORITY: &str = "operator-refresh";
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn jwt(raw: &str, part: usize) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(raw.split('.').nth(part).unwrap())
            .unwrap(),
    )
    .unwrap()
}
fn snapshot(packet: &Value, bundle: &Value, url: &str, now: i64) -> TrustSnapshot {
    let raw = packet["subject_token"].as_str().unwrap();
    let claims = jwt(raw, 1);
    let key_id = jwt(raw, 0)["kid"].as_str().unwrap().to_owned();
    let key = packet["keycloak_jwks"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"] == key_id)
        .unwrap();
    assert_eq!(key["crv"], "Ed25519");
    let actors = bundle["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["use"] == "jwt-svid")
        .map(|key| {
            assert_eq!(key["crv"], "P-256");
            let mut point = vec![4];
            point.extend(URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap()).unwrap());
            point.extend(URL_SAFE_NO_PAD.decode(key["y"].as_str().unwrap()).unwrap());
            ActorKey {
                kid: key["kid"].as_str().unwrap().into(),
                trust_domain: "pilot.kedgeflow.test".into(),
                alg: "ES256".into(),
                r#use: "jwt-svid".into(),
                public_key: URL_SAFE_NO_PAD.encode(point),
                not_before: now - 5000,
                expires_at: now + 120000,
            }
        })
        .collect();
    TrustSnapshot {
        profile: kedgeflow::exchange_identity::PROFILE.into(),
        epoch: 1,
        not_before: now - 5000,
        expires_at: now + 120000,
        issuer: claims["iss"].as_str().unwrap().into(),
        subject_audience: claims["aud"].as_str().unwrap().into(),
        actor_audience: url.into(),
        subject_keys: vec![SubjectKey {
            kid: key_id,
            public_key: key["x"].as_str().unwrap().into(),
            not_before: now - 5000,
            expires_at: now + 120000,
        }],
        actor_keys: actors,
        registrations: vec![kedgeflow::shared_auth::SubjectWorkload {
            subject: serde_json::from_value(json!({"iss":claims["iss"],"sub":claims["sub"]}))
                .unwrap(),
            workload_id: "spiffe://pilot.kedgeflow.test/gateway".into(),
            allowed_scopes: claims["scope"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .map(String::from)
                .collect(),
        }],
        withdrawn_subject_tokens: vec![],
    }
}
fn provider(
    temp: &tempfile::TempDir,
    snapshot: &TrustSnapshot,
    key: &SigningKey,
    floor: u64,
) -> RefreshingIdentityProvider {
    RefreshingIdentityProvider::new(
        Arc::new(FileRefreshSource {
            head_file: temp.path().join("head.json"),
            signed_snapshot_file: temp.path().join("signed.json"),
        }),
        RealmPins {
            issuer: snapshot.issuer.clone(),
            subject_audience: snapshot.subject_audience.clone(),
            actor_audience: snapshot.actor_audience.clone(),
        },
        AUTHORITY.into(),
        BTreeMap::from([("refresh-1".into(), key.verifying_key())]),
        Default::default(),
        floor,
    )
    .unwrap()
    .with_keycloak_pilot("kf-pilot-agent")
    .unwrap()
}
async fn permits(h: &Harness) -> Vec<Value> {
    let prefix = h.ledger.namespace();
    let response: Value = reqwest::Client::new().post(format!("{}/v3/kv/range", std::env::var("ETCD_ENDPOINT").unwrap()))
        .json(&json!({"key":STANDARD.encode(prefix),"range_end":STANDARD.encode(format!("{prefix}0"))}))
        .send().await.unwrap().json().await.unwrap();
    response["kvs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|kv| {
            String::from_utf8(STANDARD.decode(kv["key"].as_str().unwrap()).unwrap())
                .unwrap()
                .ends_with("/credential-permit")
        })
        .cloned()
        .collect()
}
async fn refused(h: &Harness, client: &reqwest::Client) {
    let response = client.post(&h.url).form(&h.fields()).send().await.unwrap();
    assert!(
        matches!(response.status().as_u16(), 400 | 503),
        "identity transition must refuse before mint"
    );
    assert!(permits(h).await.is_empty());
}
async fn verify_without_claim(h: &Harness, client: &reqwest::Client) {
    // Identity verification precedes original-claim lookup. A missing attempt
    // exercises a valid identity without spending the real claim's mint permit.
    let mut fields = h.fields();
    fields
        .iter_mut()
        .find(|(name, _)| name == "kedgeflow_attempt_id")
        .unwrap()
        .1 = "identity-cache-probe".into();
    let response = client.post(&h.url).form(&fields).send().await.unwrap();
    assert!(matches!(response.status().as_u16(), 400 | 503));
    assert!(permits(h).await.is_empty());
}
fn check(temp: &tempfile::TempDir, config: &Value) -> bool {
    let file = temp.path().join("check.json");
    std::fs::write(&file, canonical(config).unwrap()).unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_kf-broker"))
        .arg("--config")
        .arg(file)
        .arg("--check")
        .output()
        .unwrap()
        .status
        .success()
}
#[tokio::test]
async fn shipping_identity_lifecycle() {
    let input = std::path::PathBuf::from(
        std::env::var("KF_SELFHOSTED_INPUT").expect("explicit provider input required"),
    );
    let output = std::path::PathBuf::from(std::env::var("KF_SELFHOSTED_OUTPUT").unwrap());
    let old = read(input.join("old-packet.json"));
    let rotated = read(input.join("rotated.json"));
    let current = read(input.join("packet.json"));
    let workflow = read(input.join("workflow.json"));
    let storage_restore = workflow["storage_restore"].as_bool().unwrap_or(false);
    let url = workflow["broker_url"].as_str().unwrap().to_owned();
    let bundle = read(std::env::var("KF_SELFHOSTED_BUNDLE").unwrap());
    let now = kedgeflow::clock::SystemClock.now_ms();
    let initial = snapshot(&old, &bundle, &url, now);
    // Storage recovery must preserve the pre-restore trust decision; never
    // enroll a key merely because a restored provider advertises it.
    let mut latest = snapshot(
        if storage_restore { &rotated } else { &current },
        &bundle,
        &url,
        now,
    );
    assert_ne!(
        initial.subject_keys[0].kid, latest.subject_keys[0].kid,
        "issuer must actually change signing key"
    );
    assert_ne!(
        initial.subject_keys[0].public_key,
        latest.subject_keys[0].public_key
    );
    assert_eq!(
        jwt(rotated["subject_token"].as_str().unwrap(), 0)["kid"],
        json!(latest.subject_keys[0].kid)
    );
    assert_eq!(
        jwt(rotated["subject_token"].as_str().unwrap(), 1)["sub"],
        jwt(current["subject_token"].as_str().unwrap(), 1)["sub"]
    );
    let stale_restored = if storage_restore {
        let restored = read(input.join("latest-restored.json"));
        let stale = read(input.join("stale-restored.json"));
        assert_ne!(restored["subject_token"], rotated["subject_token"]);
        assert_ne!(stale["subject_token"], old["subject_token"]);
        assert_ne!(current["subject_token"], restored["subject_token"]);
        for packet in [&restored, &current] {
            assert_eq!(
                jwt(packet["subject_token"].as_str().unwrap(), 0)["kid"],
                json!(latest.subject_keys[0].kid)
            );
            assert_eq!(
                jwt(packet["subject_token"].as_str().unwrap(), 1)["sub"],
                jwt(old["subject_token"].as_str().unwrap(), 1)["sub"]
            );
        }
        assert_eq!(
            jwt(stale["subject_token"].as_str().unwrap(), 0)["kid"],
            json!(initial.subject_keys[0].kid)
        );
        // A stale restored provider genuinely issues valid old-key credentials.
        // Refusal under current trust must not rely on a corrupt token.
        let original =
            kedgeflow::exchange_identity::PinnedExchangeIdentityProvider::new(initial.clone(), 1)
                .unwrap()
                .with_keycloak_pilot("kf-pilot-agent")
                .unwrap();
        assert!(
            original
                .verify(
                    stale["subject_token"].as_str().unwrap(),
                    stale["actor_token"].as_str().unwrap(),
                    now
                )
                .await
                .is_ok()
        );
        Some((restored, stale))
    } else {
        None
    };
    let mut h = Harness::new_at_with_identity(
        true,
        now,
        Some((
            latest.clone(),
            current["subject_token"].as_str().unwrap().into(),
            current["actor_token"].as_str().unwrap().into(),
            url,
        )),
    )
    .await
    .expect("required actual etcd");
    let temp = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[15; 32]);
    let mut config = refresh_configuration(&h, &temp, &key);
    config["etcd_endpoint"] = json!(std::env::var("ETCD_ENDPOINT").unwrap());
    config["delegation_audience"] = json!(latest.subject_audience);
    config["identity_profile"] =
        json!({"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,"client_id":"kf-pilot-agent"});
    for entry in std::fs::read_dir(temp.path()).unwrap() {
        std::fs::set_permissions(
            entry.unwrap().path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    publish_refresh(&temp, initial.clone(), &key);
    let mut child = start_shipping(&mut h, &temp, &config).await;
    let pid = child.0.id();
    let client = h.client(0, Duration::from_secs(3));
    // Correct, already claimed grant; only the new actual issuer key is missing.
    refused(&h, &client).await;
    latest.epoch = 2;
    let mut overlap = latest.clone();
    overlap.subject_keys.extend(initial.subject_keys.clone());
    publish_refresh(&temp, overlap.clone(), &key);
    let verifier = provider(&temp, &latest, &key, 1);
    for packet in [&old, &current] {
        assert!(
            verifier
                .verify(
                    packet["subject_token"].as_str().unwrap(),
                    packet["actor_token"].as_str().unwrap(),
                    now
                )
                .await
                .is_ok()
        );
    }
    let mut withdrawn = latest.clone();
    withdrawn.epoch = 3;
    withdrawn.withdrawn_subject_tokens =
        vec![hex::encode(sha2::Sha256::digest(h.subject.as_bytes()))];
    publish_refresh(&temp, withdrawn.clone(), &key);
    refused(&h, &client).await;
    // Restoring a previously valid complete pair cannot roll a live process back.
    publish_refresh(&temp, overlap.clone(), &key);
    refused(&h, &client).await;
    let mut higher = latest.clone();
    higher.epoch = 4;
    publish_refresh(&temp, higher.clone(), &key);
    std::fs::remove_file(temp.path().join("signed.json")).unwrap();
    refused(&h, &client).await;
    publish_refresh(&temp, withdrawn.clone(), &key);
    refused(&h, &client).await; // higher head remembered despite missing publication
    publish_refresh(&temp, higher.clone(), &key);
    verify_without_claim(&h, &client).await;
    let signed = std::fs::read(temp.path().join("signed.json")).unwrap();
    std::fs::remove_file(temp.path().join("signed.json")).unwrap();
    refused(&h, &client).await;
    std::fs::write(
        temp.path().join("signed.json"),
        canonical(&json!({"broken":true})).unwrap(),
    )
    .unwrap();
    refused(&h, &client).await;
    std::fs::write(temp.path().join("signed.json"), signed).unwrap();
    // Retained head with a restored stale snapshot must refuse, even on restart.
    let head = std::fs::read(temp.path().join("head.json")).unwrap();
    publish_refresh(&temp, initial.clone(), &key);
    std::fs::write(temp.path().join("head.json"), head).unwrap();
    refused(&h, &client).await;
    assert!(!check(&temp, &config));
    // Restoring BOTH files still cannot bypass an independently retained floor.
    std::fs::write(temp.path().join("epoch-floor"), "4").unwrap();
    publish_refresh(&temp, initial.clone(), &key);
    assert!(!check(&temp, &config));
    refused(&h, &client).await;
    // Key retirement and registration withdrawal are separately observed.
    let mut unregistered = latest.clone();
    unregistered.epoch = 5;
    unregistered.registrations[0].workload_id = "spiffe://pilot.kedgeflow.test/withdrawn".into();
    publish_refresh(&temp, unregistered, &key);
    refused(&h, &client).await;
    latest.epoch = 6;
    publish_refresh(&temp, latest.clone(), &key);
    let verifier = provider(&temp, &latest, &key, 4);
    assert!(
        verifier
            .verify(
                old["subject_token"].as_str().unwrap(),
                old["actor_token"].as_str().unwrap(),
                now
            )
            .await
            .is_err()
    );
    assert!(verifier.verify(&h.subject, &h.actor, now).await.is_ok());
    if let Some((restored, stale)) = &stale_restored {
        assert!(
            verifier
                .verify(
                    restored["subject_token"].as_str().unwrap(),
                    restored["actor_token"].as_str().unwrap(),
                    now
                )
                .await
                .is_ok()
        );
        assert!(
            verifier
                .verify(
                    stale["subject_token"].as_str().unwrap(),
                    stale["actor_token"].as_str().unwrap(),
                    now
                )
                .await
                .is_err()
        );
        let mut fields = h.fields();
        for (name, value) in &mut fields {
            if name == "subject_token" || name == "actor_token" {
                *value = stale[name.as_str()].as_str().unwrap().into();
            }
        }
        let response = client.post(&h.url).form(&fields).send().await.unwrap();
        assert_eq!(response.status(), 400);
        assert!(permits(&h).await.is_empty());
    }
    assert_eq!(child.0.id(), pid); // all hot reloads happened without restarting
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    drop(child);
    let _restarted = start_shipping(&mut h, &temp, &config).await;
    let response = client.post(&h.url).form(&h.fields()).send().await.unwrap();
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    let value: Value = response.json().await.unwrap();
    let binding = TokenBinding {
        grant_digest: h.call.grant_digest.clone(),
        root_id: h.call.grant.root_id.clone(),
        attempt_id: h.call.attempt_id.clone(),
        gateway_workload: GATEWAY.into(),
        audience: "urn:test:target".into(),
        scope: "target:update".into(),
        max_expires_at: h.call.grant.expires_at,
    };
    assert!(
        h.verifier()
            .verify(
                value["access_token"].as_str().unwrap(),
                &binding,
                kedgeflow::clock::SystemClock.now_ms()
            )
            .is_ok()
    );
    let retained_permits = permits(&h).await;
    assert_eq!(retained_permits.len(), 1);
    assert!(
        !client
            .post(&h.url)
            .form(&h.fields())
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert_eq!(permits(&h).await, retained_permits);
    h.held().await;
    let report = json!({"status":"passed_identity_lifecycle","actual_keycloak_rotation":true,"provider_restart_key_continuity":true,"provider_storage_restore":storage_restore,"pre_restore_issuer_pins":storage_restore,
        "old_kid":initial.subject_keys[0].kid,"new_kid":latest.subject_keys[0].kid,
        "cases":["unpublished_new_issuer_key","overlap_accepts_both_actual_tokens","subject_withdrawal_before_mint",
            "live_pair_rollback","missing_higher_publication","remember_higher_head_after_failure","publication_outage_after_verified_identity","invalid_publication_no_cached_fallback",
            "stale_snapshot_current_head","restart_stale_pair_retained_floor","workload_registration_withdrawal",
            "old_issuer_key_retired","fresh_epoch_restart_original_claim_one_mint","exchange_replay_refused"],
        "broker_hot_reload_pid_unchanged":true,"final_epoch":6,"original_attempt":h.call.attempt_id,"mint_permits":1,"permit_unchanged_on_replay":true,
        "broker_binary_sha256":hex::encode(sha2::Sha256::digest(std::fs::read(env!("CARGO_BIN_EXE_kf-broker")).unwrap())),
        "storage_cases":if storage_restore {json!(["fresh_latest_restore_key_and_subject_continuity","fresh_stale_provider_issues_old_valid_credentials","retained_current_trust_refuses_stale_restored_issuer_before_mint","restored_spire_enrollment_and_jwt_signing_keys"])} else {json!([])},
        "scope":if storage_restore {"cold H2/SPIRE SQLite+disk key copies into fresh same-host containers; generated publisher/head/floor and grant/service PKI; no SQL action or production storage acceptance"} else {"real Keycloak/SPIRE credentials; generated publisher/head/floor, grant/service PKI and loopback etcd; no SQL or provider database restore"}});
    std::fs::write(
        output.join("identity-lifecycle.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "self-hosted identity lifecycle PASS: actual issuer rollover/restart, hot refresh and refusal before mint, retained floor restore, original claim consumed once"
    );
}

async fn svid_probe(pki: &support::Pki, bundle: &Path, svid: &Path) -> bool {
    use axum::{Extension, Json, Router, routing::post};
    use kedgeflow::auth::WorkloadIdentity;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/identity", listener.local_addr().unwrap());
    let config = tls::server_config_pem(
        pki.server.as_bytes(),
        pki.server_key.as_bytes(),
        &std::fs::read(bundle).unwrap(),
    )
    .unwrap();
    let router = Router::new().route(
        "/identity",
        post(
            |Extension(identity): Extension<WorkloadIdentity>| async move {
                Json(json!({"workload":identity.as_str()}))
            },
        ),
    );
    let task = tokio::spawn(kedgeflow::server::serve_router(listener, config, router));
    let client = tls::pinned_http_client_pem(
        pki.ca.as_bytes(),
        &std::fs::read(svid.join("svid.0.pem")).unwrap(),
        &std::fs::read(svid.join("svid.0.key")).unwrap(),
        Duration::from_secs(3),
    )
    .unwrap();
    let result = match client.post(url).send().await {
        Ok(response) if response.status().is_success() => {
            response.json::<Value>().await.unwrap()["workload"]
                == "spiffe://pilot.kedgeflow.test/gateway"
        }
        _ => false,
    };
    task.abort();
    let _ = task.await;
    result
}
fn ca_pem(root: &Path, name: &str, bundle: &Value) -> std::path::PathBuf {
    let mut bytes = Vec::new();
    for key in bundle["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| key["use"] == "x509-svid")
    {
        for cert in key["x5c"].as_array().unwrap() {
            let der = STANDARD.decode(cert.as_str().unwrap()).unwrap();
            bytes.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
            for chunk in STANDARD.encode(der).as_bytes().chunks(64) {
                bytes.extend_from_slice(chunk);
                bytes.push(b'\n');
            }
            bytes.extend_from_slice(b"-----END CERTIFICATE-----\n");
        }
    }
    assert!(!bytes.is_empty());
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}
async fn actor_refused(h: &Harness, client: &reqwest::Client, actor: &str) {
    let mut fields = h.fields();
    fields
        .iter_mut()
        .find(|(name, _)| name == "actor_token")
        .unwrap()
        .1 = actor.into();
    let response = client.post(&h.url).form(&fields).send().await.unwrap();
    assert!(matches!(response.status().as_u16(), 400 | 503));
    assert!(permits(h).await.is_empty());
}

#[tokio::test]
async fn shipping_spire_rollover() {
    let input = std::path::PathBuf::from(
        std::env::var("KF_SELFHOSTED_INPUT").expect("explicit real SPIRE input required"),
    );
    let output = std::path::PathBuf::from(std::env::var("KF_SELFHOSTED_OUTPUT").unwrap());
    let old = read(input.join("old-packet.json"));
    let rotated = read(input.join("rotated.json"));
    let current = read(input.join("packet.json"));
    assert_eq!(old["subject_token"], rotated["subject_token"]);
    assert_eq!(old["subject_token"], current["subject_token"]);
    assert_eq!(old["dpop_seed"], current["dpop_seed"]);
    let old_actor = old["actor_token"].as_str().unwrap();
    let new_actor = current["actor_token"].as_str().unwrap();
    let old_kid = jwt(old_actor, 0)["kid"].as_str().unwrap().to_owned();
    let new_kid = jwt(new_actor, 0)["kid"].as_str().unwrap().to_owned();
    assert_ne!(old_kid, new_kid);
    assert_eq!(
        jwt(rotated["actor_token"].as_str().unwrap(), 0)["kid"],
        json!(new_kid)
    );
    let initial_bundle = read(std::env::var("KF_SELFHOSTED_BUNDLE").unwrap());
    let overlap_bundle = read(output.join("spire-overlap.json"));
    let retired_bundle = read(output.join("spire-retired.json"));
    let url = read(input.join("workflow.json"))["broker_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let now = kedgeflow::clock::SystemClock.now_ms();
    let initial = snapshot(&old, &initial_bundle, &url, now);
    let mut overlap = snapshot(&old, &overlap_bundle, &url, now);
    // Current approval comes from the observed prepared keys before retirement/restart.
    let mut latest = overlap.clone();
    latest.actor_keys.retain(|key| key.kid == new_kid);
    assert_eq!(latest.actor_keys.len(), 1);
    assert!(initial.actor_keys.iter().all(|key| key.kid != new_kid));
    let old_key = initial
        .actor_keys
        .iter()
        .find(|key| key.kid == old_kid)
        .unwrap();
    assert_ne!(old_key.public_key, latest.actor_keys[0].public_key);
    let retired = snapshot(&old, &retired_bundle, &url, now);
    assert_eq!(retired.actor_keys.len(), 1);
    assert_eq!(retired.actor_keys[0].kid, new_kid);
    assert_eq!(
        retired.actor_keys[0].public_key,
        latest.actor_keys[0].public_key
    );
    let original =
        kedgeflow::exchange_identity::PinnedExchangeIdentityProvider::new(initial.clone(), 1)
            .unwrap()
            .with_keycloak_pilot("kf-pilot-agent")
            .unwrap();
    let a = original
        .verify(old["subject_token"].as_str().unwrap(), old_actor, now)
        .await
        .unwrap();
    let current_provider =
        kedgeflow::exchange_identity::PinnedExchangeIdentityProvider::new(latest.clone(), 1)
            .unwrap()
            .with_keycloak_pilot("kf-pilot-agent")
            .unwrap();
    let b = current_provider
        .verify(current["subject_token"].as_str().unwrap(), new_actor, now)
        .await
        .unwrap();
    assert_eq!(a.identity.delegation_digest, b.identity.delegation_digest);
    assert!(
        current_provider
            .verify(old["subject_token"].as_str().unwrap(), old_actor, now)
            .await
            .is_err()
    );
    let mut h = Harness::new_at_with_identity(
        true,
        now,
        Some((
            initial.clone(),
            old["subject_token"].as_str().unwrap().into(),
            old_actor.into(),
            url,
        )),
    )
    .await
    .expect("required etcd");
    let temp = tempfile::tempdir().unwrap();
    let ca_initial = ca_pem(temp.path(), "initial-ca.pem", &initial_bundle);
    let ca_overlap = ca_pem(temp.path(), "overlap-ca.pem", &overlap_bundle);
    let ca_retired = ca_pem(temp.path(), "retired-ca.pem", &retired_bundle);
    let mut tls_cases = Vec::new();
    for (name, ca, svid, expected) in [
        ("old_leaf_initial_ca", &ca_initial, "old-x509", true),
        (
            "new_leaf_refused_initial_ca",
            &ca_initial,
            "rotated-x509",
            false,
        ),
        ("old_leaf_overlap_ca", &ca_overlap, "old-x509", true),
        ("new_leaf_overlap_ca", &ca_overlap, "rotated-x509", true),
        (
            "old_leaf_refused_retired_ca",
            &ca_retired,
            "old-x509",
            false,
        ),
        ("new_leaf_retired_ca", &ca_retired, "rotated-x509", true),
        ("post_restart_leaf_retired_ca", &ca_retired, "x509", true),
    ] {
        assert_eq!(
            svid_probe(&h.pki[0], ca, &input.join(svid)).await,
            expected,
            "{name}"
        );
        tls_cases.push(name);
    }
    let key = SigningKey::from_bytes(&[15; 32]);
    let mut config = refresh_configuration(&h, &temp, &key);
    config["etcd_endpoint"] = json!(std::env::var("ETCD_ENDPOINT").unwrap());
    config["delegation_audience"] = json!(initial.subject_audience);
    config["identity_profile"] =
        json!({"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,"client_id":"kf-pilot-agent"});
    let mut child = start_shipping(&mut h, &temp, &config).await;
    let pid = child.0.id();
    let client = h.client(0, Duration::from_secs(3));
    verify_without_claim(&h, &client).await;
    actor_refused(&h, &client, new_actor).await;
    overlap.epoch = 2;
    publish_refresh(&temp, overlap, &key);
    let verifier = provider(&temp, &latest, &key, 1);
    for actor in [old_actor, new_actor] {
        let identity = verifier.verify(&h.subject, actor, now).await.unwrap();
        assert_eq!(
            identity.identity.delegation_digest,
            h.call.identity.delegation_digest
        );
    }
    latest.epoch = 3;
    publish_refresh(&temp, latest.clone(), &key);
    actor_refused(&h, &client, old_actor).await;
    publish_refresh(&temp, initial.clone(), &key);
    actor_refused(&h, &client, old_actor).await;
    latest.epoch = 4;
    publish_refresh(&temp, latest.clone(), &key);
    std::fs::remove_file(temp.path().join("signed.json")).unwrap();
    actor_refused(&h, &client, new_actor).await;
    let mut stale = latest.clone();
    stale.epoch = 3;
    publish_refresh(&temp, stale, &key);
    actor_refused(&h, &client, new_actor).await;
    publish_refresh(&temp, latest.clone(), &key);
    let signed = std::fs::read(temp.path().join("signed.json")).unwrap();
    let mut warm_fields = h.fields();
    for (name, value) in &mut warm_fields {
        match name.as_str() {
            "actor_token" => *value = new_actor.into(),
            "kedgeflow_attempt_id" => *value = "identity-cache-probe".into(),
            _ => (),
        }
    }
    // Exercise valid current identity verification without consuming the real
    // claim, then prove a broken publication cannot fall back and mint it.
    let warm = client.post(&h.url).form(&warm_fields).send().await.unwrap();
    assert!(matches!(warm.status().as_u16(), 400 | 503));
    assert!(permits(&h).await.is_empty());
    std::fs::write(temp.path().join("signed.json"), b"{}").unwrap();
    actor_refused(&h, &client, new_actor).await;
    std::fs::write(temp.path().join("signed.json"), signed).unwrap();
    std::fs::write(temp.path().join("epoch-floor"), "4").unwrap();
    publish_refresh(&temp, initial, &key);
    assert!(!check(&temp, &config));
    actor_refused(&h, &client, old_actor).await;
    latest.epoch = 5;
    publish_refresh(&temp, latest, &key);
    std::fs::write(temp.path().join("epoch-floor"), "5").unwrap();
    assert_eq!(child.0.id(), pid);
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    drop(child);
    let _restarted = start_shipping(&mut h, &temp, &config).await;
    let mut fields = h.fields();
    fields
        .iter_mut()
        .find(|(name, _)| name == "actor_token")
        .unwrap()
        .1 = new_actor.into();
    let response = client.post(&h.url).form(&fields).send().await.unwrap();
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    let value: Value = response.json().await.unwrap();
    let binding = TokenBinding {
        grant_digest: h.call.grant_digest.clone(),
        root_id: h.call.grant.root_id.clone(),
        attempt_id: h.call.attempt_id.clone(),
        gateway_workload: GATEWAY.into(),
        audience: "urn:test:target".into(),
        scope: "target:update".into(),
        max_expires_at: h.call.grant.expires_at,
    };
    assert!(
        h.verifier()
            .verify(
                value["access_token"].as_str().unwrap(),
                &binding,
                kedgeflow::clock::SystemClock.now_ms()
            )
            .is_ok()
    );
    let retained = permits(&h).await;
    assert_eq!(retained.len(), 1);
    for actor in [new_actor, old_actor] {
        fields
            .iter_mut()
            .find(|(name, _)| name == "actor_token")
            .unwrap()
            .1 = actor.into();
        assert!(
            !client
                .post(&h.url)
                .form(&fields)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(permits(&h).await, retained);
    }
    h.held().await;
    let report = json!({"status":"passed_identity_lifecycle","spire_issuer_rollover":true,
        "old_kid":old_kid,"new_kid":new_kid,"unchanged_subject_token":true,"unchanged_delegation":true,
        "pre_retirement_actor_pins":true,"mint_permits":1,"permit_unchanged_on_replay":true,
        "hot_reload_pid_unchanged":true,"final_epoch":5,"final_floor":5,"original_attempt":h.call.attempt_id,
        "jwt_cases":["actual_new_kid_key","unpublished_new_key_refused","overlap_both_actors_valid",
            "same_original_subject_and_delegation","old_actor_still_valid_under_original_trust","retired_actor_refused",
            "live_pair_rollback_refused","missing_higher_publication_refused","higher_head_remembered",
            "invalid_publication_no_fallback","startup_stale_pair_floor_refused","restart_retirement_persists",
            "fresh_actor_original_claim_one_mint","both_actor_replays_preserve_permit"],"tls_cases":tls_cases,
        "broker_binary_sha256":hex::encode(sha2::Sha256::digest(std::fs::read(env!("CARGO_BIN_EXE_kf-broker")).unwrap())),
        "scope":"actual SPIRE JWT/X509 authority APIs and native mTLS; generated publisher/head/floor, grant/service PKI and loopback etcd; no target dispatch or independent production custody"});
    std::fs::write(
        output.join("identity-lifecycle.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "SPIRE rollover PASS: actual JWT/X509 authorities, seven native mTLS probes, current-key original claim redeemed once after restart"
    );
}
