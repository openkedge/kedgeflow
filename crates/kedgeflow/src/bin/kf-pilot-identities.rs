//! Explicit disposable-provider probe; production service loaders do not opt in.
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    auth::{Authenticator, DualAuthenticator, KEYCLOAK_PILOT_PROFILE, WorkloadIdentity},
    broker_authorization::ExchangeIdentityProvider,
    contracts::{Subject, strict_value},
    exchange_identity::{
        ActorKey, PROFILE, PinnedExchangeIdentityProvider, SubjectKey, TrustSnapshot,
    },
    server,
    shared_auth::SubjectWorkload,
    tls,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

const ISSUER: &str = "https://keycloak:8443/realms/kedgeflow-pilot";
const AUDIENCE: &str = "urn:kedgeflow:delegated-admission";
const ACTOR_AUDIENCE: &str = "https://broker.pilot.kedgeflow.test/token";
const CLIENT: &str = "kf-pilot-agent";
const WORKLOAD: &str = "spiffe://pilot.kedgeflow.test/gateway";
type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    about = "Verify actual Keycloak/SPIRE pilot credentials without issuing execution authority"
)]
struct Arguments {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    subject_token: String,
    actor_token: String,
    keycloak_jwks: Value,
    dpop_seed: String,
}

fn require(condition: bool, message: &str) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

async fn authenticate(
    State(auth): State<Arc<DualAuthenticator>>,
    Extension(workload): Extension<WorkloadIdentity>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    let identity = auth
        .authenticate(&headers, &workload)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(json!({"delegation_digest":identity.delegation_digest,
                   "workload":identity.workload_id,"subject":identity.subject})))
}

fn proof(token: &str, url: &str, key: &SigningKey, jti: &str) -> String {
    let header = json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":{
        "kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())}});
    let claims = json!({"jti":jti,"htm":"POST","htu":url,
        "iat":chrono::Utc::now().timestamp(),"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))});
    let raw = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    format!(
        "{raw}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(raw.as_bytes()).to_bytes())
    )
}

async fn run(args: Arguments) -> AnyResult<Value> {
    let raw = std::fs::read(args.input.join("packet.json"))?;
    require(raw.len() <= 1 << 20, "pilot packet exceeds bound")?;
    let packet: Packet = serde_json::from_value(strict_value(&raw)?)?;
    let bundle = strict_value(&std::fs::read(args.bundle)?)?;
    let now = chrono::Utc::now().timestamp_millis();
    let keys = packet.keycloak_jwks["keys"]
        .as_array()
        .ok_or("missing enrolled subject keys")?;
    let mut subject_keys = Vec::new();
    for k in keys.iter().filter(|k| {
        k["alg"] == "EdDSA" && k["kty"] == "OKP" && k["crv"] == "Ed25519" && k["use"] == "sig"
    }) {
        subject_keys.push(SubjectKey {
            kid: k["kid"].as_str().ok_or("missing subject kid")?.into(),
            public_key: k["x"].as_str().ok_or("missing subject key")?.into(),
            not_before: now - 5000,
            expires_at: now + 60000,
        });
    }
    require(
        subject_keys.len() == 1,
        "pilot requires one enrolled Ed25519 subject key",
    )?;
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&subject_keys[0].public_key)?
        .try_into()
        .map_err(|_| "subject key length")?;
    let mut actor_keys = Vec::new();
    for k in bundle["keys"]
        .as_array()
        .ok_or("missing actor bundle")?
        .iter()
        .filter(|k| k["use"] == "jwt-svid" && k["kty"] == "EC" && k["crv"] == "P-256")
    {
        let mut point = vec![4];
        for field in ["x", "y"] {
            let part = URL_SAFE_NO_PAD.decode(k[field].as_str().ok_or("actor coordinate")?)?;
            require(part.len() == 32, "actor coordinate length")?;
            point.extend(part);
        }
        actor_keys.push(ActorKey {
            kid: k["kid"].as_str().ok_or("actor kid")?.into(),
            trust_domain: "pilot.kedgeflow.test".into(),
            alg: "ES256".into(),
            r#use: "jwt-svid".into(),
            public_key: URL_SAFE_NO_PAD.encode(point),
            not_before: now - 5000,
            expires_at: now + 60000,
        });
    }
    let snapshot = TrustSnapshot {
        profile: PROFILE.into(),
        epoch: 1,
        not_before: now - 5000,
        expires_at: now + 60000,
        issuer: ISSUER.into(),
        subject_audience: AUDIENCE.into(),
        actor_audience: ACTOR_AUDIENCE.into(),
        subject_keys,
        actor_keys,
        registrations: vec![SubjectWorkload {
            subject: Subject {
                iss: ISSUER.into(),
                sub: "d0b36f01-1188-4f01-907a-000000000001".into(),
            },
            workload_id: WORKLOAD.into(),
            allowed_scopes: BTreeSet::from(["resource:mutate".into(), "kf.status".into()]),
        }],
        withdrawn_subject_tokens: vec![],
    };
    let provider =
        PinnedExchangeIdentityProvider::new(snapshot.clone(), 1)?.with_keycloak_pilot(CLIENT)?;
    let identity = provider
        .verify(&packet.subject_token, &packet.actor_token, now)
        .await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("https://localhost:{}/admit", listener.local_addr()?.port());
    let auth = Arc::new(
        DualAuthenticator::new(ISSUER, AUDIENCE, &url, public)?.with_keycloak_pilot(CLIENT)?,
    );
    let tls_config = tls::server_config(
        args.input.join("loopback.pem"),
        args.input.join("loopback.key"),
        args.input.join("x509/bundle.0.pem"),
    )?;
    let task = tokio::spawn(server::serve_router(
        listener,
        tls_config,
        Router::new()
            .route("/admit", post(authenticate))
            .with_state(auth),
    ));
    let client = tls::pinned_http_client(
        args.input.join("loopback-ca.pem"),
        args.input.join("x509/svid.0.pem"),
        args.input.join("x509/svid.0.key"),
        Duration::from_secs(5),
    )?;
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&packet.dpop_seed)?
        .try_into()
        .map_err(|_| "DPoP seed length")?;
    let key = SigningKey::from_bytes(&seed);
    let send = |p: String| {
        client
            .post(&url)
            .header("authorization", format!("DPoP {}", packet.subject_token))
            .header("dpop", p)
            .send()
    };
    let first = proof(&packet.subject_token, &url, &key, "pilot-original");
    let response = send(first.clone()).await?;
    require(
        response.status() == StatusCode::OK,
        "native mTLS/Keycloak authentication refused",
    )?;
    let admitted: Value = response.json().await?;
    require(
        admitted["delegation_digest"] == identity.identity.delegation_digest,
        "admission/broker delegation mismatch",
    )?;
    require(
        admitted["workload"] == WORKLOAD && identity.identity.workload_id == WORKLOAD,
        "workload identity mismatch",
    )?;
    require(
        send(first).await?.status() == StatusCode::UNAUTHORIZED,
        "DPoP replay accepted",
    )?;
    let other = SigningKey::from_bytes(&[19; 32]);
    require(
        send(proof(&packet.subject_token, &url, &other, "wrong-key"))
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
        "substituted DPoP key accepted",
    )?;
    task.abort();
    let mut refused = vec!["dpop_replay", "dpop_key_substitution"];
    for (name, mut next, client_id) in [
        ("wrong_client", snapshot.clone(), "not-enrolled"),
        ("wrong_subject_audience", snapshot.clone(), CLIENT),
        ("wrong_actor_audience", snapshot.clone(), CLIENT),
        ("unregistered_workload", snapshot.clone(), CLIENT),
        ("withdrawn_subject", snapshot.clone(), CLIENT),
    ] {
        match name {
            "wrong_subject_audience" => next.subject_audience = "urn:wrong-audience".into(),
            "wrong_actor_audience" => next.actor_audience = "https://wrong.test/token".into(),
            "unregistered_workload" => {
                next.registrations[0].workload_id = "spiffe://pilot.kedgeflow.test/other".into()
            }
            "withdrawn_subject" => {
                next.withdrawn_subject_tokens =
                    vec![hex::encode(Sha256::digest(packet.subject_token.as_bytes()))]
            }
            _ => (),
        }
        let verifier =
            PinnedExchangeIdentityProvider::new(next, 1)?.with_keycloak_pilot(client_id)?;
        require(
            verifier
                .verify(&packet.subject_token, &packet.actor_token, now)
                .await
                .is_err(),
            "provider negative accepted",
        )?;
        refused.push(name);
    }
    require(
        PinnedExchangeIdentityProvider::new(snapshot, 1)?
            .verify(&packet.subject_token, &packet.actor_token, now)
            .await
            .is_err(),
        "legacy profile silently accepted",
    )?;
    refused.push("legacy_profile_no_fallback");
    Ok(
        json!({"profile":KEYCLOAK_PILOT_PROFILE,"status":"passed_identity_checks",
        "subject":identity.identity.subject,"workload":identity.identity.workload_id,
        "delegation_digest":identity.identity.delegation_digest,"refused":refused,
        "execution_authority_issued":false,"target_effects":0}),
    )
}

#[tokio::main]
async fn main() {
    match run(Arguments::parse()).await {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("kf-pilot-identities: {error}");
            std::process::exit(1);
        }
    }
}
