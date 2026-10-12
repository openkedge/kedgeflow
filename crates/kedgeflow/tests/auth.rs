use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use kedgeflow::{
    auth::{Authenticator, DualAuthenticator, WorkloadIdentity},
    contracts::{canonical, digest},
    tls::{pinned_http_client_pem, server_config_pem},
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

const NOW: i64 = 1_800_000_000;
const ISSUER: &str = "https://identity.test";
const ENDPOINT: &str = "https://gateway.test/mcp";

fn workload(uris: &[&str]) -> WorkloadIdentity {
    let cert = workload_cert(uris);
    WorkloadIdentity::from_verified_cert_der(cert.der()).unwrap()
}

fn workload_cert(uris: &[&str]) -> rcgen::Certificate {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = uris
        .iter()
        .map(|uri| SanType::URI((*uri).try_into().unwrap()))
        .collect();
    params.self_signed(&KeyPair::generate().unwrap()).unwrap()
}

fn jwt(header: &Value, claims: &Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    )
}

fn vectors(variant: &str, jti: &str, proof_iat: i64) -> (HeaderMap, String, String, Value) {
    let issuer_key = SigningKey::from_bytes(&[3; 32]);
    let proof_key = SigningKey::from_bytes(&[7; 32]);
    let other_key = SigningKey::from_bytes(&[9; 32]);
    let mut jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(proof_key.verifying_key().to_bytes())});
    let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()));
    let mut access = json!({
        "iss":ISSUER,"sub":"user","aud":ENDPOINT,"exp":NOW + 300,"iat":NOW,
        "scope":"mutate read","cnf":{"jkt":thumbprint}
    });
    let mut access_header = json!({"alg":"EdDSA","typ":"at+jwt"});
    match variant {
        "expired_access_token" => access["exp"] = json!(NOW),
        "wrong_audience" => access["aud"] = json!("https://other.test"),
        "wrong_issuer" => access["iss"] = json!("https://untrusted.test"),
        "missing_subject" => access["sub"] = json!(""),
        "future_token" => access["iat"] = json!(NOW + 6),
        "unsafe_expiry" => access["exp"] = json!(9_007_199_254_741_i64),
        "missing_scope" => access["scope"] = json!(""),
        "duplicate_scope" => access["scope"] = json!("mutate mutate"),
        "wrong_confirmation_key" => access["cnf"]["jkt"] = json!("different"),
        "oidc_id_token" => access_header["typ"] = json!("JWT"),
        "access_embedded_key" => access_header["jwk"] = jwk.clone(),
        "access_null_key" => access_header["jwk"] = Value::Null,
        "unknown_access_claim" => access["admin"] = json!(true),
        "unknown_access_header" => access_header["trusted"] = json!(true),
        _ => (),
    }
    let token = jwt(
        &access_header,
        &access,
        if variant == "wrong_user_signature" {
            &other_key
        } else {
            &issuer_key
        },
    );
    let mut proof = json!({"jti":jti,"htm":"POST","htu":ENDPOINT,"iat":proof_iat,
        "ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))});
    let mut proof_header = json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":jwk});
    match variant {
        "wrong_method" => proof["htm"] = json!("GET"),
        "wrong_uri" => proof["htu"] = json!("https://other.test/mcp"),
        "wrong_access_token_hash" => proof["ath"] = json!("bad"),
        "empty_jti" => proof["jti"] = json!(""),
        "large_jti" => proof["jti"] = json!("x".repeat(513)),
        "unknown_proof_claim" => proof["admin"] = json!(true),
        "wrong_proof_type" => proof_header["typ"] = json!("JWT"),
        "private_jwk" => {
            jwk = proof_header["jwk"].clone();
            jwk["d"] = json!("private");
            proof_header["jwk"] = jwk;
        }
        "wrong_curve" => proof_header["jwk"]["crv"] = json!("P-256"),
        _ => (),
    }
    let proof = jwt(
        &proof_header,
        &proof,
        if variant == "wrong_dpop_signature" {
            &other_key
        } else {
            &proof_key
        },
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
    );
    headers.insert("dpop", HeaderValue::from_str(&proof).unwrap());
    if variant == "bearer_scheme" {
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
    }
    if variant == "duplicate_authorization" {
        headers.append(
            "authorization",
            HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
        );
    }
    if variant == "duplicate_proof" {
        headers.append("dpop", HeaderValue::from_str(&proof).unwrap());
    }
    if variant == "missing_authorization" {
        headers.remove("authorization");
    }
    if variant == "missing_proof" {
        headers.remove("dpop");
    }
    (headers, token, thumbprint, access)
}

fn verifier() -> DualAuthenticator {
    DualAuthenticator::new(
        ISSUER,
        ENDPOINT,
        ENDPOINT,
        SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
    )
    .unwrap()
}

#[test]
fn authenticates_exact_dual_identity_and_canonical_delegation() {
    let (headers, token, thumbprint, access) = vectors("valid", "one-proof", NOW);
    let workload = workload(&["spiffe://test/agent"]);
    let id = verifier()
        .authenticate_at(&headers, &workload, NOW)
        .unwrap();
    assert_eq!(id.subject.iss, ISSUER);
    assert_eq!(id.subject.sub, "user");
    assert_eq!(id.workload_id, "spiffe://test/agent");
    assert_eq!(id.access_token, token);
    assert_eq!(id.dpop_jkt, thumbprint);
    assert_eq!(
        id.scopes,
        BTreeSet::from(["mutate".to_owned(), "read".to_owned()])
    );
    let delegation = json!({
        "access_token_digest":hex::encode(Sha256::digest(token.as_bytes())),
        "dpop_jkt":thumbprint,"authorization_server":ISSUER,"token_audience":ENDPOINT,
        "scopes":["mutate","read"],"expires_at":access["exp"].as_i64().unwrap()*1000
    });
    assert_eq!(
        id.delegation_digest,
        digest("delegation", &delegation).unwrap()
    );
}

#[test]
fn rejects_identity_signature_scope_and_proof_substitutions() {
    let workload = workload(&["spiffe://test/agent"]);
    for variant in [
        "expired_access_token",
        "wrong_audience",
        "wrong_issuer",
        "missing_subject",
        "future_token",
        "unsafe_expiry",
        "missing_scope",
        "duplicate_scope",
        "wrong_confirmation_key",
        "oidc_id_token",
        "access_embedded_key",
        "access_null_key",
        "unknown_access_claim",
        "unknown_access_header",
        "wrong_user_signature",
        "wrong_method",
        "wrong_uri",
        "wrong_access_token_hash",
        "empty_jti",
        "large_jti",
        "unknown_proof_claim",
        "wrong_proof_type",
        "private_jwk",
        "wrong_curve",
        "wrong_dpop_signature",
        "bearer_scheme",
        "duplicate_authorization",
        "duplicate_proof",
        "missing_authorization",
        "missing_proof",
    ] {
        let (headers, _, _, _) = vectors(variant, variant, NOW);
        assert!(
            verifier()
                .authenticate_at(&headers, &workload, NOW)
                .is_err(),
            "{variant}"
        );
    }
    for proof_iat in [NOW - 61, NOW + 6] {
        let (headers, _, _, _) = vectors("valid", "bad-proof-time", proof_iat);
        assert!(
            verifier()
                .authenticate_at(&headers, &workload, NOW)
                .is_err()
        );
    }
}

#[test]
fn rejects_jwt_duplicate_keys_before_value_parsing() {
    let (mut headers, token, _, _) = vectors("valid", "duplicate", NOW);
    let parts: Vec<_> = token.split('.').collect();
    let body = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    let duplicate = format!("{{\"sub\":\"forged\",{}", body.trim_start_matches('{'));
    let input = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(duplicate));
    let key = SigningKey::from_bytes(&[3; 32]);
    let duplicated = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("DPoP {duplicated}")).unwrap(),
    );
    assert!(
        verifier()
            .authenticate_at(&headers, &workload(&["spiffe://test/agent"]), NOW)
            .is_err()
    );
}

#[test]
fn workload_requires_exactly_one_valid_spiffe_uri() {
    for uris in [
        vec![],
        vec!["https://identity.test/agent"],
        vec!["spiffe://test/a", "spiffe://test/b"],
        vec!["spiffe://test:8443/agent"],
        vec!["spiffe://test/../agent"],
        vec!["spiffe://test/agent?x=1"],
        vec!["spiffe://test/agent#fragment"],
        vec!["spiffe://test/a%2fb"],
        vec!["spiffe://test/"],
        vec!["spiffe://test/a//b"],
        vec!["SPIFFE://test/agent"],
        vec!["spiffe://TEST/agent"],
    ] {
        let cert = workload_cert(&uris);
        assert!(
            WorkloadIdentity::from_verified_cert_der(cert.der()).is_err(),
            "{uris:?}"
        );
    }
    for uri in [
        "spiffe://test/agent",
        "spiffe://test",
        "spiffe://test/ns/service-1",
    ] {
        assert_eq!(workload(&[uri]).as_str(), uri);
    }
    let cert = workload_cert(&["spiffe://test/agent"]);
    let mut trailing = cert.der().to_vec();
    trailing.push(0);
    assert!(WorkloadIdentity::from_verified_cert_der(&trailing).is_err());
    assert!(WorkloadIdentity::from_verified_cert_der(b"not a certificate").is_err());
}

#[test]
fn replay_consumption_is_atomic_and_shared_by_clones() {
    let auth = Arc::new(verifier());
    let (headers, _, _, _) = vectors("valid", "shared-proof", NOW);
    let headers = Arc::new(headers);
    let workload = Arc::new(workload(&["spiffe://test/agent"]));
    let results = (0..32)
        .map(|_| {
            let a = auth.clone();
            let h = headers.clone();
            let w = workload.clone();
            std::thread::spawn(move || a.authenticate_at(&h, &w, NOW).is_ok())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .into_iter()
            .map(|r| r.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
}

#[test]
fn bounded_replay_cache_fails_closed_and_covers_future_skew_boundary() {
    let auth = DualAuthenticator::with_replay_capacity(
        ISSUER,
        ENDPOINT,
        ENDPOINT,
        SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
        1,
    )
    .unwrap();
    let workload = workload(&["spiffe://test/agent"]);
    let (first, _, _, _) = vectors("valid", "first", NOW + 5);
    auth.authenticate_at(&first, &workload, NOW).unwrap();
    let (second, _, _, _) = vectors("valid", "second", NOW);
    assert!(
        auth.authenticate_at(&second, &workload, NOW).is_err(),
        "live proof was evicted"
    );
    // At +65 seconds a proof issued at +5 is still valid (age 60); keep it consumed.
    assert!(
        auth.authenticate_at(&first, &workload, NOW + 65).is_err(),
        "proof replay at TTL edge"
    );
    let (fresh, _, _, _) = vectors("valid", "fresh", NOW + 66);
    assert!(auth.authenticate_at(&fresh, &workload, NOW + 66).is_ok());
}

#[tokio::test]
async fn production_trait_uses_current_time_and_never_caller_identity_headers() {
    let now = chrono::Utc::now().timestamp();
    let issuer = SigningKey::from_bytes(&[3; 32]);
    let proof_key = SigningKey::from_bytes(&[7; 32]);
    let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(proof_key.verifying_key().to_bytes())});
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()));
    let token = jwt(
        &json!({"alg":"EdDSA","typ":"at+jwt"}),
        &json!({
            "iss":ISSUER,"sub":"user","aud":ENDPOINT,"iat":now,"exp":now+120,"scope":"read","cnf":{"jkt":jkt}
        }),
        &issuer,
    );
    let proof = jwt(
        &json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":jwk}),
        &json!({
            "jti":"production","htm":"POST","htu":ENDPOINT,"iat":now,
            "ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
        }),
        &proof_key,
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("DPoP {token}")).unwrap(),
    );
    headers.insert("dpop", HeaderValue::from_str(&proof).unwrap());
    headers.insert(
        "x-workload-id",
        HeaderValue::from_static("spiffe://attacker/agent"),
    );
    headers.insert("x-user-subject", HeaderValue::from_static("administrator"));
    let id = verifier()
        .authenticate(&headers, &workload(&["spiffe://test/agent"]))
        .await
        .unwrap();
    assert_eq!(id.workload_id, "spiffe://test/agent");
    assert_eq!(id.subject.sub, "user");
}

struct Pki {
    ca: String,
    server: String,
    server_key: String,
    client: String,
    client_key: String,
}
fn new_pki() -> Pki {
    let mut ca_params = CertificateParams::new(vec!["test CA".to_owned()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let server_key = KeyPair::generate().unwrap();
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params.signed_by(&server_key, &issuer).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.subject_alt_names = vec![SanType::URI("spiffe://test/agent".try_into().unwrap())];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client = client_params.signed_by(&client_key, &issuer).unwrap();
    Pki {
        ca: ca_cert.pem(),
        server: server.pem(),
        server_key: server_key.serialize_pem(),
        client: client.pem(),
        client_key: client_key.serialize_pem(),
    }
}

#[tokio::test]
async fn tls_requires_a_real_verified_workload_client_certificate() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pki = new_pki();
    let config = server_config_pem(
        pki.server.as_bytes(),
        pki.server_key.as_bytes(),
        pki.ca.as_bytes(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        let peer = tls.get_ref().1.peer_certificates().unwrap();
        let workload = WorkloadIdentity::from_verified_cert_der(peer[0].as_ref()).unwrap();
        assert_eq!(workload.as_str(), "spiffe://test/agent");
        let mut request = [0_u8; 2048];
        let n = tls.read(&mut request).await.unwrap();
        assert!(n > 0);
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
    });
    let client = pinned_http_client_pem(
        pki.ca.as_bytes(),
        pki.client.as_bytes(),
        pki.client_key.as_bytes(),
        Duration::from_secs(3),
    )
    .unwrap();
    assert_eq!(
        client
            .post(format!("https://{addr}/mcp"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    task.await.unwrap();

    // The same verified server rejects a client that sends no certificate.
    let pki = new_pki();
    let config = server_config_pem(
        pki.server.as_bytes(),
        pki.server_key.as_bytes(),
        pki.ca.as_bytes(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        assert!(
            tokio_rustls::TlsAcceptor::from(config)
                .accept(socket)
                .await
                .is_err()
        );
    });
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca.as_bytes()).unwrap())
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .no_proxy()
        .http1_only()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    assert!(
        client
            .post(format!("https://{addr}/mcp"))
            .send()
            .await
            .is_err()
    );
    task.await.unwrap();
}

#[test]
fn tls_helpers_reject_absent_ambiguous_and_unbounded_material() {
    let pki = new_pki();
    assert!(server_config_pem(pki.server.as_bytes(), pki.server_key.as_bytes(), b"").is_err());
    let doubled = format!("{}\n{}", pki.server_key, pki.server_key);
    assert!(
        server_config_pem(pki.server.as_bytes(), doubled.as_bytes(), pki.ca.as_bytes()).is_err()
    );
    assert!(
        pinned_http_client_pem(
            pki.ca.as_bytes(),
            pki.client.as_bytes(),
            pki.client_key.as_bytes(),
            Duration::ZERO
        )
        .is_err()
    );
    assert!(
        pinned_http_client_pem(
            pki.ca.as_bytes(),
            pki.client.as_bytes(),
            b"not a private key",
            Duration::from_secs(1)
        )
        .is_err()
    );
}

mod support;

#[tokio::test]
async fn pinned_client_rejects_wrong_roots_and_untrusted_workload_chain() {
    let trusted = support::pki();
    let other = support::pki();
    let server = support::serve_tls(
        &trusted,
        axum::Router::new().route("/mcp", axum::routing::post(|| async { "ok" })),
    )
    .await;
    let wrong_root = kedgeflow::tls::pinned_client_pem(
        other.ca.as_bytes(),
        trusted.client.as_bytes(),
        trusted.client_key.as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(
        wrong_root
            .client()
            .post(format!("{}/mcp", server.url))
            .send()
            .await
            .is_err()
    );
    let wrong_client = kedgeflow::tls::pinned_client_pem(
        trusted.ca.as_bytes(),
        other.client.as_bytes(),
        other.client_key.as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(
        wrong_client
            .client()
            .post(format!("{}/mcp", server.url))
            .send()
            .await
            .is_err()
    );
    let correct = kedgeflow::tls::pinned_client_pem(
        trusted.ca.as_bytes(),
        trusted.client.as_bytes(),
        trusted.client_key.as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(
        correct
            .client()
            .post(format!("{}/mcp", server.url))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
}

#[tokio::test]
async fn pinned_client_refuses_redirects_and_bounds_the_response_deadline() {
    let pki = support::pki();
    let redirected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let target_count = redirected.clone();
    let second = support::serve_tls(
        &pki,
        axum::Router::new().route(
            "/target",
            axum::routing::post(move || {
                let count = target_count.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    "target"
                }
            }),
        ),
    )
    .await;
    let location = format!("{}/target", second.url);
    let first = support::serve_tls(
        &pki,
        axum::Router::new()
            .route(
                "/redirect",
                axum::routing::post(move || {
                    let location = location.clone();
                    async move {
                        (
                            axum::http::StatusCode::TEMPORARY_REDIRECT,
                            [("location", location)],
                        )
                    }
                }),
            )
            .route(
                "/slow",
                axum::routing::post(|| async {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "late"
                }),
            ),
    )
    .await;
    let client = kedgeflow::tls::pinned_client_pem(
        pki.ca.as_bytes(),
        pki.client.as_bytes(),
        pki.client_key.as_bytes(),
        Duration::from_millis(100),
    )
    .unwrap();
    let response = client
        .client()
        .post(format!("{}/redirect", first.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::TEMPORARY_REDIRECT
    );
    assert_eq!(redirected.load(std::sync::atomic::Ordering::SeqCst), 0);
    let start = std::time::Instant::now();
    assert!(
        client
            .client()
            .post(format!("{}/slow", first.url))
            .send()
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[path = "support/shared_auth.rs"]
mod shared_auth;
