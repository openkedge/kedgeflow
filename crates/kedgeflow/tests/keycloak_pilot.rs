//! The pilot opt-in must not broaden the original subject-token profile.
#[path = "support/exchange_identity.rs"]
mod fixture;
use fixture::{Fixture, NOW};
use kedgeflow::{
    broker_authorization::ExchangeIdentityProvider,
    exchange_identity::PinnedExchangeIdentityProvider,
};
use serde_json::json;

#[test]
fn shipping_loaders_require_a_complete_explicit_profile() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (file, kind) in [
        ("gateway-postgres.example.json", 0),
        ("control.example.json", 1),
        ("broker.example.json", 2),
        ("broker-refresh.example.json", 2),
    ] {
        let original: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("config").join(file)).unwrap())
                .unwrap();
        let decode = |v: &serde_json::Value| {
            let raw = serde_json::to_vec(v).unwrap();
            match kind {
                0 => kedgeflow::config::Config::decode(&raw).map(|_| ()),
                1 => kedgeflow::control_config::ControlConfig::decode(&raw).map(|_| ()),
                _ => kedgeflow::broker_config::BrokerConfig::decode(&raw).map(|_| ()),
            }
        };
        assert!(decode(&original).is_ok(), "{file}");
        let mut selected = original.clone();
        selected["identity_profile"] = json!({"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,
                                         "client_id":"kf-pilot-agent"});
        assert!(decode(&selected).is_ok());
        for invalid in [
            serde_json::Value::Null,
            json!({}),
            json!({"profile":"unknown","client_id":"x"}),
            json!({"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,"client_id":""}),
            json!({"profile":kedgeflow::auth::KEYCLOAK_PILOT_PROFILE,"client_id":"x","extra":true}),
        ] {
            selected["identity_profile"] = invalid;
            assert!(decode(&selected).is_err(), "{file}");
        }
    }
}

#[tokio::test]
async fn explicit_profile_preserves_signature_registration_and_closed_claims() {
    let f = Fixture::new();
    let (_, actor) = f.tokens();
    let mut claims = f.subject_claims();
    claims["typ"] = json!("DPoP");
    claims["azp"] = json!("pilot-client");
    claims["jti"] = json!("keycloak-original");
    claims["cnf"]["kc-jkt-type"] = json!("DPoP");
    let header = json!({"alg":"EdDSA","typ":"JWT","kid":"subject-1"});
    let token = f.subject_token(header.clone(), claims.clone());
    let provider = || {
        PinnedExchangeIdentityProvider::new(f.snapshot.clone(), 1)
            .unwrap()
            .with_keycloak_pilot("pilot-client")
            .unwrap()
    };
    assert!(provider().verify(&token, &actor, NOW).await.is_ok());
    assert!(f.provider().verify(&token, &actor, NOW).await.is_err());
    for changed in [
        json!({"alg":"EdDSA","typ":"JWT","kid":"subject-1","jwk":null}),
        json!({"alg":"EdDSA","typ":"JWT","kid":null}),
        json!({"alg":"EdDSA","typ":"JWT"}),
        json!({"alg":"EdDSA","typ":"JWT","kid":"subject-1","extra":true}),
    ] {
        let signed = f.subject_token(changed, claims.clone());
        assert!(provider().verify(&signed, &actor, NOW).await.is_err());
    }
    for field in ["typ", "azp", "jti", "scope", "cnf", "aud", "extra"] {
        let mut changed = claims.clone();
        match field {
            "typ" => changed[field] = json!("Bearer"),
            "azp" => changed[field] = json!("other-client"),
            "jti" => changed[field] = json!(""),
            "scope" => changed[field] = json!("admin"),
            "cnf" => changed[field]["kc-jkt-type"] = json!("refresh-token"),
            "aud" => changed[field] = json!([fixture::AUDIENCE]),
            _ => changed[field] = json!(true),
        }
        let signed = f.subject_token(header.clone(), changed);
        assert!(
            provider().verify(&signed, &actor, NOW).await.is_err(),
            "{field}"
        );
    }
    assert!(
        provider()
            .verify(&token, &actor, NOW + 120001)
            .await
            .is_err()
    );
    assert!(
        PinnedExchangeIdentityProvider::new(f.snapshot.clone(), 1)
            .unwrap()
            .with_keycloak_pilot("")
            .is_err()
    );
    assert!(provider().verify(&f.tokens().0, &actor, NOW).await.is_err());
}
