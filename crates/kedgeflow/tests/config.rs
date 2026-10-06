use base64::{Engine as _, engine::general_purpose::STANDARD};
use kedgeflow::config::Config;
use serde_json::{Value, json};
mod support;
fn configuration() -> Value {
    let mut value: Value =
        serde_json::from_str(include_str!("../../../config/gateway.example.json")).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
    value["grant_public_key_base64"] = json!(STANDARD.encode(key.to_bytes()));
    value["oidc_public_key_base64"] = value["grant_public_key_base64"].clone();
    value["tools"][0]["action"]["digest"] = json!("a".repeat(64));
    value
}
#[test]
fn template_requires_real_keys_and_registered_digest() {
    let raw = include_bytes!("../../../config/gateway.example.json");
    assert!(Config::decode(raw).unwrap().validate().is_err());
    assert!(
        Config::decode(&serde_json::to_vec(&configuration()).unwrap())
            .unwrap()
            .validate()
            .is_ok()
    );
}
#[test]
fn closed_configuration_refuses_duplicate_unknown_case_and_profile_downgrade() {
    for variant in [
        "unknown",
        "case",
        "insecure-etcd",
        "duplicate-tool",
        "resolver-half-config",
        "unsupported-guard",
        "wrong-idempotency-key",
    ] {
        let mut value = configuration();
        match variant {
            "unknown" => value["agent_selected_target"] = json!("https://other.test"),
            "case" => {
                let issuer = value
                    .as_object_mut()
                    .unwrap()
                    .remove("oidc_issuer")
                    .unwrap();
                value["OIDC_ISSUER"] = issuer;
            }
            "insecure-etcd" => value["etcd_endpoints"] = json!(["http://127.0.0.1:2379"]),
            "duplicate-tool" => {
                let tool = value["tools"][0].clone();
                value["tools"].as_array_mut().unwrap().push(tool);
            }
            "resolver-half-config" => {
                value["grant_resolver_endpoint"] = json!("https://resolver.test/resolve")
            }
            "unsupported-guard" => {
                value["tools"][0]["adapter_contract"]["guard_primitive"] = json!("SQL_CAS")
            }
            _ => {
                value["tools"][0]["adapter_contract"]["idempotency"]["parameter"] =
                    json!("never-injected")
            }
        }
        assert!(
            Config::decode(&serde_json::to_vec(&value).unwrap())
                .and_then(|c| c.validate())
                .is_err(),
            "{variant}"
        );
    }
    assert!(Config::decode(br#"{"listen":"127.0.0.1:8443","listen":"0.0.0.0:8443"}"#).is_err());
}

#[test]
fn native_cli_checks_local_trust_material_without_network_or_public_issuance() {
    let p = support::pki();
    let directory = tempfile::tempdir().unwrap();
    let ca = directory.path().join("ca.pem");
    let certificate = directory.path().join("gateway.pem");
    let key = directory.path().join("gateway-key.pem");
    let token = directory.path().join("etcd-token");
    std::fs::write(&ca, p.ca).unwrap();
    std::fs::write(&certificate, p.server).unwrap();
    std::fs::write(&key, p.server_key).unwrap();
    std::fs::write(&token, "namespace-scoped-test-token").unwrap();
    let mut value = configuration();
    value["certificate"] = json!(certificate);
    value["private_key"] = json!(key);
    value["etcd_token_file"] = json!(token);
    for field in ["workload_ca", "etcd_ca", "broker_ca", "target_ca"] {
        value[field] = json!(ca);
    }
    let config = directory.path().join("gateway.json");
    std::fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kf-proxy"))
        .arg("--config")
        .arg(&config)
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("were not probed"));
}
