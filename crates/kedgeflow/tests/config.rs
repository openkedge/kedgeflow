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
    value["enforcement"]["installation_keys"] = json!({"key-12": STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes())});
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
fn valid_terraform_descriptor_cannot_enable_generic_gateway_discovery() {
    let mut value = configuration();
    value["tools"][0]["action"]["id"] = json!(kedgeflow::terraform_apply::ACTION);
    value["tools"][0]["action"]["version"] = json!("1.0");
    value["tools"][0]["adapter_contract"] = kedgeflow::terraform_apply::adapter_contract();
    value["tools"][0]["fence_parameter"] = json!("");
    let tool: kedgeflow::gateway::ToolDescriptor =
        serde_json::from_value(value["tools"][0].clone()).unwrap();
    tool.validate().unwrap();
    let error = Config::decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .validate()
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Terraform requires the native runner")
    );
}

fn terraform_configuration() -> Value {
    use kedgeflow::{terraform_adapter, terraform_apply as apply};
    let mut value = configuration();
    let t = &mut value["tools"][0];
    t["action"]["id"] = json!(apply::ACTION);
    t["action"]["version"] = json!("1.0");
    t["adapter_contract"] = apply::adapter_contract();
    t["fence_parameter"] = json!("");
    t["required_scope"] = json!("terraform:apply");
    let tool = t.clone();
    let schema = apply::parameter_schema(
        &"a".repeat(64),
        &"b".repeat(64),
        tool["resource"]["id"].as_str().unwrap(),
    )
    .unwrap();
    value["target_url"] = json!("https://terraform-runner.test/apply");
    value["target_audience"] = value["target_url"].clone();
    value["target_scope"] = json!("terraform:apply");
    value["terraform_adapter"] = json!({"profile":terraform_adapter::PROFILE,"token_issuer":"https://broker.test/exchange","target_keys":{"target":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[29;32]).verifying_key().as_bytes())},
        "pins":{"profile":apply::PROFILE,"material_root":"/protected/plan","manifest_file":"/protected/plan/manifest.json","backend_root":"/protected/backend","secret_root":"/protected/secrets","writer_token_file":"/protected/secrets/writer.token","observer_token_file":"/protected/secrets/observer.token","manifest_digest":"a".repeat(64),"effect_digest":"b".repeat(64),"inspection_sha256":"c".repeat(64),"tool":tool,"parameter_schema":schema,"gateway_workload":"spiffe://test/gateway","target_audience":value["target_audience"],"target_scope":"terraform:apply"}});
    value
}
#[test]
fn terraform_gateway_requires_exact_explicit_protected_selection() {
    let valid = terraform_configuration();
    Config::decode(&serde_json::to_vec(&valid).unwrap())
        .unwrap()
        .validate()
        .unwrap();
    for case in [
        "null",
        "profile",
        "native-profile",
        "schema",
        "tool",
        "read",
        "scope",
        "audience",
        "unmanaged",
        "missing-token",
        "mixed",
        "key-role",
        "wrong-action",
    ] {
        let mut bad = valid.clone();
        match case {
            "null" => bad["terraform_adapter"] = Value::Null,
            "profile" => bad["terraform_adapter"]["profile"] = json!("other"),
            "native-profile" => bad["terraform_adapter"]["pins"]["profile"] = json!("other"),
            "schema" => {
                bad["terraform_adapter"]["pins"]["parameter_schema"]["additionalProperties"] =
                    json!(true)
            }
            "tool" => bad["terraform_adapter"]["pins"]["tool"]["name"] = json!("other"),
            "read" => bad["read_token_file"] = json!("/protected/read.token"),
            "scope" => bad["target_scope"] = json!("admin"),
            "audience" => bad["target_url"] = json!("https://other.test/apply"),
            "unmanaged" => bad["require_control"] = json!(false),
            "missing-token" => bad["etcd_token_file"] = json!(""),
            "mixed" => bad["tools"]
                .as_array_mut()
                .unwrap()
                .push(configuration()["tools"][0].clone()),
            "key-role" => {
                bad["terraform_adapter"]["target_keys"] =
                    json!({"target":bad["grant_public_key_base64"]})
            }
            _ => bad["tools"][0]["action"]["id"] = json!("other"),
        }
        assert!(
            Config::decode(&serde_json::to_vec(&bad).unwrap())
                .and_then(|c| c.validate())
                .is_err(),
            "{case}"
        );
    }
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
        "unmanaged-enrollment",
        "missing-managed-token",
        "status-mutation-scope",
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
            "unmanaged-enrollment" => value["require_control"] = json!(false),
            "missing-managed-token" => value["etcd_token_file"] = json!(""),
            "status-mutation-scope" => {
                value["tools"][0]["status_scope"] = value["tools"][0]["required_scope"].clone()
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
    let directory =
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let ca = directory.path().join("ca.pem");
    let certificate = directory.path().join("gateway.pem");
    let key = directory.path().join("gateway-key.pem");
    let token = directory.path().join("etcd-token");
    std::fs::write(&ca, p.ca).unwrap();
    std::fs::write(&certificate, p.server).unwrap();
    std::fs::write(&key, p.server_key).unwrap();
    std::fs::write(&token, "namespace-scoped-test-token").unwrap();
    let ack_key = directory.path().join("ack-key");
    std::fs::write(&ack_key, STANDARD.encode([9; 32])).unwrap();
    let mut value = configuration();
    value["certificate"] = json!(certificate);
    value["private_key"] = json!(key);
    value["etcd_token_file"] = json!(token);
    value["enforcement"]["control_ca"] = json!(ca);
    value["enforcement"]["acknowledgement_key_file"] = json!(ack_key);
    for field in ["workload_ca", "etcd_ca", "broker_ca", "target_ca"] {
        value[field] = json!(ca);
    }
    value["shared_auth"] = json!({
        "capacity":16,
        "registrations":[{"subject":{"iss":value["oidc_issuer"],"sub":"software-check"},
        "workload_id":"spiffe://test/agent","allowed_scopes":["resource:mutate"]}]
    });
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
    // The shipping gateway checks the opt-in SQL client with the same local TLS
    // material without reaching the target, database, broker or ledger.
    let sql = sql_configuration();
    for field in [
        "tools",
        "postgres_adapter",
        "target_audience",
        "target_scope",
    ] {
        value[field] = sql[field].clone();
    }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actor = directory.path().join("actor.jwt");
        std::fs::write(&actor, "operator-provisioned-assertion").unwrap();
        value["actor_token_file"] = json!(actor);
        // Cover optional resolver, witness and acknowledgement paths as well.
        value["grant_resolver_endpoint"] = json!("https://localhost:9000/resolve");
        value["grant_resolver_ca"] = json!(ca);
        value["restore_gate"] = json!({"endpoint":"https://localhost:9001","prefix":"/witness",
            "ca":ca,"certificate":certificate,"private_key":key,"token_file":token});
        std::fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            std::fs::set_permissions(
                entry.unwrap().path(),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let protected = || {
            std::process::Command::new(env!("CARGO_BIN_EXE_kf-proxy"))
                .arg("--config")
                .arg(&config)
                .arg("--custody-root")
                .arg(directory.path())
                .arg("--require-managed")
                .arg("--check")
                .output()
                .unwrap()
        };
        let output = protected();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for name in [
            "gateway.json",
            "gateway.pem",
            "gateway-key.pem",
            "ca.pem",
            "etcd-token",
            "ack-key",
            "actor.jwt",
        ] {
            let path = directory.path().join(name);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            assert!(!protected().status.success(), "unsafe gateway role {name}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // --check must not ignore a live assertion path outside custody.
        value["actor_token_file"] = json!(directory.path().join("../actor.jwt"));
        std::fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!protected().status.success());
    }
}

fn sql_configuration() -> Value {
    let mut value = configuration();
    let example: Value = serde_json::from_str(include_str!(
        "../../../config/gateway-postgres.example.json"
    ))
    .unwrap();
    value["tools"] = example["tools"].clone();
    value["postgres_adapter"] = example["postgres_adapter"].clone();
    value["tools"][0]["action"]["digest"] = json!("a".repeat(64));
    value["postgres_adapter"]["registration"]["action"]["digest"] = json!("a".repeat(64));
    value["postgres_adapter"]["target_keys"] = json!({"target":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[29;32]).verifying_key().to_bytes())});
    value["target_audience"] = value["postgres_adapter"]["registration"]["target_audience"].clone();
    value["target_scope"] = value["postgres_adapter"]["registration"]["target_scope"].clone();
    value
}
#[test]
fn explicit_sql_adapter_refuses_mock_fallback_mixed_tools_and_registration_substitution() {
    let valid = sql_configuration();
    assert!(
        Config::decode(&serde_json::to_vec(&valid).unwrap())
            .unwrap()
            .validate()
            .is_ok()
    );
    for variant in [
        "missing-adapter",
        "profile",
        "version",
        "resource",
        "contract",
        "audience",
        "scope",
        "keys",
        "read",
        "mixed",
        "version-parameter",
    ] {
        let mut value = valid.clone();
        match variant {
            "missing-adapter" => {
                value.as_object_mut().unwrap().remove("postgres_adapter");
            }
            "profile" => value["postgres_adapter"]["profile"] = json!("other"),
            "version" => value["tools"][0]["action"]["version"] = json!("2"),
            "resource" => {
                value["postgres_adapter"]["registration"]["resource"]["incarnation"] =
                    json!("other")
            }
            "contract" => {
                value["postgres_adapter"]["registration"]["adapter_contract"]["commit_point"] =
                    json!("other")
            }
            "audience" => value["target_audience"] = json!("https://other.test"),
            "scope" => value["target_scope"] = json!("admin"),
            "keys" => {
                value["postgres_adapter"]["target_keys"] =
                    json!({"target":value["grant_public_key_base64"]})
            }
            "read" => value["tools"][0]["read_only"] = json!(true),
            "mixed" => value["tools"]
                .as_array_mut()
                .unwrap()
                .push(configuration()["tools"][0].clone()),
            _ => value["tools"][0]["version_parameter"] = json!("version"),
        }
        assert!(
            Config::decode(&serde_json::to_vec(&value).unwrap())
                .and_then(|c| c.validate())
                .is_err(),
            "{variant}"
        );
    }
}

#[test]
fn pair_gateway_selection_refuses_generic_and_crossed_single_profiles() {
    use kedgeflow::{terraform_adapter, terraform_pair_apply as pair};
    let mut v = terraform_configuration();
    let node = format!("terraform-pair:{}", "a".repeat(64));
    v["tools"][0]["action"]["id"] = json!(pair::ACTION);
    v["tools"][0]["adapter_contract"] = pair::adapter_contract();
    v["tools"][0]["resource"] = json!({"id":node,"incarnation":"d".repeat(64)});
    v["tools"][0]["required_scope"] = json!(pair::SCOPE);
    v["target_scope"] = json!(pair::SCOPE);
    v["terraform_adapter"]["profile"] = json!(terraform_adapter::PAIR_PROFILE);
    v["terraform_adapter"]["pins"]["profile"] = json!(pair::PROFILE);
    v["terraform_adapter"]["pins"]["target_scope"] = json!(pair::SCOPE);
    v["terraform_adapter"]["pins"]["tool"] = v["tools"][0].clone();
    v["terraform_adapter"]["pins"]["parameter_schema"] =
        pair::parameter_schema(&"a".repeat(64), &"b".repeat(64), &node).unwrap();
    Config::decode(&serde_json::to_vec(&v).unwrap())
        .unwrap()
        .validate()
        .unwrap();
    for case in [
        "generic",
        "single-gateway",
        "single-runner",
        "single-contract",
        "single-scope",
        "single-resource",
        "incarnation",
        "mixed",
    ] {
        let mut bad = v.clone();
        match case {
            "generic" => bad["terraform_adapter"] = Value::Null,
            "single-gateway" => {
                bad["terraform_adapter"]["profile"] = json!(terraform_adapter::PROFILE)
            }
            "single-runner" => {
                bad["terraform_adapter"]["pins"]["profile"] =
                    json!(kedgeflow::terraform_apply::PROFILE)
            }
            "single-contract" => {
                bad["terraform_adapter"]["pins"]["tool"]["adapter_contract"] =
                    kedgeflow::terraform_apply::adapter_contract()
            }
            "single-scope" => {
                bad["terraform_adapter"]["pins"]["target_scope"] = json!("terraform:apply")
            }
            "single-resource" => {
                bad["terraform_adapter"]["pins"]["tool"]["resource"]["id"] = json!("terraform:plan")
            }
            "incarnation" => {
                bad["terraform_adapter"]["pins"]["tool"]["resource"]["incarnation"] =
                    json!("not-a-digest")
            }
            _ => bad["tools"]
                .as_array_mut()
                .unwrap()
                .push(terraform_configuration()["tools"][0].clone()),
        }
        assert!(
            Config::decode(&serde_json::to_vec(&bad).unwrap())
                .and_then(|c| c.validate())
                .is_err(),
            "{case}"
        );
    }
}
