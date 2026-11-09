use kedgeflow::terraform_plan::{Manifest, validate_inspection};
use serde_json::{Value, json};
use std::path::Path;

fn fixture() -> (Manifest, Value, Value, Value) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/terraform-plan");
    let load =
        |name| serde_json::from_slice::<Value>(&std::fs::read(root.join(name)).unwrap()).unwrap();
    (
        Manifest::decode(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap(),
        load("configuration.json"),
        load("state.json"),
        load("inspection.json"),
    )
}
fn valid(m: &Manifest, c: &Value, s: &Value, v: &Value) -> bool {
    validate_inspection(m, c, s, &serde_json::to_vec(v).unwrap()).is_ok()
}
// Keep views consistent so effect negatives cannot pass only because the test
// accidentally left a redundant view stale.
fn correlate(s: &mut Value, v: &mut Value) {
    v["prior_state"]["values"]["root_module"]["resources"][0]["values"] =
        v["resource_changes"][0]["change"]["before"].clone();
    v["planned_values"]["root_module"]["resources"][0]["values"] =
        v["resource_changes"][0]["change"]["after"].clone();
    s["resources"][0]["instances"][0]["attributes"] =
        v["resource_changes"][0]["change"]["before"].clone();
}

#[test]
fn real_provider_plan_yields_candidate_binding_without_execution_authority() {
    let (m, c, s, v) = fixture();
    let result = validate_inspection(&m, &c, &s, &serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(result.status, "inspection_passed");
    assert_eq!(result.inputs, m.files);
    assert_eq!(result.state_lineage, s["lineage"].as_str().unwrap());
    assert_eq!(result.state_serial, s["serial"].as_u64().unwrap());
    assert_eq!(result.guard_level, "Level_C");
    assert!(!result.execution_enabled);
    let summary = serde_json::to_string(&result).unwrap();
    assert!(!summary.contains("fixture-readonly-token"));
    assert!(!summary.contains("BEGIN CERTIFICATE"));
    assert!(valid(&m, &c, &s, &v));
}

#[test]
fn incomplete_errored_and_unsupported_inspections_refuse() {
    let (m, c, s, v) = fixture();
    for (field, value) in [
        ("applyable", json!(false)),
        ("complete", json!(false)),
        ("errored", json!(true)),
        ("terraform_version", json!("1.18.0")),
        ("format_version", json!("2.0")),
        ("action_invocations", json!([])),
    ] {
        let mut bad = v.clone();
        bad[field] = value;
        assert!(!valid(&m, &c, &s, &bad), "{field}");
    }
    for field in [
        "resource_drift",
        "deferred_changes",
        "output_changes",
        "variables",
        "checks",
    ] {
        let mut bad = v.clone();
        bad[field] = json!([{"unexpected":true}]);
        assert!(!valid(&m, &c, &s, &bad), "{field}");
    }
}

#[test]
fn only_one_existing_configmap_update_is_supported() {
    let (m, c, s, v) = fixture();
    for actions in [
        json!(["create"]),
        json!(["delete"]),
        json!(["delete", "create"]),
        json!(["no-op"]),
    ] {
        let mut bad = v.clone();
        bad["resource_changes"][0]["change"]["actions"] = actions;
        assert!(!valid(&m, &c, &s, &bad));
    }
    for field in ["previous_address", "deposed", "index"] {
        let mut bad = v.clone();
        bad["resource_changes"][0][field] = json!("extra");
        assert!(!valid(&m, &c, &s, &bad), "{field}");
    }
    for field in ["importing", "generated_config"] {
        let mut bad = v.clone();
        bad["resource_changes"][0]["change"][field] = json!({});
        assert!(!valid(&m, &c, &s, &bad), "{field}");
    }
    let mut bad = v.clone();
    let extra = bad["resource_changes"][0].clone();
    bad["resource_changes"].as_array_mut().unwrap().push(extra);
    assert!(!valid(&m, &c, &s, &bad));
    let mut bad = v.clone();
    bad["resource_changes"][0]["provider_name"] = json!("unapproved/provider");
    assert!(!valid(&m, &c, &s, &bad));
}

#[test]
fn consistent_views_still_refuse_additional_or_substituted_effects() {
    let (m, c, s, v) = fixture();
    for pointer in [
        "/data/fixed",
        "/binary_data/extra",
        "/metadata/0/labels/extra",
        "/metadata/0/annotations/extra",
        "/metadata/0/name",
        "/metadata/0/namespace",
        "/metadata/0/uid",
        "/id",
    ] {
        let mut state = s.clone();
        let mut bad = v.clone();
        match pointer {
            "/binary_data/extra" => {
                bad["resource_changes"][0]["change"]["after"]["binary_data"]["extra"] =
                    json!("eA==")
            }
            "/metadata/0/labels/extra" => {
                bad["resource_changes"][0]["change"]["after"]["metadata"][0]["labels"]["extra"] =
                    json!("forbidden")
            }
            "/metadata/0/annotations/extra" => {
                bad["resource_changes"][0]["change"]["after"]["metadata"][0]["annotations"]["extra"] =
                    json!("forbidden")
            }
            _ => {
                *bad["resource_changes"][0]["change"]["after"]
                    .pointer_mut(pointer)
                    .unwrap() = json!("forbidden")
            }
        }
        correlate(&mut state, &mut bad);
        assert!(!valid(&m, &c, &state, &bad), "{pointer}");
    }
    let mut state = s;
    let mut bad = v;
    bad["resource_changes"][0]["change"]["before"]["id"] = json!("other/target");
    bad["resource_changes"][0]["change"]["after"]["id"] = json!("other/target");
    correlate(&mut state, &mut bad);
    assert!(!valid(&m, &c, &state, &bad));
}

#[test]
fn only_computed_metadata_may_be_unknown() {
    let (m, c, s, v) = fixture();
    for value in [
        json!({"metadata":[{"uid":true}]}),
        json!({"metadata":[{"annotations":true}]}),
        json!({"data":true}),
        json!({"id":true}),
        json!({"metadata":true}),
        json!(true),
    ] {
        let mut bad = v.clone();
        bad["resource_changes"][0]["change"]["after_unknown"] = value;
        assert!(!valid(&m, &c, &s, &bad));
    }
    let mut computed = v;
    computed["resource_changes"][0]["change"]["after_unknown"] =
        json!({"metadata":[{"resource_version":true,"generation":true}]});
    computed["resource_changes"][0]["change"]["after"]["metadata"][0]
        .as_object_mut()
        .unwrap()
        .remove("resource_version");
    computed["resource_changes"][0]["change"]["after"]["metadata"][0]
        .as_object_mut()
        .unwrap()
        .remove("generation");
    let mut state = s;
    correlate(&mut state, &mut computed);
    assert!(valid(&m, &c, &state, &computed));
}

#[test]
fn provider_hooks_modules_and_unfrozen_configuration_refuse() {
    let (m, c, s, v) = fixture();
    for field in ["exec", "config_path", "insecure", "proxy_url"] {
        let mut config = c.clone();
        config["provider"]["kubernetes"][field] = json!("ambient");
        assert!(!valid(&m, &config, &s, &v), "{field}");
    }
    for field in ["module", "variable", "output", "import"] {
        let mut config = c.clone();
        config[field] = json!({});
        assert!(!valid(&m, &config, &s, &v), "{field}");
    }
    let mut config = c.clone();
    config["resource"]["kubernetes_config_map_v1"]["target"]["provisioner"] =
        json!({"local-exec":{"command":"bad"}});
    assert!(!valid(&m, &config, &s, &v));
    let mut config = c;
    config["resource"]["kubernetes_config_map_v1"]["target"]["data"]["fixed"] =
        json!("${file(\"secret\")}");
    assert!(!valid(&m, &config, &s, &v));
    let (m, c, s, mut bad) = fixture();
    bad["configuration"]["provider_config"]["kubernetes"]["expressions"]["exec"] =
        json!({"constant_value":"bad"});
    assert!(!valid(&m, &c, &s, &bad));
    let (m, c, s, mut bad) = fixture();
    bad["configuration"]["root_module"]["module_calls"] = json!({"hidden":{}});
    assert!(!valid(&m, &c, &s, &bad));
}

#[test]
fn stale_state_and_cross_view_substitution_refuse() {
    let (m, c, s, v) = fixture();
    for field in ["uid", "resource_version", "name", "namespace"] {
        let mut manifest = m.clone();
        match field {
            "uid" => manifest.target.uid = "other".into(),
            "resource_version" => manifest.target.resource_version = "other".into(),
            "name" => manifest.target.name = "other".into(),
            _ => manifest.target.namespace = "other".into(),
        }
        assert!(!valid(&manifest, &c, &s, &v), "{field}");
    }
    for pointer in ["/version", "/lineage", "/serial"] {
        let mut state = s.clone();
        *state.pointer_mut(pointer).unwrap() = json!(null);
        assert!(!valid(&m, &c, &state, &v), "{pointer}");
    }
    let mut state = s.clone();
    state["resources"][0]["instances"][0]["attributes"]["data"]["fixed"] = json!("stale");
    assert!(!valid(&m, &c, &state, &v));
    let mut bad = v;
    bad["planned_values"]["root_module"]["resources"][0]["values"]["data"]["fixed"] =
        json!("substituted");
    assert!(!valid(&m, &c, &s, &bad));
}

#[test]
fn embedded_configuration_must_match_the_protected_source() {
    let (m, c, s, v) = fixture();
    let mut config = c.clone();
    config["resource"]["kubernetes_config_map_v1"]["target"]["data"]["fixed"] =
        json!("different-source");
    assert!(!valid(&m, &config, &s, &v));
    let mut bad = v.clone();
    bad["configuration"]["root_module"]["resources"][0]["expressions"]["data"]["constant_value"]
        ["fixed"] = json!("different-plan");
    assert!(!valid(&m, &c, &s, &bad));
    let mut bad = v;
    bad["configuration"]["provider_config"]["kubernetes"]["expressions"]["host"]["constant_value"] =
        json!("https://different.test");
    assert!(!valid(&m, &c, &s, &bad));
}

#[test]
fn manifest_and_inspection_are_closed_bounded_strict_json() {
    let (m, c, s, v) = fixture();
    let mut manifest = serde_json::to_value(&m).unwrap();
    manifest["apply"] = json!(true);
    assert!(Manifest::decode(&serde_json::to_vec(&manifest).unwrap()).is_err());
    for key in ["../plan.bin", "environment", "credentials"] {
        let mut manifest = serde_json::to_value(&m).unwrap();
        manifest["files"][key] = json!("a".repeat(64));
        assert!(Manifest::decode(&serde_json::to_vec(&manifest).unwrap()).is_err());
    }
    let raw = serde_json::to_string(&v).unwrap();
    let duplicate = raw.replacen('{', "{\"complete\":true,", 1);
    assert!(validate_inspection(&m, &c, &s, duplicate.as_bytes()).is_err());
    assert!(validate_inspection(&m, &c, &s, &vec![b' '; (2 << 20) + 1]).is_err());
    let mut manifest = m;
    manifest.backend = "remote".into();
    assert!(!valid(&manifest, &c, &s, &v));
}

#[test]
fn execution_profile_requires_explicit_backend_and_credential_free_configuration() {
    use kedgeflow::terraform_plan::EXECUTION_PROFILE;
    let (mut m, mut c, s, mut v) = fixture();
    let mut old = serde_json::to_value(&m).unwrap();
    old["backend_state_path"] = Value::Null;
    assert!(Manifest::decode(&serde_json::to_vec(&old).unwrap()).is_err());
    m.profile = EXECUTION_PROFILE.into();
    m.backend_state_path = Some("/protected/backend/terraform.tfstate".into());
    m.files.insert("backend.json".into(), "a".repeat(64));
    c["terraform"]["backend"] = json!({"local":{"path":m.backend_state_path}});
    c["provider"]["kubernetes"]
        .as_object_mut()
        .unwrap()
        .remove("token");
    v["configuration"]["provider_config"]["kubernetes"]["expressions"]
        .as_object_mut()
        .unwrap()
        .remove("token");
    assert!(valid(&m, &c, &s, &v));
    let encoded = serde_json::to_vec(&m).unwrap();
    assert!(Manifest::decode(&encoded).is_ok());
    let mut bad = c.clone();
    bad["provider"]["kubernetes"]["token"] = json!("embedded-token");
    assert!(!valid(&m, &bad, &s, &v));
    for path in [
        "relative/terraform.tfstate",
        "/protected/../terraform.tfstate",
        "/protected/other",
    ] {
        let mut bad = m.clone();
        bad.backend_state_path = Some(path.into());
        assert!(Manifest::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    m.files.remove("backend.json");
    assert!(Manifest::decode(&serde_json::to_vec(&m).unwrap()).is_err());
}

#[test]
fn terraform_named_action_requires_exact_adapter_schema_and_parameters() {
    use kedgeflow::{contracts::Resource, terraform_apply as apply};
    let manifest = "a".repeat(64);
    let effect = "b".repeat(64);
    let r = Resource {
        id: format!("terraform:{manifest}"),
        incarnation: "target-uid".into(),
    };
    let schema = apply::parameter_schema(&manifest, &effect, &r.id).unwrap();
    assert!(apply::validate_schema("1.0", &schema).is_ok());
    let p =
        json!({"node":r.id,"expected_version":1,"manifest_digest":manifest,"effect_digest":effect});
    assert!(apply::bind("1.0", &p, &r, "expected_version").is_ok());
    for key in ["command", "arguments", "credential", "kf_fence"] {
        let mut bad = p.clone();
        bad[key] = json!("extra");
        assert!(apply::bind("1.0", &bad, &r, "expected_version").is_err());
    }
    let mut bad = schema;
    bad["additionalProperties"] = json!(true);
    assert!(apply::validate_schema("1.0", &bad).is_err());
    assert!(apply::validate_adapter("1.0", &apply::adapter_contract(), None).is_ok());
    let mut bad = apply::adapter_contract();
    bad["level"] = json!("Level_A");
    assert!(apply::validate_adapter("1.0", &bad, None).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn protected_inspector_refuses_swapped_or_public_inputs_before_tool_spawn() {
    use kedgeflow::{
        file_custody::{Material, Root},
        terraform_plan::inspect,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let (mut m, _, _, _) = fixture();
    for name in m.files.clone().keys() {
        fs::write(root.join(name), b"not a tool").unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        m.files
            .insert(name.clone(), hex::encode(Sha256::digest(b"not a tool")));
    }
    m.files.insert("plan.bin".into(), "a".repeat(64));
    let manifest = root.join("manifest.json");
    fs::write(&manifest, serde_json::to_vec(&m).unwrap()).unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let error = inspect(&root, &manifest).await.unwrap_err().to_string();
    assert!(error.contains("input digest mismatch"), "{error}");
    fs::set_permissions(
        root.join("terraform.bin"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        inspect(&root, &manifest)
            .await
            .unwrap_err()
            .to_string()
            .contains("custody rejected")
    );
    fs::set_permissions(
        root.join("terraform.bin"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::remove_file(root.join("terraform.bin")).unwrap();
    symlink(root.join("kubernetes.bin"), root.join("terraform.bin")).unwrap();
    assert!(
        inspect(&root, &manifest)
            .await
            .unwrap_err()
            .to_string()
            .contains("custody rejected")
    );
    let reader = Root::open(&root).unwrap();
    let large = root.join("large.bin");
    fs::write(&large, vec![0u8; 3 << 20]).unwrap();
    fs::set_permissions(&large, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(reader.read(&large, Material::Secret, 3 << 20).is_err());
    assert_eq!(
        reader.read_snapshot(&large, 3 << 20).unwrap().len(),
        3 << 20
    );
    assert!(reader.read_snapshot(&large, (128 << 20) + 1).is_err());
}
