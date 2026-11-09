use kedgeflow::terraform_pair::{Manifest, validate_inspection};
use serde_json::{Value, json};
use std::path::Path;

fn fixture() -> (Manifest, Value, Value, Value) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/terraform-pair-plan");
    let load = |name| serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap();
    (
        Manifest::decode(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap(),
        load("configuration.json"),
        load("state.json"),
        load("inspection.json"),
    )
}
fn valid(m: &Manifest, c: &Value, s: &Value, p: &Value) -> bool {
    validate_inspection(m, c, s, &serde_json::to_vec(p).unwrap()).is_ok()
}
#[test]
fn real_pair_plan_retains_order_and_two_candidate_effects_without_authority() {
    let (m, c, s, p) = fixture();
    let r = validate_inspection(&m, &c, &s, &serde_json::to_vec(&p).unwrap()).unwrap();
    assert_eq!(r.order, ["first", "second"]);
    assert_eq!(r.members.len(), 2);
    assert_ne!(r.members[0].effect_digest, r.members[1].effect_digest);
    assert_eq!(r.guard_level, "Level_C");
    assert!(!r.execution_enabled);
    let summary = serde_json::to_string(&r).unwrap();
    assert!(!summary.contains("BEGIN CERTIFICATE"));
    assert!(!summary.contains("token"));
    assert!(kedgeflow::terraform_plan::Manifest::decode(&serde_json::to_vec(&m).unwrap()).is_err());
}
#[test]
fn pair_manifest_refuses_aliasing_reordering_extra_fields_and_profile_substitution() {
    let (m, _, _, _) = fixture();
    let base = serde_json::to_value(&m).unwrap();
    let mut bads = Vec::new();
    let mut v = base.clone();
    v["members"][1]["target"] = v["members"][0]["target"].clone();
    bads.push(v);
    for field in ["cluster_uid", "namespace"] {
        let mut v = base.clone();
        v["members"][1]["target"][field] = json!("different");
        bads.push(v);
    }
    let mut v = base.clone();
    v["members"].as_array_mut().unwrap().swap(0, 1);
    bads.push(v);
    let mut v = base.clone();
    v["members"].as_array_mut().unwrap().pop();
    bads.push(v);
    let mut v = base.clone();
    v["execution_enabled"] = json!(true);
    bads.push(v);
    let mut v = base.clone();
    v["profile"] = json!(kedgeflow::terraform_plan::EXECUTION_PROFILE);
    bads.push(v);
    for v in bads {
        assert!(Manifest::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    let raw = serde_json::to_string(&m).unwrap();
    assert!(
        Manifest::decode(format!("{{\"profile\":\"duplicate\",{}", &raw[1..]).as_bytes()).is_err()
    );
}
#[test]
fn every_plan_and_state_view_requires_the_exact_two_members() {
    let (m, c, s, p) = fixture();
    for pointer in [
        "/resource_changes",
        "/prior_state/values/root_module/resources",
        "/planned_values/root_module/resources",
        "/configuration/root_module/resources",
    ] {
        for mode in 0..4 {
            let mut bad = p.clone();
            let rows = bad.pointer_mut(pointer).unwrap().as_array_mut().unwrap();
            match mode {
                0 => {
                    rows.pop();
                }
                1 => {
                    rows.push(rows[0].clone());
                }
                2 => rows.swap(0, 1),
                _ => rows[1] = rows[0].clone(),
            }
            assert!(!valid(&m, &c, &s, &bad), "{pointer} {mode}");
        }
    }
    let mut bad = s.clone();
    bad["resources"].as_array_mut().unwrap().swap(0, 1);
    assert!(!valid(&m, &c, &bad, &p));
}
#[test]
fn consistent_views_cannot_expand_either_annotation_effect() {
    let (m, c, s, p) = fixture();
    for i in 0..2 {
        for field in ["data", "uid", "unknown", "replacement"] {
            let mut bad = p.clone();
            match field {
                "data" => {
                    bad["resource_changes"][i]["change"]["after"]["data"]["fixed"] =
                        json!("forbidden")
                }
                "uid" => {
                    bad["resource_changes"][i]["change"]["after"]["metadata"][0]["uid"] =
                        json!("forbidden")
                }
                "unknown" => {
                    bad["resource_changes"][i]["change"]["after_unknown"] =
                        json!({"metadata":[{"uid":true}]})
                }
                _ => bad["resource_changes"][i]["change"]["actions"] = json!(["delete", "create"]),
            }
            bad["planned_values"]["root_module"]["resources"][i]["values"] =
                bad["resource_changes"][i]["change"]["after"].clone();
            assert!(!valid(&m, &c, &s, &bad), "{i} {field}");
        }
    }
}
#[test]
fn dependency_provider_and_global_inputs_remain_closed() {
    let (m, c, s, p) = fixture();
    for dependency in [
        json!([]),
        json!(["external.resource"]),
        json!(["kubernetes_config_map_v1.second"]),
    ] {
        let mut config = c.clone();
        let mut plan = p.clone();
        config["resource"]["kubernetes_config_map_v1"]["second"]["depends_on"] = dependency.clone();
        plan["configuration"]["root_module"]["resources"][1]["depends_on"] = dependency;
        assert!(!valid(&m, &config, &s, &plan));
    }
    let mut bad = c.clone();
    bad["provider"]["kubernetes"]["exec"] = json!({"command":"false"});
    assert!(!valid(&m, &bad, &s, &p));
    let mut bad = p.clone();
    bad["configuration"]["root_module"]["resources"][1]["provisioners"] = json!([{}]);
    assert!(!valid(&m, &c, &s, &bad));
    for field in [
        "variables",
        "checks",
        "resource_drift",
        "deferred_changes",
        "output_changes",
    ] {
        let mut bad = p.clone();
        bad[field] = json!([{"extra":true}]);
        assert!(!valid(&m, &c, &s, &bad));
    }
    let mut bad = p.clone();
    bad["relevant_attributes"] = json!([{"resource":"external.resource","attribute":["id"]}]);
    assert!(!valid(&m, &c, &s, &bad));
}
#[test]
fn aggregate_digest_binds_the_second_member_and_its_exact_revision() {
    let (mut m, mut c, s, mut p) = fixture();
    let before = validate_inspection(&m, &c, &s, &serde_json::to_vec(&p).unwrap()).unwrap();
    m.members[1].after_revision = "different-approved-revision".into();
    let revision = json!(m.members[1].after_revision);
    c["resource"]["kubernetes_config_map_v1"]["second"]["metadata"]["annotations"]["kedgeflow.dev/revision"] =
        revision.clone();
    p["configuration"]["root_module"]["resources"][1]["expressions"]["metadata"][0]["annotations"]
        ["constant_value"]["kedgeflow.dev/revision"] = revision.clone();
    p["resource_changes"][1]["change"]["after"]["metadata"][0]["annotations"]["kedgeflow.dev/revision"] =
        revision;
    p["planned_values"]["root_module"]["resources"][1]["values"] =
        p["resource_changes"][1]["change"]["after"].clone();
    let after = validate_inspection(&m, &c, &s, &serde_json::to_vec(&p).unwrap()).unwrap();
    assert_eq!(
        before.members[0].effect_digest,
        after.members[0].effect_digest
    );
    assert_ne!(
        before.members[1].effect_digest,
        after.members[1].effect_digest
    );
    assert_ne!(before.effect_digest, after.effect_digest);
    assert_ne!(before.manifest_digest, after.manifest_digest);
}

#[cfg(unix)]
#[tokio::test]
async fn protected_pair_inspector_refuses_hooks_and_swapped_inputs_before_spawn() {
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::PermissionsExt};
    let (mut m, mut config, state, _) = fixture();
    config["provider"]["kubernetes"]["exec"] = json!({"command":"false"});
    let directory = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in m.files.clone().keys() {
        let bytes=match name.as_str() {
            "configuration.json"=>serde_json::to_vec(&config).unwrap(),
            "state.json"=>serde_json::to_vec(&state).unwrap(),
            "backend.json"=>serde_json::to_vec(&json!({"backend":{"type":"local","config":{"path":m.backend_state_path,"workspace_dir":null}}})).unwrap(),
            _=>b"not an executable or a plan".to_vec(),
        };
        fs::write(root.join(name), &bytes).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        m.files
            .insert(name.clone(), hex::encode(Sha256::digest(&bytes)));
    }
    let manifest = root.join("manifest.json");
    fs::write(&manifest, serde_json::to_vec(&m).unwrap()).unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let error = kedgeflow::terraform_pair::inspect(&root, &manifest)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("provider credential source"), "{error}");
    m.files.insert("plan.bin".into(), "a".repeat(64));
    fs::write(&manifest, serde_json::to_vec(&m).unwrap()).unwrap();
    let error = kedgeflow::terraform_pair::inspect(&root, &manifest)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("input digest mismatch"), "{error}");
    fs::set_permissions(
        root.join("terraform.bin"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        kedgeflow::terraform_pair::inspect(&root, &manifest)
            .await
            .unwrap_err()
            .to_string()
            .contains("custody rejected")
    );
}
