//! Local protected operational preflight; no deployed account or authority claim.
#![cfg(unix)]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn public(seed: u8) -> String {
    STANDARD.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
}
fn example(name: &str) -> Value {
    serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../config")
                .join(format!("{name}.example.json")),
        )
        .unwrap(),
    )
    .unwrap()
}
fn fields(value: &Value, prefix: Vec<String>, output: &mut Vec<Vec<String>>) {
    if let Some(object) = value.as_object() {
        for (name, value) in object {
            let mut path = prefix.clone();
            path.push(name.clone());
            if value.is_object() {
                fields(value, path, output);
            } else if value.as_str().is_some_and(|s| !s.is_empty())
                && [
                    "certificate",
                    "private_key",
                    "workload_ca",
                    "etcd_ca",
                    "etcd_certificate",
                    "etcd_private_key",
                    "etcd_token_file",
                    "query_ca",
                    "query_certificate",
                    "query_private_key",
                    "query_token_file",
                    "receipt_signing_key_file",
                    "acknowledgement_signing_key_file",
                    "collector_ca",
                    "token_file",
                    "dpop_signing_key_file",
                    "ca",
                ]
                .contains(&name.as_str())
            {
                output.push(path);
            }
        }
    }
}
fn at<'a>(mut value: &'a mut Value, path: &[String]) -> &'a mut Value {
    for component in path {
        value = &mut value[component];
    }
    value
}

#[test]
fn shipping_operational_modes_confine_every_reached_material_path() {
    let temp = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let root = temp.path();
    let pki = support::dual_pki_for_workloads(&["spiffe://test/outcome"])
        .pop()
        .unwrap();
    for (name, data) in [
        ("ca", pki.ca),
        ("cert", pki.client),
        ("key", pki.client_key),
        ("etcd-token", "etcd-role".into()),
        ("query-token", "query-role".into()),
        ("reporter-token", "reporter".into()),
        ("receipt", STANDARD.encode([14; 32])),
        ("ack", STANDARD.encode([15; 32])),
        ("proof", STANDARD.encode([8; 32])),
    ] {
        let path = root.join(name);
        fs::write(&path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    let witness = json!({"endpoint":"https://127.0.0.1:9001","prefix":"/witness","ca":root.join("ca"),"certificate":root.join("cert"),"private_key":root.join("key"),"token_file":root.join("etcd-token")});
    let mut recovery = example("recovery");
    for field in ["etcd_ca", "query_ca"] {
        recovery[field] = json!(root.join("ca"));
    }
    for field in ["etcd_certificate", "query_certificate"] {
        recovery[field] = json!(root.join("cert"));
    }
    for field in ["etcd_private_key", "query_private_key"] {
        recovery[field] = json!(root.join("key"));
    }
    recovery["etcd_token_file"] = json!(root.join("etcd-token"));
    recovery["query_token_file"] = json!(root.join("query-token"));
    recovery["grant_keys"] = json!({"grant":public(6)});
    recovery["receipt_key_id"] = json!("outcome");
    recovery["receipt_signing_key_file"] = json!(root.join("receipt"));
    recovery["restore_gate"] = witness.clone();
    let mut collector = example("outcomes");
    for (field, file) in [
        ("certificate", "cert"),
        ("private_key", "key"),
        ("workload_ca", "ca"),
        ("etcd_ca", "ca"),
        ("etcd_certificate", "cert"),
        ("etcd_private_key", "key"),
        ("etcd_token_file", "etcd-token"),
        ("acknowledgement_signing_key_file", "ack"),
    ] {
        collector[field] = json!(root.join(file));
    }
    collector["oidc_public_key_base64"] = json!(public(7));
    collector["grant_keys"] = recovery["grant_keys"].clone();
    collector["outcome_keys"] = json!({"outcome":public(14)});
    collector["restore_gate"] = witness.clone();
    collector["shared_auth"] = json!({"capacity":16,"registrations":[{"subject":collector["reporter_subject"],"workload_id":collector["source_id"],"allowed_scopes":[collector["report_scope"]]}]});
    let mut governance = example("governance");
    for (field, file) in [
        ("certificate", "cert"),
        ("private_key", "key"),
        ("workload_ca", "ca"),
        ("etcd_ca", "ca"),
        ("etcd_certificate", "cert"),
        ("etcd_private_key", "key"),
        ("etcd_token_file", "etcd-token"),
    ] {
        governance["control"][field] = json!(root.join(file));
    }
    // This service has public enrollment pins, never another role's signing seeds.
    governance["control"]["admission_signing_key_file"] = json!("");
    governance["control"]["issuer_signing_key_file"] = json!("");
    governance["control"]["restore_gate"] = witness.clone();
    governance["control"]["shared_auth"] = json!({"capacity":16,"registrations":[{"subject":governance["control"]["subjects"][0],"workload_id":governance["control"]["workload_id"],"allowed_scopes":["kf.control"]}]});
    let mut supervisor = example("supervision");
    supervisor["recovery"] = recovery.clone();
    for (field, file) in [
        ("collector_ca", "ca"),
        ("certificate", "cert"),
        ("private_key", "key"),
        ("token_file", "reporter-token"),
        ("dpop_signing_key_file", "proof"),
    ] {
        supervisor["delivery"][field] = json!(root.join(file));
    }
    supervisor["delivery"]["outcome_keys"] = json!({"outcome":public(14)});
    supervisor["delivery"]["acknowledgement_keys"] = json!({"ack":public(15)});
    let operator = json!({"etcd_endpoint":"https://127.0.0.1:9000","etcd_prefix":"/authority","etcd_ca":root.join("ca"),"etcd_certificate":root.join("cert"),"etcd_private_key":root.join("key"),"etcd_token_file":root.join("etcd-token"),"restore_gate":witness});
    let cases = [
        (env!("CARGO_BIN_EXE_kf-recover"), recovery),
        (env!("CARGO_BIN_EXE_kf-outcomes"), collector),
        (env!("CARGO_BIN_EXE_kf-governance"), governance),
        (env!("CARGO_BIN_EXE_kf-supervise"), supervisor),
        (env!("CARGO_BIN_EXE_kf-restore"), operator),
    ];
    for (binary, config) in cases {
        let path = root.join("config.json");
        let run = |value: &Value| {
            fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            let mut command = std::process::Command::new(binary);
            if let Some(url) = value.get("external_url").and_then(Value::as_str) {
                let origin = url::Url::parse(url).unwrap().origin().ascii_serialization();
                command.args([
                    "--operations-url",
                    &format!("{origin}/ops/ready"),
                    "--operations-workload",
                    "spiffe://test/monitor",
                ]);
            }
            command
                .arg("--config")
                .arg(&path)
                .arg("--custody-root")
                .arg(root)
                .args(["--require-managed", "--check"])
                .output()
                .unwrap()
        };
        let positive = run(&config);
        assert!(
            positive.status.success(),
            "{binary}: {}",
            String::from_utf8_lossy(&positive.stderr)
        );
        let mut paths = Vec::new();
        fields(&config, Vec::new(), &mut paths);
        assert!(paths.len() >= 8);
        for field in paths {
            let mut bad = config.clone();
            let value = at(&mut bad, &field);
            let outside = tempfile::NamedTempFile::new().unwrap();
            fs::copy(value.as_str().unwrap(), outside.path()).unwrap();
            *value = json!(outside.path());
            assert!(
                !run(&bad).status.success(),
                "{binary} loaded escaped {field:?}"
            );
        }
        assert!(run(&config).status.success());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            !run(&config).status.success(),
            "{binary} accepted unsafe config"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
