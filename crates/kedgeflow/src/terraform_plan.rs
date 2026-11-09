//! Protected, read-only saved-plan inspection. This module issues no authority
//! and deliberately offers no apply command or ResourceAdapter implementation.
use crate::{
    contracts::{digest, strict_value},
    error::{Error, Result},
    file_custody::{Material, Root},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

pub const PROFILE: &str = "KF-TERRAFORM-PLAN-0.1-draft";
pub const EXECUTION_PROFILE: &str = "KF-TERRAFORM-PLAN-0.2-draft";
pub const ANNOTATION: &str = "kedgeflow.dev/revision";
const ADDRESS: &str = "kubernetes_config_map_v1.target";
const PROVIDER: &str = "registry.terraform.io/hashicorp/kubernetes";
const FILES: [&str; 6] = [
    "terraform.bin",
    "kubernetes.bin",
    "plan.bin",
    "state.json",
    "lock.hcl",
    "configuration.json",
];
const MAX_JSON: usize = 2 << 20;
fn refuse(reason: &str) -> Error {
    Error::Refused(format!("Terraform plan: {reason}"))
}
fn require(condition: bool, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(refuse(reason))
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}
fn closed(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.keys().all(|k| keys.contains(&k.as_str())))
}
fn empty(v: Option<&Value>) -> bool {
    v.is_none_or(|v| {
        v.as_object().is_some_and(|o| o.is_empty()) || v.as_array().is_some_and(|a| a.is_empty())
    })
}
fn one(v: &Value) -> Result<&Value> {
    let a = v
        .as_array()
        .ok_or_else(|| refuse("expected one resource"))?;
    require(a.len() == 1, "expected one resource")?;
    Ok(&a[0])
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub cluster_uid: String,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub resource_version: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub profile: String,
    pub terraform_version: String,
    pub provider_version: String,
    pub platform: String,
    pub workspace_id: String,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_state_path: Option<String>,
    pub target: Target,
    pub before_revision: String,
    pub after_revision: String,
    pub files: BTreeMap<String, String>,
}
impl Manifest {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        require(raw.len() <= 64 * 1024, "manifest size")?;
        let value = strict_value(raw)?;
        require(
            value["profile"] != PROFILE || value.get("backend_state_path").is_none(),
            "v0.1 backend override",
        )?;
        let result: Self = serde_json::from_value(value).map_err(|_| refuse("manifest shape"))?;
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        require(
            (self.profile == PROFILE || self.profile == EXECUTION_PROFILE)
                && self.terraform_version == "1.17.1"
                && self.provider_version == "2.38.0",
            "unsupported version",
        )?;
        require(
            ["darwin_arm64", "darwin_amd64", "linux_arm64", "linux_amd64"]
                .contains(&self.platform.as_str()),
            "unsupported platform",
        )?;
        require(
            self.backend == "local" && identifier(&self.workspace_id),
            "workspace/backend",
        )?;
        match (&self.backend_state_path, self.profile.as_str()) {
            (None, PROFILE) => (),
            (Some(path), EXECUTION_PROFILE) => {
                let p = Path::new(path);
                require(
                    p.is_absolute()
                        && p.file_name().is_some_and(|s| s == "terraform.tfstate")
                        && p.components().all(|c| {
                            matches!(
                                c,
                                std::path::Component::RootDir | std::path::Component::Normal(_)
                            )
                        }),
                    "explicit local backend path",
                )?;
            }
            _ => return Err(refuse("backend profile binding")),
        }
        for id in [
            &self.target.cluster_uid,
            &self.target.namespace,
            &self.target.name,
            &self.target.uid,
            &self.target.resource_version,
        ] {
            require(identifier(id), "target identity")?;
        }
        let dns = |value: &str| {
            value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        };
        require(
            self.target.namespace.len() <= 63
                && !self.target.namespace.contains('.')
                && dns(&self.target.namespace)
                && dns(&self.target.name),
            "target DNS names",
        )?;
        require(
            self.before_revision != self.after_revision
                && [&self.before_revision, &self.after_revision]
                    .iter()
                    .all(|s| !s.is_empty() && s.len() <= 256),
            "revision binding",
        )?;
        require(
            self.files.len() == FILES.len() + usize::from(self.profile == EXECUTION_PROFILE)
                && (self.profile != EXECUTION_PROFILE
                    || self
                        .files
                        .get("backend.json")
                        .is_some_and(|h| crate::grant_reference::valid_reference(h)))
                && FILES.iter().all(|n| {
                    self.files.get(*n).is_some_and(|h| {
                        h.len() == 64
                            && h.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                }),
            "exact file pins",
        )
    }
}
/// Candidate evidence only. Neither the digest nor `inspection_passed` is an
/// admission certificate, a grant, current target evidence or permission to apply.
#[derive(Debug, Serialize)]
pub struct Inspection {
    pub profile: String,
    pub status: &'static str,
    pub manifest_digest: String,
    pub inspection_sha256: String,
    pub inputs: BTreeMap<String, String>,
    pub workspace_id: String,
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_state_path: Option<String>,
    pub state_lineage: String,
    pub state_serial: u64,
    pub target: Target,
    pub effect_digest: String,
    pub guard_level: &'static str,
    pub execution_enabled: bool,
}

fn configuration(m: &Manifest, value: &Value) -> Result<()> {
    fn literal(v: &Value) -> bool {
        match v {
            Value::String(s) => !s.contains("${") && !s.contains("%{"),
            Value::Array(a) => a.iter().all(literal),
            Value::Object(o) => o.values().all(literal),
            _ => true,
        }
    }
    require(literal(value), "configuration expressions")?;
    require(
        closed(value, &["terraform", "provider", "resource"])
            && value.as_object().is_some_and(|o| o.len() == 3),
        "configuration root",
    )?;
    let mut terraform = json!({"required_providers":{"kubernetes":{"source":"hashicorp/kubernetes","version":"=2.38.0"}}});
    if let Some(path) = &m.backend_state_path {
        terraform["backend"] = json!({"local":{"path":path}});
    }
    require(
        value["terraform"] == terraform,
        "provider declaration or backend override",
    )?;
    let providers = &value["provider"];
    require(
        closed(providers, &["kubernetes"]) && providers.as_object().is_some_and(|o| o.len() == 1),
        "provider configuration",
    )?;
    let p = &providers["kubernetes"];
    let provider_fields = if m.profile == EXECUTION_PROFILE {
        vec!["host", "cluster_ca_certificate"]
    } else {
        vec!["host", "cluster_ca_certificate", "token"]
    };
    require(
        closed(p, &provider_fields)
            && p.as_object()
                .is_some_and(|o| o.len() == provider_fields.len()),
        "provider credential source",
    )?;
    let url = p["host"]
        .as_str()
        .and_then(|s| reqwest::Url::parse(s).ok())
        .ok_or_else(|| refuse("provider origin"))?;
    require(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "provider origin",
    )?;
    for key in provider_fields.into_iter().filter(|s| *s != "host") {
        require(
            p[key].as_str().is_some_and(|s| !s.is_empty()),
            "provider credential source",
        )?;
    }
    let resources = &value["resource"];
    require(
        closed(resources, &["kubernetes_config_map_v1"])
            && resources.as_object().is_some_and(|o| o.len() == 1),
        "resource type",
    )?;
    let maps = &resources["kubernetes_config_map_v1"];
    require(
        closed(maps, &["target"]) && maps.as_object().is_some_and(|o| o.len() == 1),
        "resource count",
    )?;
    let map = &maps["target"];
    require(
        closed(map, &["metadata", "data", "binary_data", "immutable"]),
        "resource hooks or unsupported fields",
    )?;
    let metadata = &map["metadata"];
    require(
        closed(metadata, &["name", "namespace", "annotations", "labels"])
            && metadata["name"] == m.target.name
            && metadata["namespace"] == m.target.namespace
            && metadata["annotations"][ANNOTATION] == m.after_revision,
        "configured target/revision",
    )?;
    Ok(())
}

fn values(m: &Manifest, before: &Value, after: &Value, unknown: &Value) -> Result<()> {
    require(
        before.is_object() && after.is_object(),
        "missing resource values",
    )?;
    let b = one(&before["metadata"])?;
    let a = one(&after["metadata"])?;
    require(
        before["id"] == format!("{}/{}", m.target.namespace, m.target.name)
            && after["id"] == before["id"],
        "provider target identity",
    )?;
    require(
        b["uid"] == m.target.uid
            && b["resource_version"] == m.target.resource_version
            && b["name"] == m.target.name
            && b["namespace"] == m.target.namespace
            && a["uid"] == m.target.uid
            && a["name"] == m.target.name
            && a["namespace"] == m.target.namespace
            && b["annotations"][ANNOTATION] == m.before_revision
            && a["annotations"][ANNOTATION] == m.after_revision,
        "target state or revision",
    )?;
    // Only provider-computed generation/resource_version may become unknown.
    let mut allowed_unknown = unknown.clone();
    if let Some(meta) = allowed_unknown.get_mut("metadata") {
        let rows = meta
            .as_array_mut()
            .ok_or_else(|| refuse("unknown metadata shape"))?;
        require(rows.len() == 1, "unknown metadata count")?;
        let row = rows[0]
            .as_object_mut()
            .ok_or_else(|| refuse("unknown metadata shape"))?;
        row.remove("generation");
        row.remove("resource_version");
    }
    fn known(v: &Value) -> bool {
        match v {
            Value::Bool(false) => true,
            Value::Object(o) => o.values().all(known),
            Value::Array(a) => a.iter().all(known),
            _ => false,
        }
    }
    require(known(&allowed_unknown), "unknown authorized effect")?;
    let mut expected = before.clone();
    expected["metadata"][0]["annotations"][ANNOTATION] = json!(m.after_revision);
    let mut actual = after.clone();
    for v in [&mut expected, &mut actual] {
        let meta = v["metadata"][0]
            .as_object_mut()
            .ok_or_else(|| refuse("metadata shape"))?;
        meta.remove("generation");
        meta.remove("resource_version");
    }
    require(expected == actual, "effect exceeds one annotation")
}

/// Semantic validation for offline verification/tests. The protected `inspect`
/// entry point additionally derives these bytes from the pinned binary plan.
pub fn validate_inspection(
    m: &Manifest,
    config: &Value,
    state: &Value,
    raw: &[u8],
) -> Result<Inspection> {
    m.validate()?;
    configuration(m, config)?;
    require(raw.len() <= MAX_JSON, "inspection size")?;
    let v = strict_value(raw)?;
    require(
        v["format_version"] == "1.2" && v["terraform_version"] == m.terraform_version,
        "inspection version",
    )?;
    require(
        closed(
            &v,
            &[
                "format_version",
                "terraform_version",
                "planned_values",
                "resource_changes",
                "prior_state",
                "configuration",
                "timestamp",
                "applyable",
                "complete",
                "errored",
                "resource_drift",
                "deferred_changes",
                "output_changes",
                "relevant_attributes",
                "variables",
                "checks",
            ],
        ),
        "unsupported plan fields",
    )?;
    require(
        v["applyable"] == true && v["complete"] == true && v["errored"] == false,
        "incomplete or errored plan",
    )?;
    for key in [
        "resource_drift",
        "deferred_changes",
        "output_changes",
        "variables",
        "checks",
    ] {
        require(empty(v.get(key)), "extra effects, inputs, drift or checks")?;
    }
    let change = one(&v["resource_changes"])?;
    require(
        change["address"] == ADDRESS
            && change["mode"] == "managed"
            && change["type"] == "kubernetes_config_map_v1"
            && change["provider_name"] == PROVIDER
            && change["change"]["actions"] == json!(["update"]),
        "action is not one ConfigMap update",
    )?;
    require(
        ["previous_address", "deposed", "index"]
            .iter()
            .all(|k| change.get(k).is_none())
            && ["importing", "generated_config"]
                .iter()
                .all(|k| change["change"].get(k).is_none()),
        "move/import/replacement",
    )?;
    let before = &change["change"]["before"];
    let after = &change["change"]["after"];
    values(m, before, after, &change["change"]["after_unknown"])?;
    for (key, expected) in [("prior_state", before), ("planned_values", after)] {
        let module = if key == "prior_state" {
            &v[key]["values"]["root_module"]
        } else {
            &v[key]["root_module"]
        };
        require(empty(module.get("child_modules")), "child module")?;
        let resource = one(&module["resources"])?;
        require(
            resource["address"] == ADDRESS
                && resource["provider_name"] == PROVIDER
                && resource["mode"] == "managed"
                && resource["type"] == "kubernetes_config_map_v1"
                && resource["schema_version"] == 0
                && resource["values"] == *expected,
            "inconsistent resource view",
        )?;
    }
    let module = &v["configuration"]["root_module"];
    require(empty(module.get("module_calls")), "module calls")?;
    let configured = one(&module["resources"])?;
    require(
        configured["address"] == ADDRESS
            && configured["mode"] == "managed"
            && configured["type"] == "kubernetes_config_map_v1"
            && configured["provider_config_key"] == "kubernetes"
            && configured.get("provisioners").is_none(),
        "executable configuration",
    )?;
    let mut expected_expressions = serde_json::Map::new();
    for (key, value) in config["resource"]["kubernetes_config_map_v1"]["target"]
        .as_object()
        .unwrap()
    {
        let expression = if key == "metadata" {
            let fields: serde_json::Map<String, Value> = value
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| (name.clone(), json!({"constant_value":value})))
                .collect();
            json!([fields])
        } else {
            json!({"constant_value":value})
        };
        expected_expressions.insert(key.clone(), expression);
    }
    require(
        configured["expressions"] == Value::Object(expected_expressions),
        "embedded resource differs from protected configuration",
    )?;
    let provider = &v["configuration"]["provider_config"]["kubernetes"];
    require(
        v["configuration"]["provider_config"]
            .as_object()
            .is_some_and(|p| p.len() == 1),
        "additional provider configuration",
    )?;
    require(
        provider["full_name"] == PROVIDER && provider["version_constraint"] == "2.38.0",
        "inspection provider",
    )?;
    let expected_provider: serde_json::Map<String, Value> = config["provider"]["kubernetes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), json!({"constant_value":value})))
        .collect();
    require(
        provider["expressions"] == Value::Object(expected_provider),
        "embedded provider differs from protected configuration",
    )?;
    require(
        state["version"] == 4
            && state["terraform_version"] == m.terraform_version
            && state["lineage"].as_str().is_some_and(identifier),
        "state identity",
    )?;
    let serial = state["serial"]
        .as_u64()
        .ok_or_else(|| refuse("state serial"))?;
    require(
        serial <= 9_007_199_254_740_991 && empty(state.get("outputs")),
        "state serial or outputs",
    )?;
    let stored = one(&state["resources"])?;
    require(
        stored["mode"] == "managed"
            && stored["type"] == "kubernetes_config_map_v1"
            && stored["name"] == "target"
            && stored["provider"] == format!("provider[\"{PROVIDER}\"]")
            && stored.get("module").is_none(),
        "state resource",
    )?;
    let instance = one(&stored["instances"])?;
    require(
        instance["attributes"] == *before
            && instance["schema_version"] == 0
            && instance.get("index_key").is_none()
            && instance.get("deposed").is_none(),
        "state differs from plan baseline",
    )?;
    Ok(Inspection {
        profile: m.profile.clone(),
        status: "inspection_passed",
        manifest_digest: digest("terraform-plan-manifest", &serde_json::to_value(m)?)?,
        inspection_sha256: hash(raw),
        inputs: m.files.clone(),
        workspace_id: m.workspace_id.clone(),
        backend: m.backend.clone(),
        backend_state_path: m.backend_state_path.clone(),
        state_lineage: state["lineage"].as_str().unwrap().into(),
        state_serial: serial,
        target: m.target.clone(),
        effect_digest: digest(
            "terraform-plan-effect",
            &json!({"address":ADDRESS,"before":before,"after":after}),
        )?,
        guard_level: "Level_C",
        execution_enabled: false,
    })
}

#[cfg(unix)]
pub(crate) struct Stage(PathBuf);
#[cfg(unix)]
impl Stage {
    fn new() -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::fs::canonicalize(std::env::temp_dir())?
            .join(format!("kf-tf-inspect-{:032x}", rand::random::<u128>()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        let stage = Self(path);
        Root::open(&stage.0)?;
        Ok(stage)
    }
    fn write(&self, name: &str, bytes: &[u8], executable: bool) -> Result<()> {
        use std::{
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(bytes)?;
        if executable {
            file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    async fn command(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        self.command_with_token(arguments, None).await
    }
    pub(crate) async fn command_with_token(
        &self,
        arguments: &[&str],
        token: Option<&str>,
    ) -> Result<Vec<u8>> {
        use std::{os::unix::process::CommandExt, process::Stdio};
        use tokio::io::AsyncReadExt;
        let mut command = tokio::process::Command::new(self.0.join("terraform"));
        command
            .args(arguments)
            .current_dir(&self.0)
            .env_clear()
            .env("TF_DATA_DIR", self.0.join(".terraform"))
            .env("TF_CLI_CONFIG_FILE", self.0.join("terraform.rc"))
            .env("CHECKPOINT_DISABLE", "1")
            .env("TF_IN_AUTOMATION", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        // Terraform can create backend state and lock files. Set only the child
        // mask; the syscall is async-signal-safe and touches no allocator/locks.
        unsafe {
            command.as_std_mut().pre_exec(|| {
                rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));
                Ok(())
            });
        }
        if let Some(token) = token {
            command.env("KUBE_TOKEN", token);
        }
        let mut child = command.spawn().map_err(|_| refuse("tool spawn"))?;
        struct Group(rustix::process::Pid);
        impl Drop for Group {
            fn drop(&mut self) {
                let _ = rustix::process::kill_process_group(self.0, rustix::process::Signal::KILL);
            }
        }
        let _group = Group(rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap());
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        async fn read<R: tokio::io::AsyncRead + Unpin>(stream: R, cap: usize) -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            stream.take(cap as u64 + 1).read_to_end(&mut bytes).await?;
            require(bytes.len() <= cap, "tool output size")?;
            Ok(bytes)
        }
        let (out, _err, status) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::try_join!(read(stdout, MAX_JSON), read(stderr, 64 * 1024), async {
                child.wait().await.map_err(Error::from)
            })
        })
        .await
        .map_err(|_| refuse("tool deadline"))??;
        require(status.success(), "tool refused inspection")?;
        Ok(out)
    }
}
#[cfg(unix)]
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Read pinned private blobs through descriptor-relative custody, copy them to
/// an owned private directory, and derive JSON there without inherited secrets.
/// Root and manifest belong to the protected planner, not the agent runtime.
#[cfg(unix)]
pub async fn inspect(root_path: &Path, manifest_path: &Path) -> Result<Inspection> {
    Ok(prepare(root_path, manifest_path).await?.inspection)
}

#[cfg(unix)]
pub struct Prepared {
    pub inspection: Inspection,
    pub manifest: Manifest,
    pub(crate) config: Value,
    pub(crate) state: Value,
    pub(crate) stage: Stage,
}
#[cfg(unix)]
pub async fn prepare(root_path: &Path, manifest_path: &Path) -> Result<Prepared> {
    let root = Root::open(root_path)?;
    let manifest = Manifest::decode(&root.read(manifest_path, Material::Secret, 64 * 1024)?)?;
    let stage = Stage::new()?;
    let provider_path = format!(
        ".terraform/providers/{PROVIDER}/{}/{}/terraform-provider-kubernetes_v{}_x5",
        manifest.provider_version, manifest.platform, manifest.provider_version
    );
    let destinations = [
        "terraform",
        &provider_path,
        "plan.bin",
        "terraform.tfstate",
        ".terraform.lock.hcl",
        "main.tf.json",
    ];
    let mut config = Value::Null;
    let mut state = Value::Null;
    for (name, destination) in FILES.iter().zip(destinations) {
        let bound = match *name {
            "terraform.bin" | "kubernetes.bin" => 128 << 20,
            "plan.bin" => 16 << 20,
            _ => MAX_JSON,
        };
        let bytes = root.read_snapshot(&root_path.join(name), bound)?;
        require(
            hash(&bytes) == manifest.files[*name],
            "input digest mismatch",
        )?;
        if *name == "configuration.json" {
            config = strict_value(&bytes)?;
            configuration(&manifest, &config)?;
        }
        if *name == "state.json" {
            state = strict_value(&bytes)?;
        }
        stage.write(
            destination,
            &bytes,
            *name == "terraform.bin" || *name == "kubernetes.bin",
        )?;
    }
    if manifest.profile == EXECUTION_PROFILE {
        let bytes = root.read_snapshot(&root_path.join("backend.json"), MAX_JSON)?;
        require(
            hash(&bytes) == manifest.files["backend.json"],
            "backend metadata digest",
        )?;
        let backend = strict_value(&bytes)?;
        require(
            backend["backend"]["type"] == "local"
                && backend["backend"]["config"]["path"] == json!(manifest.backend_state_path)
                && backend["backend"]["config"]["workspace_dir"].is_null(),
            "native local backend identity",
        )?;
        stage.write(".terraform/terraform.tfstate", &bytes, false)?;
    }
    stage.write("terraform.rc", b"disable_checkpoint = true\n", false)?;
    let version = strict_value(&stage.command(&["version", "-json"]).await?)?;
    require(
        version["terraform_version"] == manifest.terraform_version
            && version["platform"] == manifest.platform,
        "tool version/platform",
    )?;
    let raw = stage.command(&["show", "-json", "plan.bin"]).await?;
    let inspection = validate_inspection(&manifest, &config, &state, &raw)?;
    Ok(Prepared {
        inspection,
        manifest,
        config,
        state,
        stage,
    })
}
#[cfg(not(unix))]
pub async fn inspect(_root_path: &Path, _manifest_path: &Path) -> Result<Inspection> {
    Err(refuse("Unix custody required"))
}
