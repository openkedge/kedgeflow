//! Separate read-only two-resource candidate profile. This module never issues
//! authority or exposes apply; the single-resource runner rejects this profile.
use crate::{
    contracts::{digest, strict_value},
    error::{Error, Result},
    terraform_plan::{self as single, Target},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

pub const PROFILE: &str = "KF-TERRAFORM-PAIR-PLAN-0.1-draft";
const IDS: [&str; 2] = ["first", "second"];
const PREFIX: &str = "kubernetes_config_map_v1.";
const MAX_JSON: usize = 2 << 20;
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Refused(format!("Terraform pair: {message}")))
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub id: String,
    pub target: Target,
    pub before_revision: String,
    pub after_revision: String,
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
    pub backend_state_path: String,
    pub files: BTreeMap<String, String>,
    pub members: Vec<Member>,
}
impl Manifest {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        require(raw.len() <= 64 * 1024, "manifest size")?;
        let value = strict_value(raw)?;
        let m: Self = serde_json::from_value(value)
            .map_err(|_| Error::Refused("Terraform pair: manifest shape".into()))?;
        m.validate()?;
        Ok(m)
    }
    fn single(&self, i: usize) -> single::Manifest {
        let member = &self.members[i];
        single::Manifest {
            profile: single::EXECUTION_PROFILE.into(),
            terraform_version: self.terraform_version.clone(),
            provider_version: self.provider_version.clone(),
            platform: self.platform.clone(),
            workspace_id: self.workspace_id.clone(),
            backend: self.backend.clone(),
            backend_state_path: Some(self.backend_state_path.clone()),
            target: member.target.clone(),
            before_revision: member.before_revision.clone(),
            after_revision: member.after_revision.clone(),
            files: self.files.clone(),
        }
    }
    fn validate(&self) -> Result<()> {
        require(
            self.profile == PROFILE && self.members.len() == 2,
            "profile or member count",
        )?;
        for (i, id) in IDS.iter().enumerate() {
            require(self.members[i].id == *id, "fixed member order")?;
            self.single(i).validate()?;
        }
        let (a, b) = (&self.members[0].target, &self.members[1].target);
        require(
            a.cluster_uid == b.cluster_uid
                && a.namespace == b.namespace
                && a.name != b.name
                && a.uid != b.uid,
            "distinct targets in one cluster/namespace",
        )
    }
}
#[derive(Debug, Serialize)]
pub struct MemberInspection {
    pub id: String,
    pub address: String,
    pub target: Target,
    pub effect_digest: String,
}
#[derive(Debug, Serialize)]
pub struct Inspection {
    pub profile: &'static str,
    pub status: &'static str,
    pub manifest_digest: String,
    pub inspection_sha256: String,
    pub effect_digest: String,
    pub inputs: BTreeMap<String, String>,
    pub workspace_id: String,
    pub backend: String,
    pub backend_state_path: String,
    pub state_lineage: String,
    pub state_serial: u64,
    pub members: Vec<MemberInspection>,
    pub order: [&'static str; 2],
    pub guard_level: &'static str,
    pub execution_enabled: bool,
}
fn selected(rows: &Value, i: usize, field: &str) -> Result<Value> {
    let rows = rows
        .as_array()
        .ok_or_else(|| Error::Refused("Terraform pair: resource list".into()))?;
    require(rows.len() == 2, "exactly two resources in every view")?;
    for (row, id) in rows.iter().zip(IDS) {
        require(
            row[field]
                == if field == "name" {
                    id.to_string()
                } else {
                    format!("{PREFIX}{id}")
                },
            "resource identity/order",
        )?;
        if field == "address" {
            require(row["name"] == id, "resource name")?;
        }
    }
    let mut row = rows[i].clone();
    row["name"] = json!("target");
    if field == "address" {
        row["address"] = json!(format!("{PREFIX}target"));
    }
    Ok(row)
}
fn configuration(m: &Manifest, config: &Value, i: usize) -> Result<Value> {
    let maps = &config["resource"]["kubernetes_config_map_v1"];
    require(
        maps.as_object()
            .is_some_and(|o| o.len() == 2 && IDS.iter().all(|id| o.contains_key(*id))),
        "configured member set",
    )?;
    require(
        maps["first"].get("depends_on").is_none()
            && maps["second"]["depends_on"] == json!([format!("{PREFIX}first")]),
        "explicit forward dependency",
    )?;
    let mut member = maps[IDS[i]].clone();
    member
        .as_object_mut()
        .ok_or_else(|| Error::Refused("Terraform pair: member configuration".into()))?
        .remove("depends_on");
    let mut projected = config.clone();
    projected["resource"]["kubernetes_config_map_v1"] = json!({"target":member});
    // Reuse the original closed literal/provider/effect validator, after checking
    // both resource identities and the only permitted dependency above.
    require(m.members[i].id == IDS[i], "member identity")?;
    Ok(projected)
}
pub fn validate_inspection(
    m: &Manifest,
    config: &Value,
    state: &Value,
    raw: &[u8],
) -> Result<Inspection> {
    m.validate()?;
    require(raw.len() <= MAX_JSON, "inspection size")?;
    let plan = strict_value(raw)?;
    if let Some(reads) = plan.get("relevant_attributes") {
        let reads = reads
            .as_array()
            .ok_or_else(|| Error::Refused("Terraform pair: dependency read set".into()))?;
        require(
            reads.iter().all(|read| {
                IDS.iter()
                    .any(|id| read["resource"] == format!("{PREFIX}{id}"))
            }),
            "external dependency read",
        )?;
    }
    let mut members = Vec::new();
    let mut identity = None;
    for (i, id) in IDS.iter().enumerate() {
        let c = configuration(m, config, i)?;
        let mut s = state.clone();
        s["resources"] = json!([selected(&state["resources"], i, "name")?]);
        let mut p = plan.clone();
        for pointer in [
            "/resource_changes",
            "/prior_state/values/root_module/resources",
            "/planned_values/root_module/resources",
            "/configuration/root_module/resources",
        ] {
            let rows = plan
                .pointer(pointer)
                .ok_or_else(|| Error::Refused("Terraform pair: missing view".into()))?;
            let mut row = selected(rows, i, "address")?;
            if pointer == "/configuration/root_module/resources" {
                require(
                    row.as_object().is_some_and(|fields| {
                        fields.keys().all(|key| {
                            [
                                "address",
                                "mode",
                                "type",
                                "name",
                                "provider_config_key",
                                "expressions",
                                "schema_version",
                                "depends_on",
                            ]
                            .contains(&key.as_str())
                        })
                    }),
                    "embedded resource fields",
                )?;
                require(
                    if i == 0 {
                        row.get("depends_on").is_none()
                    } else {
                        row["depends_on"] == json!([format!("{PREFIX}first")])
                    },
                    "embedded dependency differs",
                )?;
                row.as_object_mut().unwrap().remove("depends_on");
            }
            *p.pointer_mut(pointer).unwrap() = json!([row]);
        }
        let result = single::validate_inspection(&m.single(i), &c, &s, &serde_json::to_vec(&p)?)?;
        let current = (result.state_lineage, result.state_serial);
        if let Some(previous) = &identity {
            require(previous == &current, "shared state identity")?;
        }
        identity = Some(current);
        members.push(MemberInspection {
            id: (*id).into(),
            address: format!("{PREFIX}{id}"),
            target: m.members[i].target.clone(),
            effect_digest: result.effect_digest,
        });
    }
    let (state_lineage, state_serial) = identity.unwrap();
    Ok(Inspection {
        profile: PROFILE,
        status: "inspection_passed",
        manifest_digest: digest("terraform-pair-plan-manifest", &serde_json::to_value(m)?)?,
        inspection_sha256: hash(raw),
        effect_digest: digest(
            "terraform-pair-plan-effect",
            &json!({"members":members,"order":IDS}),
        )?,
        inputs: m.files.clone(),
        workspace_id: m.workspace_id.clone(),
        backend: m.backend.clone(),
        backend_state_path: m.backend_state_path.clone(),
        state_lineage,
        state_serial,
        members,
        order: IDS,
        guard_level: "Level_C",
        execution_enabled: false,
    })
}

#[cfg(unix)]
pub async fn inspect(root_path: &Path, manifest_path: &Path) -> Result<Inspection> {
    use crate::file_custody::{Material, Root};
    let root = Root::open(root_path)?;
    let m = Manifest::decode(&root.read(manifest_path, Material::Secret, 64 * 1024)?)?;
    let stage = single::Stage::new()?;
    let provider = format!(
        ".terraform/providers/registry.terraform.io/hashicorp/kubernetes/{}/{}/terraform-provider-kubernetes_v{}_x5",
        m.provider_version, m.platform, m.provider_version
    );
    let mut config = Value::Null;
    let mut state = Value::Null;
    for (name, destination, bound, executable) in [
        ("terraform.bin", "terraform", 128 << 20, true),
        ("kubernetes.bin", provider.as_str(), 128 << 20, true),
        ("plan.bin", "plan.bin", 16 << 20, false),
        ("state.json", "terraform.tfstate", MAX_JSON, false),
        ("lock.hcl", ".terraform.lock.hcl", MAX_JSON, false),
        ("configuration.json", "main.tf.json", MAX_JSON, false),
        (
            "backend.json",
            ".terraform/terraform.tfstate",
            MAX_JSON,
            false,
        ),
    ] {
        let bytes = root.read_snapshot(&root_path.join(name), bound)?;
        require(hash(&bytes) == m.files[name], "input digest mismatch")?;
        if name == "configuration.json" {
            config = strict_value(&bytes)?;
        }
        if name == "state.json" {
            state = strict_value(&bytes)?;
        }
        if name == "backend.json" {
            let b = strict_value(&bytes)?;
            require(
                b["backend"]["type"] == "local"
                    && b["backend"]["config"]["path"] == m.backend_state_path
                    && b["backend"]["config"]["workspace_dir"].is_null(),
                "native backend identity",
            )?;
        }
        stage.write(destination, &bytes, executable)?;
    }
    // Refuse hooks/ambient credential sources before spawning even version/show.
    for i in 0..2 {
        let projected = configuration(&m, &config, i)?;
        single::validate_configuration(&m.single(i), &projected)?;
    }
    stage.write("terraform.rc", b"disable_checkpoint = true\n", false)?;
    let version = strict_value(&stage.command(&["version", "-json"]).await?)?;
    require(
        version["terraform_version"] == m.terraform_version && version["platform"] == m.platform,
        "tool version/platform",
    )?;
    let raw = stage.command(&["show", "-json", "plan.bin"]).await?;
    validate_inspection(&m, &config, &state, &raw)
}
#[cfg(not(unix))]
pub async fn inspect(_root: &Path, _manifest: &Path) -> Result<Inspection> {
    Err(Error::Refused(
        "Terraform pair: Unix custody required".into(),
    ))
}
