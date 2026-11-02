//! Scoped etcd authentication. This code never grants roles or retries ledger writes.
use crate::{
    contracts::strict_value,
    error::{Error, Result},
    service_files::ServiceFiles,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, time::Duration};

pub const PROFILE: &str = "KF-LEDGER-CREDENTIALS-0.1";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub permission: String,
    pub key: String,
    pub range_end: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub name: String,
    pub endpoint: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub username: String,
    pub password_file: PathBuf,
    pub scope_prefix: String,
    pub permissions: Vec<Permission>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub staging_root: PathBuf,
    pub issuers: Vec<Issuer>,
}
fn refused() -> Error {
    Error::Refused("ledger credential policy refused".into())
}
fn unavailable() -> Error {
    Error::Unavailable("ledger credential issuance unavailable".into())
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
impl Config {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_value(strict_value(raw)?)?;
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<()> {
        if self.profile != PROFILE
            || self.issuers.is_empty()
            || self.issuers.len() > 16
            || !self.staging_root.is_absolute()
        {
            return Err(refused());
        }
        let mut names = BTreeSet::new();
        for issuer in &self.issuers {
            issuer.validate()?;
            if !names.insert(&issuer.name) {
                return Err(refused());
            }
        }
        Ok(())
    }
    pub async fn check(&self, files: &ServiceFiles) -> Result<()> {
        self.validate()?;
        if !files.is_protected() {
            return Err(refused());
        }
        crate::file_custody::Root::open(&self.staging_root)?;
        for issuer in &self.issuers {
            issuer.material(files).await?;
        }
        Ok(())
    }
    pub async fn issue(&self, files: &ServiceFiles) -> Result<usize> {
        self.validate()?;
        if !files.is_protected() {
            return Err(refused());
        }
        let staging = crate::file_custody::Root::open(&self.staging_root)?;
        let created_at = crate::clock::Clock::now_ms(&crate::clock::SystemClock);
        let mut credentials = Vec::new();
        for issuer in &self.issuers {
            credentials.push(
                tokio::time::timeout(Duration::from_secs(5), issuer.issue(files))
                    .await
                    .map_err(|_| unavailable())??,
            );
        }
        let batch = json!({"profile":PROFILE,"created_at":created_at,"credentials":credentials});
        staging.stage_batch(&crate::contracts::canonical(&batch)?)?;
        Ok(self.issuers.len())
    }
}
impl Issuer {
    fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.endpoint).map_err(|_| refused())?;
        if !name(&self.name)
            || !name(&self.username)
            || self.username == "root"
            || url.scheme() != "https"
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || self.endpoint.ends_with('/')
            || !self.scope_prefix.starts_with('/')
            || self.scope_prefix.len() > 512
            || self.scope_prefix.split('/').skip(1).any(|p| {
                p.is_empty()
                    || p == "."
                    || p == ".."
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
            || self.permissions.is_empty()
            || self.permissions.len() > 128
        {
            return Err(refused());
        }
        let lower = format!("{}/", self.scope_prefix);
        let upper = format!("{}0", self.scope_prefix);
        let mut ranges = BTreeSet::new();
        for p in &self.permissions {
            if !["READ", "WRITE", "READWRITE"].contains(&p.permission.as_str())
                || !p.key.starts_with(&lower)
                || p.key.contains('\0')
                || (!p.range_end.is_empty() && (p.range_end <= p.key || p.range_end > upper))
                || !ranges.insert((&p.key, &p.range_end))
            {
                return Err(refused());
            }
        }
        Ok(())
    }
    async fn material(&self, files: &ServiceFiles) -> Result<(reqwest::Client, String)> {
        let password = files.secret(&self.password_file).await?;
        if password.len() < 32
            || password.len() > 4096
            || password.bytes().any(|b| b <= b' ' || b >= 127)
        {
            return Err(refused());
        }
        let certificate = files
            .read(
                &self.certificate,
                crate::file_custody::Material::Public,
                1 << 20,
            )
            .await?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&certificate).map_err(|_| refused())?;
        let (_, leaf) =
            x509_parser::parse_x509_certificate(&pem.contents).map_err(|_| refused())?;
        // etcd rejects nonempty client CNs at its authenticated JSON gateway.
        if leaf.subject().iter_common_name().next().is_some() {
            return Err(refused());
        }
        let ca = files
            .read(&self.ca, crate::file_custody::Material::Public, 1 << 20)
            .await?;
        let key = files
            .read(
                &self.private_key,
                crate::file_custody::Material::Secret,
                65536,
            )
            .await?;
        let client =
            crate::tls::pinned_http_client_pem(&ca, &certificate, &key, Duration::from_secs(5))?;
        Ok((client, password))
    }
    async fn rpc(
        &self,
        client: &reqwest::Client,
        route: &str,
        body: Value,
        token: Option<&str>,
    ) -> Result<(u16, Value)> {
        let url = reqwest::Url::parse(&format!("{}/v3/auth/{route}", self.endpoint))
            .map_err(|_| refused())?;
        let mut request = client.post(url.clone()).json(&body);
        if let Some(token) = token {
            request = request.header("authorization", token);
        }
        let response = request.send().await.map_err(|_| {
            Error::Unavailable(format!("ledger credential {route} transport unavailable"))
        })?;
        if response.url() != &url {
            return Err(unavailable());
        }
        let status = response.status().as_u16();
        let raw = crate::grant_reference::bounded_response(response, 128 * 1024)
            .await
            .map_err(|_| unavailable())?;
        Ok((
            status,
            strict_value(&raw).map_err(|_| {
                Error::Unavailable(format!("ledger credential {route} response invalid"))
            })?,
        ))
    }
    async fn permissions(
        &self,
        client: &reqwest::Client,
        token: &str,
    ) -> Result<BTreeSet<Permission>> {
        let (status, root) = self
            .rpc(client, "user/get", json!({"name":"root"}), Some(token))
            .await?;
        if status != 403 || root.get("code") != Some(&json!(7)) {
            return Err(refused());
        }
        let (status, user) = self
            .rpc(
                client,
                "user/get",
                json!({"name":self.username}),
                Some(token),
            )
            .await?;
        let roles = user
            .get("roles")
            .and_then(Value::as_array)
            .ok_or_else(refused)?;
        if status != 200 || roles.is_empty() || roles.len() > 16 {
            return Err(refused());
        }
        let mut unique = BTreeSet::new();
        let mut result = BTreeSet::new();
        for role in roles {
            let role = role
                .as_str()
                .filter(|s| name(s) && *s != "root")
                .ok_or_else(refused)?;
            if !unique.insert(role) {
                return Err(refused());
            }
            let (status, data) = self
                .rpc(client, "role/get", json!({"role":role}), Some(token))
                .await?;
            // Protobuf JSON omits empty repeated fields and zero-valued READ.
            let entries = match data.get("perm") {
                None => &[][..],
                Some(Value::Array(entries)) => entries.as_slice(),
                Some(_) => return Err(refused()),
            };
            if status != 200 || entries.len() > 128 {
                return Err(refused());
            }
            for p in entries {
                let text = |key: &str| p.get(key).and_then(Value::as_str).ok_or_else(refused);
                let decode = |s: &str| -> Result<String> {
                    let raw = STANDARD.decode(s).map_err(|_| refused())?;
                    if STANDARD.encode(&raw) != s {
                        return Err(refused());
                    }
                    String::from_utf8(raw).map_err(|_| refused())
                };
                result.insert(Permission {
                    permission: match p.get("permType") {
                        None => "READ",
                        Some(Value::String(value)) => value,
                        Some(_) => return Err(refused()),
                    }
                    .into(),
                    key: decode(text("key")?)?,
                    range_end: decode(match p.get("range_end") {
                        None => "",
                        Some(Value::String(value)) => value,
                        Some(_) => return Err(refused()),
                    })?,
                });
            }
        }
        Ok(result)
    }
    async fn issue(&self, files: &ServiceFiles) -> Result<Value> {
        let (client, password) = self.material(files).await?;
        let (status, value) = self
            .rpc(
                &client,
                "authenticate",
                json!({"name":self.username,"password":password}),
                None,
            )
            .await?;
        let token = value
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(unavailable)?;
        if status != 200
            || token.is_empty()
            || token.len() > 8192
            || token.bytes().any(|b| b <= b' ' || b >= 127)
        {
            return Err(unavailable());
        }
        let expected: BTreeSet<_> = self.permissions.iter().cloned().collect();
        if self.permissions(&client, token).await? != expected
            || self.permissions(&client, token).await? != expected
        {
            return Err(refused());
        }
        Ok(
            json!({"name":self.name,"username":self.username,"scope_prefix":self.scope_prefix,
            "permissions_digest":crate::contracts::digest("ledger-credential-permissions",&json!(expected))?,"token":token}),
        )
    }
}
