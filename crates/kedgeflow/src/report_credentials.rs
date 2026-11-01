//! Operator-supplied receipt delivery credentials; no issuance or fallback cache.
use crate::{config::key, error::Result, service_files::ServiceFiles};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Credential {
    pub token: String,
    pub proof_key: SigningKey,
}

#[async_trait]
pub trait Source: Send + Sync {
    async fn load(&self) -> Result<Credential>;
}

pub(crate) struct Static(pub Credential);
#[async_trait]
impl Source for Static {
    async fn load(&self) -> Result<Credential> {
        Ok(self.0.clone())
    }
}

pub struct FileSource {
    pub files: ServiceFiles,
    pub token_file: PathBuf,
    pub proof_key_file: PathBuf,
}
#[async_trait]
impl Source for FileSource {
    async fn load(&self) -> Result<Credential> {
        let token = self.files.secret(&self.token_file).await?;
        let proof_key =
            SigningKey::from_bytes(&key(&self.files.secret(&self.proof_key_file).await?)?);
        Ok(Credential { token, proof_key })
    }
}
