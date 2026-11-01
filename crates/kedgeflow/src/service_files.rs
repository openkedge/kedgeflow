//! Explicit file access policy shared by a service's startup and live readers.
use crate::{
    error::{Error, Result},
    file_custody::{Material, Root},
    tls,
};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;

#[derive(Clone, Default)]
pub struct ServiceFiles(Option<Arc<Root>>);

impl ServiceFiles {
    pub fn is_protected(&self) -> bool {
        self.0.is_some()
    }

    pub fn protected(root: &Path) -> Result<Self> {
        Ok(Self(Some(Arc::new(Root::open(root)?))))
    }

    pub async fn read(&self, path: &Path, kind: Material, bound: usize) -> Result<Vec<u8>> {
        if let Some(root) = &self.0 {
            let root = root.clone();
            let path = path.to_owned();
            return tokio::task::spawn_blocking(move || root.read(&path, kind, bound))
                .await
                .map_err(|_| Error::Unavailable("protected file read unavailable".into()))?;
        }
        if bound == 0 || bound > crate::file_custody::MAX_READ {
            return Err(Error::Invalid("invalid service file bound".into()));
        }
        let file = tokio::fs::File::open(path).await?;
        let meta = file.metadata().await?;
        if !meta.is_file() || meta.len() > bound as u64 {
            return Err(Error::Invalid("invalid service file".into()));
        }
        let mut bytes = Vec::new();
        file.take(bound as u64 + 1).read_to_end(&mut bytes).await?;
        if bytes.len() > bound {
            return Err(Error::Invalid("service file exceeds bound".into()));
        }
        Ok(bytes)
    }

    pub async fn secret(&self, path: &Path) -> Result<String> {
        let raw = self.read(path, Material::Secret, 65536).await?;
        let value = std::str::from_utf8(&raw)
            .map_err(|_| Error::Invalid("secret UTF8".into()))?
            .trim();
        if value.is_empty() {
            return Err(Error::Invalid("empty configured secret".into()));
        }
        Ok(value.to_owned())
    }

    pub async fn server_tls(
        &self,
        certificate: &Path,
        key: &Path,
        ca: &Path,
    ) -> Result<Arc<rustls::ServerConfig>> {
        tls::server_config_pem(
            &self.read(certificate, Material::Public, 1 << 20).await?,
            &self.read(key, Material::Secret, 65536).await?,
            &self.read(ca, Material::Public, 1 << 20).await?,
        )
    }

    pub async fn http_client(
        &self,
        ca: &Path,
        certificate: &Path,
        key: &Path,
        timeout: Duration,
    ) -> Result<reqwest::Client> {
        tls::pinned_http_client_pem(
            &self.read(ca, Material::Public, 1 << 20).await?,
            &self.read(certificate, Material::Public, 1 << 20).await?,
            &self.read(key, Material::Secret, 65536).await?,
            timeout,
        )
    }

    pub async fn pinned_client(
        &self,
        ca: &Path,
        certificate: &Path,
        key: &Path,
        timeout: Duration,
    ) -> Result<tls::PinnedClient> {
        tls::pinned_client_pem(
            &self.read(ca, Material::Public, 1 << 20).await?,
            &self.read(certificate, Material::Public, 1 << 20).await?,
            &self.read(key, Material::Secret, 65536).await?,
            timeout,
        )
    }
}
