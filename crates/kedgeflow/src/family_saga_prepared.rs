//! Durable exact owner command for submission/recovery. A partial file, conflict
//! or expired uncommitted intent is never replaced or re-signed automatically.
use crate::{
    contracts::{canonical, strict_value},
    error::{Error, Result},
    family::Registration,
    family_saga::{Collected, Intent, IntentPayload},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::{Read, Write},
    path::Path,
};
pub const MAX_PREPARED: usize = (512 << 10) + (32 << 10);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub intent: Intent,
    pub capture: Option<Collected>,
}
impl Prepared {
    pub async fn sign(
        payload: IntentPayload,
        capture: Option<Collected>,
        key_id: &str,
        key_file: &Path,
        r: &Registration,
    ) -> Result<Self> {
        let secret = crate::config::read_secret(&key_file.to_path_buf()).await?;
        let key = ed25519_dalek::SigningKey::from_bytes(&crate::config::key(&secret)?);
        let p = Self {
            intent: Intent::sign(payload, key_id, &key)?,
            capture,
        };
        p.verify(r)?;
        Ok(p)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_PREPARED {
            return Err(Error::Invalid("prepared saga intent exceeds bound".into()));
        }
        let v = strict_value(raw)?;
        let p: Self = serde_json::from_value(v.clone())?;
        if json!(p) != v {
            return Err(Error::Invalid(
                "closed prepared saga command required".into(),
            ));
        }
        // Apply the existing closed wire decoders, including explicit null and
        // nested proof limits; serde alone is not the public wire validator.
        Intent::decode(&canonical(&json!(p.intent))?)?;
        if let Some(c) = &p.capture {
            Collected::decode(&canonical(&json!(c))?)?;
        }
        Ok(p)
    }
    pub fn verify(&self, r: &Registration) -> Result<()> {
        self.intent.verify_owner(r)?;
        match (&self.capture, &self.intent.payload.proof_digest) {
            (None, None) => Ok(()),
            (Some(c), Some(d)) => {
                c.verify(r)?;
                if c.snapshot.digest()? != *d
                    || c.snapshot.phase_head != self.intent.payload.expected_head
                    || c.snapshot.captured_at > self.intent.payload.issued_at
                {
                    return Err(Error::Refused("prepared saga intent/capture differ".into()));
                }
                Ok(())
            }
            _ => Err(Error::Refused(
                "prepared saga capture required exactly".into(),
            )),
        }
    }
    pub fn read(path: &Path) -> Result<Self> {
        let mut raw = Vec::new();
        std::fs::File::open(path)?
            .take(MAX_PREPARED as u64 + 1)
            .read_to_end(&mut raw)?;
        Self::decode(&raw)
    }
    /// Exclusive creation, durable file and directory before any submission.
    /// An existing or partially written record deliberately blocks restaging.
    pub fn retain(&self, path: &Path, r: &Registration) -> Result<()> {
        self.verify(r)?;
        let raw = canonical(&json!(self))?;
        Self::decode(&raw)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&raw)?;
        file.sync_all()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}
