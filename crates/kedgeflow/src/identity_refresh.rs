//! Signed per-exchange identity refresh. The protected head/floor must survive
//! broker/snapshot restore independently; this module never publishes them.
use crate::{
    auth::valid_spiffe_id,
    broker_authorization::{ExchangeIdentityProvider, VerifiedExchangeIdentity},
    contracts::{canonical, digest, strict_value},
    error::{Error, Result},
    exchange_identity::{PinnedExchangeIdentityProvider, TrustSnapshot},
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::io::AsyncReadExt;
pub const PROFILE: &str = "KF-IDENTITY-REFRESH-0.1-draft";
const SAFE: u64 = 9_007_199_254_740_991;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmPins {
    pub issuer: String,
    pub subject_audience: String,
    pub actor_audience: String,
}
impl RealmPins {
    pub fn digest(&self) -> Result<String> {
        digest("identity-realm", &serde_json::to_value(self)?)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshHead {
    pub profile: String,
    pub kind: String,
    pub authority_id: String,
    pub realm_digest: String,
    pub epoch: u64,
    pub snapshot_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSnapshot {
    pub profile: String,
    pub kind: String,
    pub authority_id: String,
    pub realm_digest: String,
    pub epoch: u64,
    pub snapshot_digest: String,
    pub snapshot: TrustSnapshot,
    pub key_id: String,
    pub signature: String,
}
fn signing_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut v = value.clone();
    v.as_object_mut().ok_or_else(refused)?.remove("signature");
    let mut bytes = PROFILE.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(canonical(&v)?);
    Ok(bytes)
}
pub fn sign_snapshot(
    snapshot: TrustSnapshot,
    authority_id: String,
    key_id: String,
    key: &SigningKey,
) -> Result<(SignedSnapshot, RefreshHead)> {
    snapshot.validate()?;
    let realm = RealmPins {
        issuer: snapshot.issuer.clone(),
        subject_audience: snapshot.subject_audience.clone(),
        actor_audience: snapshot.actor_audience.clone(),
    };
    let head = RefreshHead {
        profile: PROFILE.into(),
        kind: "head".into(),
        authority_id: authority_id.clone(),
        realm_digest: realm.digest()?,
        epoch: snapshot.epoch,
        snapshot_digest: digest("identity-snapshot", &serde_json::to_value(&snapshot)?)?,
    };
    validate(&serde_json::to_value(&head)?)?;
    let mut record = SignedSnapshot {
        profile: PROFILE.into(),
        kind: "snapshot".into(),
        authority_id,
        realm_digest: head.realm_digest.clone(),
        epoch: head.epoch,
        snapshot_digest: head.snapshot_digest.clone(),
        snapshot,
        key_id,
        signature: String::new(),
    };
    record.signature = URL_SAFE_NO_PAD.encode(
        key.sign(&signing_bytes(&serde_json::to_value(&record)?)?)
            .to_bytes(),
    );
    validate(&serde_json::to_value(&record)?)?;
    Ok((record, head))
}
pub fn validate(value: &Value) -> Result<()> {
    static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    let s = SCHEMA.get_or_init(|| {
        crate::schema::compile(
            &serde_json::from_str(include_str!(
                "../../../spec/drafts/identity-refresh-v0.1.schema.json"
            ))
            .expect("embedded refresh schema"),
        )
        .expect("valid refresh schema")
    });
    if !s.is_valid(value) {
        return Err(Error::Invalid(
            "closed identity refresh record mismatch".into(),
        ));
    }
    Ok(())
}
#[async_trait]
pub trait RefreshSource: Send + Sync {
    async fn head(&self) -> Result<Vec<u8>>;
    async fn snapshot(&self) -> Result<Vec<u8>>;
}
pub struct FileRefreshSource {
    pub head_file: PathBuf,
    pub signed_snapshot_file: PathBuf,
}
async fn read(path: &PathBuf, max: usize) -> Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    let meta = file.metadata().await?;
    if !meta.is_file() || meta.len() > max as u64 {
        return Err(Error::Unavailable("invalid identity refresh source".into()));
    }
    let mut raw = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut raw).await?;
    if raw.len() > max {
        return Err(Error::Unavailable(
            "identity refresh source exceeds bound".into(),
        ));
    }
    Ok(raw)
}
#[async_trait]
impl RefreshSource for FileRefreshSource {
    async fn head(&self) -> Result<Vec<u8>> {
        read(&self.head_file, 16384).await
    }
    async fn snapshot(&self) -> Result<Vec<u8>> {
        read(&self.signed_snapshot_file, (1 << 20) + 16384).await
    }
}
#[derive(Clone)]
pub struct RefreshingIdentityProvider {
    source: Arc<dyn RefreshSource>,
    realm: RealmPins,
    realm_digest: String,
    authority_id: String,
    keys: BTreeMap<String, VerifyingKey>,
    forbidden: BTreeSet<[u8; 32]>,
    minimum_epoch: u64,
    seen: Arc<Mutex<Option<RefreshHead>>>,
}
impl RefreshingIdentityProvider {
    pub fn new(
        source: Arc<dyn RefreshSource>,
        realm: RealmPins,
        authority_id: String,
        keys: BTreeMap<String, VerifyingKey>,
        forbidden: BTreeSet<[u8; 32]>,
        minimum_epoch: u64,
    ) -> Result<Self> {
        if authority_id.is_empty()
            || authority_id.len() > 1024
            || minimum_epoch == 0
            || minimum_epoch > SAFE
            || keys.is_empty()
            || keys.len() > 32
            || keys.iter().any(|(id, k)| {
                id.is_empty() || id.len() > 1024 || k.is_weak() || forbidden.contains(k.as_bytes())
            })
        {
            return Err(Error::Invalid(
                "invalid independent identity refresh pins".into(),
            ));
        }
        for value in [
            &realm.issuer,
            &realm.subject_audience,
            &realm.actor_audience,
        ] {
            if value.is_empty()
                || value.len() > 2048
                || !value.is_ascii()
                || value.bytes().any(|c| c <= b' ' || c == 127)
            {
                return Err(Error::Invalid("invalid refresh realm pins".into()));
            }
        }
        Ok(Self {
            source,
            realm_digest: realm.digest()?,
            realm,
            authority_id,
            keys,
            forbidden,
            minimum_epoch,
            seen: Arc::new(Mutex::new(None)),
        })
    }
    async fn head(&self) -> Result<RefreshHead> {
        let raw = self.source.head().await?;
        if raw.len() > 16384 {
            return Err(refused());
        }
        let value = strict_value(&raw)?;
        validate(&value)?;
        let h: RefreshHead = serde_json::from_value(value)?;
        if h.kind != "head"
            || h.authority_id != self.authority_id
            || h.realm_digest != self.realm_digest
            || h.epoch < self.minimum_epoch
        {
            return Err(refused());
        }
        // Observe even if the matching publication is unavailable or malformed.
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| Error::Unavailable("identity head state poisoned".into()))?;
        if let Some(old) = &*seen
            && (h.epoch < old.epoch || (h.epoch == old.epoch && h != *old))
        {
            return Err(refused());
        }
        *seen = Some(h.clone());
        Ok(h)
    }
    fn snapshot(&self, raw: &[u8], head: &RefreshHead) -> Result<TrustSnapshot> {
        if raw.len() > (1 << 20) + 16384 {
            return Err(refused());
        }
        let value = strict_value(raw)?;
        validate(&value)?;
        let record: SignedSnapshot = serde_json::from_value(value.clone())?;
        let key = self.keys.get(&record.key_id).ok_or_else(refused)?;
        let sig = URL_SAFE_NO_PAD
            .decode(&record.signature)
            .map_err(|_| refused())?;
        if URL_SAFE_NO_PAD.encode(&sig) != record.signature {
            return Err(refused());
        }
        let sig = Signature::from_slice(&sig).map_err(|_| refused())?;
        key.verify_strict(&signing_bytes(&value)?, &sig)
            .map_err(|_| refused())?;
        let s = record.snapshot;
        s.validate()?;
        if record.kind != "snapshot"
            || record.authority_id != head.authority_id
            || record.realm_digest != head.realm_digest
            || record.epoch != head.epoch
            || record.epoch != s.epoch
            || record.snapshot_digest != head.snapshot_digest
            || record.snapshot_digest != digest("identity-snapshot", &value["snapshot"])?
            || s.issuer != self.realm.issuer
            || s.subject_audience != self.realm.subject_audience
            || s.actor_audience != self.realm.actor_audience
        {
            return Err(refused());
        }
        for k in &s.subject_keys {
            let bytes = URL_SAFE_NO_PAD
                .decode(&k.public_key)
                .map_err(|_| refused())?;
            let raw: [u8; 32] = bytes.try_into().map_err(|_| refused())?;
            if self.forbidden.contains(&raw) || self.keys.values().any(|k| k.as_bytes() == &raw) {
                return Err(refused());
            }
        }
        for r in &s.registrations {
            if !valid_spiffe_id(&r.workload_id) {
                return Err(refused());
            }
        }
        Ok(s)
    }
    /// Signature/head/role material check only, no token or execution authority.
    pub async fn check_material(&self) -> Result<()> {
        let first = self.head().await?;
        self.snapshot(&self.source.snapshot().await?, &first)?;
        if self.head().await? != first {
            return Err(refused());
        }
        Ok(())
    }
}
#[async_trait]
impl ExchangeIdentityProvider for RefreshingIdentityProvider {
    async fn verify(
        &self,
        subject: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<VerifiedExchangeIdentity> {
        let first = self.head().await?;
        let snapshot = self.snapshot(&self.source.snapshot().await?, &first)?;
        let verified = PinnedExchangeIdentityProvider::new(snapshot, first.epoch)?
            .verify(subject, actor, now_ms)
            .await?;
        if self.head().await? != first {
            return Err(refused());
        }
        Ok(verified)
    }
}
fn refused() -> Error {
    Error::Refused("identity refresh signature/head/realm/epoch mismatch".into())
}
