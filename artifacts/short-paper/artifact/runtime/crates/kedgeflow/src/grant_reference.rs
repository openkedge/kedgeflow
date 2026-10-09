//! Optional immutable-envelope carriage; a reference confers no authority.
use crate::{
    auth::Identity,
    error::{Error, Result},
    tls::PinnedClient,
};
use async_trait::async_trait;
use serde::Serialize;
use std::time::Duration;

pub const REFERENCE_PROFILE: &str = "KF-GRANT-REF-0.1";
pub const REFERENCE_HEADER: &str = "Mcp-KedgeFlow-Grant-Ref";
pub const INLINE_HEADER: &str = "Mcp-KedgeFlow-Grant";
pub const MAX_INLINE_HEADER: usize = 6 * 1024;
pub const MAX_RESOLVED_BYTES: usize = 64 * 1024;

pub fn valid_reference(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validate a fixed operator-configured URL, never an agent-provided location.
pub(crate) fn fixed_https(endpoint: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| Error::Invalid("invalid fixed endpoint".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid(
            "fixed endpoint requires HTTPS without userinfo, query or fragment".into(),
        ));
    }
    Ok(url)
}

pub(crate) async fn bounded_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(Error::Unavailable("response exceeds bound".into()));
    }
    let mut raw = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(raw.len()) {
            return Err(Error::Unavailable("response exceeds bound".into()));
        }
        raw.extend_from_slice(&chunk);
    }
    Ok(raw)
}

#[async_trait]
pub trait GrantResolver: Send + Sync {
    async fn resolve(&self, identity: &Identity, digest: &str) -> Result<Vec<u8>>;
}

#[derive(Serialize)]
struct ReferenceQuery<'a> {
    grant_digest: &'a str,
    subject: &'a crate::contracts::Subject,
    workload_id: &'a str,
    dpop_jkt: &'a str,
    delegation_digest: &'a str,
}

pub struct HttpsGrantResolver {
    endpoint: reqwest::Url,
    client: PinnedClient,
}
impl HttpsGrantResolver {
    pub fn new(endpoint: &str, client: PinnedClient) -> Result<Self> {
        Ok(Self {
            endpoint: fixed_https(endpoint)?,
            client,
        })
    }
}
#[async_trait]
impl GrantResolver for HttpsGrantResolver {
    async fn resolve(&self, identity: &Identity, digest: &str) -> Result<Vec<u8>> {
        if !valid_reference(digest)
            || identity.subject.iss.is_empty()
            || identity.subject.sub.is_empty()
            || identity.workload_id.is_empty()
            || identity.dpop_jkt.is_empty()
            || identity.delegation_digest.is_empty()
        {
            return Err(Error::Invalid("invalid reference scope".into()));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            let query = ReferenceQuery {
                grant_digest: digest,
                subject: &identity.subject,
                workload_id: &identity.workload_id,
                dpop_jkt: &identity.dpop_jkt,
                delegation_digest: &identity.delegation_digest,
            };
            let response = self
                .client
                .client()
                .post(self.endpoint.clone())
                .json(&query)
                .header("Accept", "application/json")
                .header("Accept-Encoding", "identity")
                .send()
                .await?;
            if response.status() != reqwest::StatusCode::OK
                || response.headers().contains_key("content-encoding")
            {
                return Err(Error::Unavailable("grant reference unavailable".into()));
            }
            let raw = bounded_response(response, MAX_RESOLVED_BYTES).await?;
            if raw.is_empty() {
                return Err(Error::Unavailable("empty grant reference response".into()));
            }
            Ok(raw)
        })
        .await
        .map_err(|_| Error::Unavailable("grant reference lookup timed out".into()))?
    }
}
