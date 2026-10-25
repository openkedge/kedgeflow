//! Protected fixed read-only SQL witness client. No caller-selected destination.
use crate::{
    clock::Clock,
    current_reservation::{PROFILE, Query, Registration, Witness},
    error::{Error, Result},
    grant_reference::{bounded_response, fixed_https},
    managed_drain_store::{Context, ReservedQuery},
    tls::PinnedClient,
};
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
#[async_trait]
pub trait Querier: Send + Sync {
    async fn query(&self, context: &Context, query: &ReservedQuery) -> Result<Witness>;
}
pub struct Client {
    transport: PinnedClient,
    registration: Registration,
    endpoint: reqwest::Url,
    token: String,
    clock: Arc<dyn Clock>,
}
impl Client {
    pub fn new(
        transport: PinnedClient,
        registration: Registration,
        token: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        registration.validate()?;
        if token.len() < 32 || token.len() > 16384 || token.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(Error::Refused(
                "protected current reservation credential required".into(),
            ));
        }
        Ok(Self {
            endpoint: fixed_https(&registration.endpoint)?,
            transport,
            registration,
            token,
            clock,
        })
    }
}
#[async_trait]
impl Querier for Client {
    async fn query(&self, c: &Context, reserved: &ReservedQuery) -> Result<Witness> {
        let unavailable =
            || Error::Unavailable("current original SQL reservation witness unavailable".into());
        if c.enrollment.current_sql != self.registration {
            return Err(unavailable());
        }
        let requested_at = self.clock.now_ms();
        if requested_at >= reserved.slot.expires_at {
            return Err(unavailable());
        }
        let q = Query {
            profile: PROFILE.into(),
            enrollment_digest: c.enrollment.digest()?,
            origin: reserved.origin.clone(),
            reservation_digest: reserved.slot.reservation_digest.clone(),
            requested_at,
        };
        let response = self
            .transport
            .client()
            .post(self.endpoint.clone())
            .bearer_auth(&self.token)
            .json(&q)
            .timeout(Duration::from_millis(self.registration.request_timeout_ms))
            .send()
            .await
            .map_err(|_| unavailable())?;
        if response.url() != &self.endpoint || response.status() != reqwest::StatusCode::OK {
            return Err(unavailable());
        }
        let w: Witness = serde_json::from_value(crate::contracts::strict_value(
            &bounded_response(response, 65536).await?,
        )?)?;
        let (_, sql) = c.validate_origin(&reserved.origin)?;
        let sql_digest = c
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(unavailable)?
            .node(&self.registration.forward_child_id)?
            .forward()?
            .lineage
            .grants
            .verify_retained(reserved.origin.forward_signed_grant.as_bytes())?
            .digest;
        let at = self.clock.now_ms();
        w.validate_current(
            &c.enrollment,
            &reserved.origin,
            &reserved.slot.reservation_digest,
            at,
            &sql,
            &sql_digest,
        )?;
        if w.body.query_digest != q.digest()? || at >= reserved.slot.expires_at {
            return Err(unavailable());
        }
        Ok(w)
    }
}
