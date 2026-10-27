//! Bounded delivery of the durable original incident. Sink receipts annotate
//! delivery only; they never establish a physical outcome or release authority.
use crate::{
    clock::Clock,
    error::{Error, Result},
    grant_reference::{bounded_response, fixed_https},
    managed_drain_evidence::{Ack, IncidentReport, Signed},
    managed_drain_store::{ReservedDelivery, Store},
    physical_operations::IncidentSink,
    tls::PinnedClient,
};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use std::{sync::Arc, time::Duration};
fn refuse() -> Error {
    Error::Refused("protected original incident delivery refused".into())
}
#[async_trait]
pub trait Sink: Send + Sync {
    async fn deliver(&self, report: &Signed<IncidentReport>) -> Result<Ack>;
}
pub struct Client {
    transport: PinnedClient,
    endpoint: reqwest::Url,
    token: String,
}
impl Client {
    pub fn new(transport: PinnedClient, sink: &IncidentSink, token: String) -> Result<Self> {
        if token.len() < 32 || token.len() > 16384 || token.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(refuse());
        }
        Ok(Self {
            transport,
            endpoint: fixed_https(&sink.url)?,
            token,
        })
    }
}
#[async_trait]
impl Sink for Client {
    async fn deliver(&self, report: &Signed<IncidentReport>) -> Result<Ack> {
        let unavailable = || Error::Unavailable("owned incident sink unavailable".into());
        let response = self
            .transport
            .client()
            .post(self.endpoint.clone())
            .bearer_auth(&self.token)
            .json(report)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| unavailable())?;
        if response.url() != &self.endpoint || response.status() != reqwest::StatusCode::OK {
            return Err(unavailable());
        }
        Ok(serde_json::from_value(crate::contracts::strict_value(
            &bounded_response(response, 65536).await?,
        )?)?)
    }
}
/// The report is derived only from the immutable outbox, never a later capture
/// or delivery attempt. Restart and lost reply therefore reuse its exact body.
pub fn report(store: &Store, reserved: &ReservedDelivery) -> Result<IncidentReport> {
    let e = &store.context.enrollment;
    store.context.validate_origin(&reserved.origin)?;
    if reserved.incident.id
        != crate::managed_drain_journal::Core::initial(e, &reserved.origin)?.incident_id(e)?
    {
        return Err(refuse());
    }
    Ok(IncidentReport {
        incident_id: reserved.incident.id.clone(),
        event_digest: reserved.incident.event_digest.clone(),
        original: reserved.origin.original.clone(),
        deadline: reserved.incident.deadline,
        opened_at: reserved.incident.opened_at,
        resource_owner_id: e.policy.resource_owner_id.clone(),
        on_call_team_id: e.policy.on_call_team_id.clone(),
        sink_id: e.policy.incident_sink.id.clone(),
        physical_state: "unresolved_at_operating_deadline".into(),
    })
}
pub struct Worker {
    store: Store,
    sink: Arc<dyn Sink>,
    clock: Arc<dyn Clock>,
    key_id: String,
    key: SigningKey,
}
impl Worker {
    pub fn new(
        store: Store,
        sink: Arc<dyn Sink>,
        clock: Arc<dyn Clock>,
        key_id: String,
        key: SigningKey,
    ) -> Result<Self> {
        if crate::control_config::keys(&store.context.enrollment.operating_observer.keys)?
            .get(&key_id)
            != Some(&key.verifying_key())
        {
            return Err(refuse());
        }
        Ok(Self {
            store,
            sink,
            clock,
            key_id,
            key,
        })
    }
    /// At most one sink call. The independent stop timer must run separately
    /// from this bounded network operation and from physical capture.
    pub async fn tick(&self) -> Result<bool> {
        self.store.expire_delivery(self.clock.now_ms()).await?;
        let Some(reserved) = self.store.reserve_delivery(self.clock.now_ms()).await? else {
            return Ok(false);
        };
        let body = report(&self.store, &reserved)?;
        let signed = Signed::sign(
            "incident_report",
            body,
            &self.store.context.enrollment.operating_observer,
            &self.key_id,
            &self.key,
        )?;
        let result = tokio::time::timeout(Duration::from_secs(5), self.sink.deliver(&signed)).await;
        match result {
            Ok(Ok(ack)) => {
                // The store checks sink signature and exact original outbox before CAS.
                // Retention failure is not a malformed network reply. Keep
                // this consumed original slot for expiry; do not clear it
                // early or turn a local CAS race into another sink request.
                self.store
                    .delivery_acknowledged(&reserved, self.clock.as_ref(), ack)
                    .await?;
            }
            _ => {
                self.store
                    .delivery_failed(&reserved, self.clock.now_ms(), "transport")
                    .await?
            }
        }
        Ok(true)
    }
}
