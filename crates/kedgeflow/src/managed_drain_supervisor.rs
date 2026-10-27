//! Independent bounded physical supervision. This process owns no controller,
//! mutation credential, grant issuer, broker or inverse execution client.
use crate::{
    clock::Clock,
    error::{Error, Result},
    family_saga::{AggregateBundle, Saga},
    managed_drain_journal::QueryKind,
    managed_drain_store::Store,
};
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
#[async_trait]
pub trait Collector: Send + Sync {
    async fn collect(&self) -> Result<AggregateBundle>;
}
pub struct SagaCollector {
    pub saga: Saga,
    pub family_observer: crate::control_history::HistoryObserver,
}
#[async_trait]
impl Collector for SagaCollector {
    async fn collect(&self) -> Result<AggregateBundle> {
        self.saga.export(&self.family_observer).await
    }
}
pub struct Supervisor {
    store: Store,
    collector: Arc<dyn Collector>,
    clock: Arc<dyn Clock>,
}
impl Supervisor {
    pub fn new(store: Store, collector: Arc<dyn Collector>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            collector,
            clock,
        }
    }
    /// Scheduled separately from any aggregate capture or incident sink request.
    pub async fn deadline(&self) -> Result<()> {
        self.store.expire_query(self.clock.now_ms()).await?;
        Ok(())
    }
    /// At most one complete aggregate cycle, reserved durably before any source I/O.
    /// A failed or cancelled request never restores its slot or observation budget.
    pub async fn observe(&self) -> Result<bool> {
        let now = self.clock.now_ms();
        self.store.expire_query(now).await?;
        let Some(s) = self.store.load().await? else {
            return Ok(false);
        };
        let core = s.state();
        let policy = &self.store.context.enrollment.policy;
        let limit = if now < core.deadline {
            policy.maximum_automated_queries
        } else {
            match policy.post_deadline_observation {
                crate::physical_operations::PostDeadline::Disabled => return Ok(false),
                crate::physical_operations::PostDeadline::QueryOnly {
                    maximum_queries, ..
                } => maximum_queries,
            }
        };
        let count = if now < core.deadline {
            core.before_queries
        } else {
            core.after_queries
        };
        if !core.unresolved()
            || core.pending.is_some()
            || now < core.next_query_at
            || now >= core.observation_until
            || count >= limit
            || !core.accepted && now < s.origin.grant_expires_at
        {
            return Ok(false);
        }
        let query = self
            .store
            .reserve_query(QueryKind::Observe, self.clock.now_ms())
            .await?;
        let from = self.clock.now_ms();
        if from >= query.slot.expires_at {
            self.store.expire_query(from).await?;
            return Ok(true);
        }
        let result = tokio::time::timeout(
            Duration::from_millis((query.slot.expires_at - from) as u64),
            self.collector.collect(),
        )
        .await;
        match result {
            Ok(Ok(bundle)) => {
                if let Err(error) = self
                    .store
                    .observe_now(&query, bundle, self.clock.as_ref())
                    .await
                {
                    let _ = self
                        .store
                        .unavailable(&query, self.clock.now_ms(), "malformed")
                        .await;
                    return Err(error);
                }
            }
            failure => {
                let error = match failure {
                    Ok(Err(error)) => error,
                    Err(_) => Error::Unavailable(
                        "managed aggregate capture exceeded its original slot".into(),
                    ),
                    _ => unreachable!(),
                };
                // If the independent timer already expired this exact slot it
                // remains consumed. No fallback read or replacement claim.
                if self.clock.now_ms() >= query.slot.expires_at {
                    self.store.expire_query(self.clock.now_ms()).await?;
                } else {
                    self.store
                        .unavailable(&query, self.clock.now_ms(), "transport")
                        .await?;
                }
                return Err(error);
            }
        }
        Ok(true)
    }
    pub async fn status(&self) -> Result<Option<crate::managed_drain_journal::Core>> {
        self.store.escalate(self.clock.now_ms()).await
    }
    pub async fn run(
        self: Arc<Self>,
        delivery: Arc<crate::managed_drain_delivery::Worker>,
    ) -> Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        let timer = self.clone();
        tasks.spawn(async move {
            let mut last = None;
            loop {
                log_result("deadline", timer.deadline().await, &mut last);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        let observer = self.clone();
        tasks.spawn(async move {
            let mut last = None;
            loop {
                log_result(
                    "observation",
                    observer.observe().await.map(|_| ()),
                    &mut last,
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        tasks.spawn(async move {
            let mut last = None;
            loop {
                log_result(
                    "incident delivery",
                    delivery.tick().await.map(|_| ()),
                    &mut last,
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        tokio::select! {
            _ = tasks.join_next() => {
                tasks.abort_all();
                Err(Error::Unavailable("managed supervisor worker terminated; original slots remain consumed".into()))
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Ok(())
            }
        }
    }
}
fn log_result(stage: &str, result: Result<()>, last: &mut Option<String>) {
    match result {
        Ok(()) => *last = None,
        Err(error) => {
            let message = error.to_string();
            if last.as_ref() != Some(&message) {
                eprintln!("managed supervisor {stage} retains original state: {message}");
                *last = Some(message);
            }
        }
    }
}
