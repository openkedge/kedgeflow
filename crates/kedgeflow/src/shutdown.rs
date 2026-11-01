//! Shared SIGINT/SIGTERM notification for long-running services and workers.
use crate::error::{Error, Result};

pub async fn wait() -> Result<()> {
    let refused = |_| Error::Unavailable("shutdown signal failed".into());
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(refused)?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(refused),
            result = terminate.recv() => result.map(|_| ()).ok_or_else(|| Error::Unavailable("shutdown signal closed".into())),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.map_err(refused)
}
