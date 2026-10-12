use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    recovery_config::RecoveryConfig,
};
use std::{path::PathBuf, time::Duration};
#[derive(Parser)]
#[command(
    version,
    about = "Query-only draft recovery worker; never dispatches or restores authority"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Validate configuration/TLS/key material without querying or writing.
    #[arg(long)]
    check: bool,
    /// Process one bounded page, then exit. Nonzero if an entry is unavailable.
    #[arg(long, conflicts_with = "check")]
    once: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let raw = tokio::fs::read(args.config).await?;
    let config = RecoveryConfig::decode(&raw)?;
    let worker = config.worker().await?;
    if args.check {
        println!("recovery material validated; no remote query or state transition");
        return Ok(());
    }
    let mut cursor = None;
    loop {
        let sweep = tokio::select! {s=worker.sweep(cursor.as_deref(),config.page_size)=>s,signal=tokio::signal::ctrl_c()=>{signal?;return Ok(());}};
        match sweep {
            Ok(s) => {
                cursor = s.next_cursor.clone();
                println!("{}", serde_json::to_string(&s)?);
                if args.once {
                    return if s.unavailable == 0 {
                        Ok(())
                    } else {
                        Err(Error::Unavailable(
                            "recovery page contains unavailable entries".into(),
                        ))
                    };
                }
            }
            Err(e) => {
                if args.once {
                    return Err(e);
                }
                eprintln!("recovery authority unavailable; retrying bounded polling");
            }
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_millis(config.poll_interval_ms))=>(),signal=tokio::signal::ctrl_c()=>{signal?;return Ok(());}}
    }
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-recover: {e}");
        std::process::exit(1);
    }
}
