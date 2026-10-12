use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    supervision_config::SupervisionConfig,
};
use std::{path::PathBuf, time::Duration};
#[derive(Parser)]
#[command(
    version,
    about = "Owned unknown incidents and ordered retained delivery; query-only recovery"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Validate enrollment/TLS/key material; no remote reads, writes or reporting.
    #[arg(long)]
    check: bool,
    /// Process one bounded page and exit nonzero if an entry is unavailable.
    #[arg(long, conflicts_with = "check")]
    once: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let raw = tokio::fs::read(args.config).await?;
    let config = SupervisionConfig::decode(&raw)?;
    let supervisor = config.supervisor().await?;
    if args.check {
        println!("supervisor material validated; no remote transition or delivery");
        return Ok(());
    }
    let mut cursor = None;
    loop {
        let sweep = tokio::select! {s=supervisor.sweep(cursor.as_deref(),config.recovery.page_size)=>s,signal=tokio::signal::ctrl_c()=>{signal?;return Ok(());}};
        match sweep {
            Ok(s) => {
                cursor = s.next_cursor.clone();
                println!("{}", serde_json::to_string(&s)?);
                if args.once {
                    return if s.unavailable == 0 {
                        Ok(())
                    } else {
                        Err(Error::Unavailable(
                            "supervision page contains unavailable entries".into(),
                        ))
                    };
                }
            }
            Err(e) => {
                if args.once {
                    return Err(e);
                }
                eprintln!("supervision authority unavailable; retaining ownership and progress");
            }
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_millis(config.recovery.poll_interval_ms))=>(),signal=tokio::signal::ctrl_c()=>{signal?;return Ok(());}}
    }
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-supervise: {e}");
        std::process::exit(1);
    }
}
