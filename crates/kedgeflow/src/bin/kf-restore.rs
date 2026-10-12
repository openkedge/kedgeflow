use clap::Parser;
use kedgeflow::{error::Result, restore::RestoreOperatorConfig};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Privileged draft restore witness check or EMPTY namespace enrollment"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Query the independently retained witness and local head; writes nothing.
    #[arg(
        long,
        required_unless_present = "enroll_empty",
        conflicts_with = "enroll_empty"
    )]
    status: bool,
    /// Reserve a fresh witness and enroll an entirely empty local namespace.
    #[arg(long)]
    enroll_empty: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let raw = tokio::fs::read(args.config).await?;
    let c = RestoreOperatorConfig::decode(&raw)?;
    let ledger = c.ledger().await?;
    let gate = c.restore_gate.gate().await?;
    let head = if args.enroll_empty {
        gate.enroll_empty(&ledger).await?
    } else {
        gate.check(&ledger).await?
    };
    println!("{}", serde_json::to_string(&head)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-restore: {e}");
        std::process::exit(1);
    }
}
