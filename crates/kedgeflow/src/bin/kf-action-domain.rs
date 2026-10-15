use clap::{ArgGroup, Parser};
use kedgeflow::{action_domain_config::ActionDomainConfig, error::Result};
use std::{io::Read, path::PathBuf};
#[derive(Parser)]
#[command(version, about="Enroll, query or permanently stop a protected paired action domain; no inverse execution", group(ArgGroup::new("operation").required(true).multiple(false).args(["check","enroll","status","stop"])))]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    enroll: bool,
    #[arg(long)]
    status: bool,
    #[arg(long)]
    stop: bool,
}
async fn run() -> Result<()> {
    let a = Arguments::parse();
    let mut raw = vec![];
    std::fs::File::open(a.config)?
        .take((128 << 10) + 1)
        .read_to_end(&mut raw)?;
    let c = ActionDomainConfig::decode(&raw)?;
    if a.check {
        println!(
            "protected paired topology validated; no remote query or mutation; inverse_execution_available=false"
        );
        return Ok(());
    }
    let ledger = c.ledger().await?;
    if a.enroll {
        c.topology.enroll(&ledger).await?;
    }
    if a.stop {
        c.topology.stop(&ledger).await?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&c.topology.status(&ledger).await?)?
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-action-domain: {e}");
        std::process::exit(1);
    }
}
