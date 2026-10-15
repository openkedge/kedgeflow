use clap::{ArgGroup, Parser};
use kedgeflow::{
    error::{Error, Result},
    saga_config::SagaConfig,
};
use std::{io::Read, path::PathBuf};
#[derive(Parser)]
#[command(version,about="Query-only durable saga observations; no forward or compensation execution",group(ArgGroup::new("operation").required(true).multiple(false).args(["check","enroll","once","status","history","request_compensation"])))]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    enroll: bool,
    #[arg(long)]
    once: bool,
    #[arg(long)]
    status: bool,
    #[arg(long)]
    history: bool,
    /// Record blocked inverse intent; never authorizes or executes compensation.
    #[arg(long)]
    request_compensation: bool,
}
async fn run() -> Result<()> {
    let a = Arguments::parse();
    let mut raw = vec![];
    std::fs::File::open(a.config)?
        .take((1 << 20) + 1)
        .read_to_end(&mut raw)?;
    let c = SagaConfig::decode(&raw)?;
    let observer = c.observer().await?;
    if a.check {
        println!(
            "saga observation material validated; no remote query or mutation; execution_authority=false"
        );
        return Ok(());
    }
    let value = if a.enroll {
        serde_json::to_value(observer.enroll().await?)?
    } else if a.once {
        serde_json::to_value(observer.reconcile().await?)?
    } else if a.status {
        serde_json::to_value(observer.status().await?)?
    } else if a.history {
        serde_json::to_value(observer.history().await?)?
    } else if a.request_compensation {
        serde_json::to_value(observer.request_compensation().await?)?
    } else {
        return Err(Error::Invalid("saga observation operation required".into()));
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-saga: {e}");
        std::process::exit(1);
    }
}
