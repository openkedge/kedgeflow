use clap::Parser;
use kedgeflow::{error::Result, outcome_report_config::OutcomeReportConfig, server, tls};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Draft retained outcome collector and signed delivery acknowledgements"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let config = OutcomeReportConfig::decode(&tokio::fs::read(args.config).await?)?;
    let tls = tls::server_config(
        &config.certificate,
        &config.private_key,
        &config.workload_ca,
    )?;
    let service = config.service().await?;
    if args.check {
        println!("outcome collector material validated; no records queried or written");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    server::serve_router(listener, tls, service.router()).await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-outcomes: {e}");
        std::process::exit(1);
    }
}
