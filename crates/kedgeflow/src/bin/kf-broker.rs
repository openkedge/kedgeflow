use clap::Parser;
use kedgeflow::{broker_config::BrokerConfig, error::Result, server, tls};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Draft one-shot broker exchange with a reference target credential"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let config = BrokerConfig::decode(&tokio::fs::read(args.config).await?)?;
    let tls = tls::server_config(
        &config.certificate,
        &config.private_key,
        &config.workload_ca,
    )?;
    let service = config.service().await?;
    if args.check {
        println!("broker material validated; no records queried or written");
        return Ok(());
    }
    server::serve_router(
        tokio::net::TcpListener::bind(config.listen).await?,
        tls,
        service.router(),
    )
    .await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-broker: {e}");
        std::process::exit(1);
    }
}
