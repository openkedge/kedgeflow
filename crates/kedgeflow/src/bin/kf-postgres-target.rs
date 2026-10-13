use clap::Parser;
use kedgeflow::{error::Result, postgres_config::PostgresTargetConfig, server, tls};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Draft authenticated PostgreSQL reservation target and retained query"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let config = PostgresTargetConfig::decode(&tokio::fs::read(args.config).await?)?;
    let tls = tls::server_config(
        &config.certificate,
        &config.private_key,
        &config.workload_ca,
    )?;
    let service = config.service().await?;
    if args.check {
        println!("SQL target material validated; no database contacted or effect authorized");
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
        eprintln!("kf-postgres-target: {e}");
        std::process::exit(1);
    }
}
