use clap::Parser;
use kedgeflow::{config::Config, error::Result, server, tls};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(version, about = "Bounded KedgeFlow v0.9 Rust reference gateway")]
struct Arguments {
    /// Operator-controlled JSON configuration (never an agent-supplied file).
    #[arg(long)]
    config: PathBuf,
    /// Validate configuration and TLS/client material without listening.
    #[arg(long)]
    check: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let bytes = tokio::fs::read(&args.config).await?;
    let config = Config::decode(&bytes)?;
    let endpoint = config.validate()?;
    let tls = tls::server_config(
        &config.certificate,
        &config.private_key,
        &config.workload_ca,
    )?;
    let gateway = Arc::new(config.gateway().await?);
    if args.check {
        println!("configuration validated; remote services and authority state were not probed");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    eprintln!(
        "KedgeFlow Rust reference gateway listening on {}",
        listener.local_addr()?
    );
    server::serve(listener, tls, gateway, endpoint).await
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("kf-proxy: {error}");
        std::process::exit(1);
    }
}
