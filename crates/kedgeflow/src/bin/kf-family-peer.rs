use clap::Parser;
use kedgeflow::{error::Result, family_peer::Config, server, tls};
use std::{io::Read, path::PathBuf};
#[derive(Parser)]
#[command(
    version,
    about = "Bounded A2A v1 JSON-RPC family coordination peer; tasks confer no target authority"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    /// Validate protected local material without probing authority or listening.
    #[arg(long)]
    check: bool,
}
async fn run() -> Result<()> {
    let args = Args::parse();
    let mut raw = Vec::new();
    std::fs::File::open(args.config)?
        .take((1 << 20) + 1)
        .read_to_end(&mut raw)?;
    let c = Config::decode(&raw)?;
    let tls = tls::server_config(&c.certificate, &c.private_key, &c.workload_ca)?;
    let service = c.service().await?;
    if args.check {
        println!("A2A family peer material validated; no remote query, mutation or listener");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(c.listen).await?;
    server::serve_router(listener, tls, service.router()).await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-family-peer: {e}");
        std::process::exit(1)
    }
}
