use clap::Parser;
use kedgeflow::{error::Result, governance_config::GovernanceConfig, server, tls};
use std::path::PathBuf;
#[derive(Parser)]
#[command(version, about = "Draft KedgeFlow administrative control service")]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, conflicts_with = "print_registration")]
    check: bool,
    #[arg(long)]
    print_registration: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let c = GovernanceConfig::decode(&tokio::fs::read(args.config).await?)?;
    if args.print_registration {
        println!(
            "{}",
            serde_json::to_string_pretty(&c.trust()?.registration)?
        );
        return Ok(());
    }
    let tls = tls::server_config(
        &c.control.certificate,
        &c.control.private_key,
        &c.control.workload_ca,
    )?;
    let service = c.service().await?;
    if args.check {
        println!("administrative material validated; no authority state was probed or published");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(c.listen).await?;
    server::serve_router(listener, tls, service.router()).await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-governance: {e}");
        std::process::exit(1);
    }
}
