use clap::Parser;
use kedgeflow::{control_config::ControlConfig, error::Result, server, tls};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Bounded draft KedgeFlow admission and issuer service"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Validate key/TLS/configuration material without listening or publishing.
    #[arg(long, conflicts_with = "print_pins")]
    check: bool,
    /// Print registration pins for authorized installation; publishes nothing.
    #[arg(long)]
    print_pins: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let raw = tokio::fs::read(&args.config).await?;
    let config = ControlConfig::decode(&raw)?;
    if args.print_pins {
        let (trust, _) = config.registration()?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"profile":"KF-CEDAR-LEAF-0.1-draft","policy":trust.policy,"ownership_epoch":trust.ownership_epoch,"descriptor_digest":trust.descriptor_digest,"obligation_manifest_digest":trust.obligation_manifest_digest})
            )?
        );
        return Ok(());
    }
    let tls = tls::server_config(
        &config.certificate,
        &config.private_key,
        &config.workload_ca,
    )?;
    let service = config.service().await?;
    if args.check {
        println!(
            "control material validated; no remote installation or authority state was probed"
        );
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    eprintln!(
        "KedgeFlow draft control service listening on {}",
        listener.local_addr()?
    );
    server::serve_router(listener, tls, service.router()).await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-control: {e}");
        std::process::exit(1);
    }
}
