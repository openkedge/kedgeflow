use clap::{Parser, Subcommand};
use kedgeflow::{current_reservation_config::Config, error::Result};
use std::{path::PathBuf, sync::Arc};
#[derive(Parser)]
#[command(
    version,
    about = "Protected one-use read-only original/current SQL reservation evidence"
)]
struct Args {
    #[arg(long)]
    material_root: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    operation: Operation,
}
#[derive(Subcommand)]
enum Operation {
    Check,
    Serve,
}
async fn run() -> Result<()> {
    let args = Args::parse();
    let loaded = Config::load(&args.material_root, &args.config).await?;
    match args.operation {
        Operation::Check => println!(
            "{}",
            serde_json::json!({"validated":true,"profile":kedgeflow::current_reservation::PROFILE,"source":"read_only_current_sql","execution_authority":false,"managed_physical_enablement":false})
        ),
        Operation::Serve => {
            let service = Arc::new(kedgeflow::current_reservation_service::Service::new(
                loaded.provider,
                &loaded.query_token,
                &loaded.evidence_token,
            )?);
            kedgeflow::server::serve_router(
                tokio::net::TcpListener::bind(loaded.config.listen).await?,
                loaded.tls,
                service.router(),
            )
            .await?;
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("kf-current-reservation: {error}");
        std::process::exit(1);
    }
}
