use clap::{Parser, Subcommand};
use kedgeflow::{error::Result, managed_drain_supervisor_config::Config};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Protected read-only physical supervisor and bounded owned incident delivery"
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
    Status,
    Tick,
    Observe,
    Deliver,
    Run,
    Export,
}
async fn run() -> Result<()> {
    let a = Args::parse();
    let loaded = Config::load(&a.material_root, &a.config).await?;
    let s = &loaded.supervisor;
    let value = match a.operation {
        Operation::Export => serde_json::to_value(loaded.auditor.export().await?)?,
        Operation::Check => {
            serde_json::json!({"validated":true,"profile":kedgeflow::managed_drain::PROFILE,"execution_authority":false,"physical_mutation":false})
        }
        Operation::Status => {
            serde_json::json!({"operating":s.status().await?,"execution_authority":false})
        }
        Operation::Tick => {
            s.deadline().await?;
            serde_json::json!({"operating":s.status().await?,"execution_authority":false})
        }
        Operation::Observe => {
            serde_json::json!({"observed":s.observe().await?,"operating":s.status().await?,"execution_authority":false})
        }
        Operation::Deliver => {
            serde_json::json!({"attempted":loaded.delivery.tick().await?,"operating":s.status().await?,"execution_authority":false})
        }
        Operation::Run => {
            loaded.supervisor.run(loaded.delivery).await?;
            return Ok(());
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-managed-drain-supervisor: {e}");
        std::process::exit(1);
    }
}
