use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Protected original-attempt two-resource Terraform apply/query; no automatic retries"
)]
struct Arguments {
    #[arg(long)]
    material_root: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Execute {
        #[arg(long)]
        request: PathBuf,
    },
    Query {
        #[arg(long)]
        attempt_id: String,
    },
}
#[cfg(unix)]
async fn run() -> kedgeflow::error::Result<()> {
    use kedgeflow::{
        contracts::strict_value,
        file_custody::{Material, Root},
        terraform_apply::Request,
    };
    let args = Arguments::parse();
    let runner = kedgeflow::terraform_pair_apply::load(&args.material_root, &args.config).await?;
    let report = match args.command {
        Command::Execute { request } => {
            let root = Root::open(&args.material_root)?;
            let value: Request = serde_json::from_value(strict_value(&root.read(
                &request,
                Material::Secret,
                2 << 20,
            )?)?)?;
            runner.execute(&value).await?
        }
        Command::Query { attempt_id } => runner.status(&attempt_id).await?,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    #[cfg(unix)]
    if let Err(error) = run().await {
        eprintln!("kf-terraform-pair-apply: {error}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        eprintln!("kf-terraform-pair-apply: Unix custody required");
        std::process::exit(1);
    }
}
