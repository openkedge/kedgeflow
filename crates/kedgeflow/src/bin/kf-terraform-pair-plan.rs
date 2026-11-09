use clap::Parser;
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Inspect one protected two-resource Terraform plan; never applies it"
)]
struct Arguments {
    #[arg(long)]
    material_root: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
}
#[tokio::main]
async fn main() {
    let args = Arguments::parse();
    match kedgeflow::terraform_pair::inspect(&args.material_root, &args.manifest).await {
        Ok(report) => println!(
            "{}",
            serde_json::to_string(&report).expect("serializable inspection")
        ),
        Err(error) => {
            eprintln!("kf-terraform-pair-plan: {error}");
            std::process::exit(1);
        }
    }
}
