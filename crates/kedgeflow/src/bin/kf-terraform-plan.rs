use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Inspect one protected saved Terraform plan; never applies it"
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
    match kedgeflow::terraform_plan::inspect(&args.material_root, &args.manifest).await {
        Ok(result) => println!(
            "{}",
            serde_json::to_string(&result).expect("serializable inspection")
        ),
        Err(error) => {
            eprintln!("kf-terraform-plan: {error}");
            std::process::exit(1);
        }
    }
}
