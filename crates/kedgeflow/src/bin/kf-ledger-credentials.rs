use clap::{ArgGroup, Parser};
use kedgeflow::{
    error::Result, file_custody::Material, ledger_credentials::Config, service_files::ServiceFiles,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Issue audited, namespace-scoped etcd credentials; never print credentials")]
#[command(group(ArgGroup::new("mode").required(true).args(["check","issue"])))]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    custody_root: PathBuf,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    issue: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = ServiceFiles::protected(&args.custody_root)?;
    let config = Config::decode(&files.read(&args.config, Material::Public, 1 << 20).await?)?;
    if args.check {
        config.check(&files).await?;
        println!("credential configuration validated; no authentication or publication performed");
    } else {
        let count = config.issue(&files).await?;
        println!("credential batch staged for {count} configured principals");
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("kf-ledger-credentials: {error}");
        std::process::exit(1)
    }
}
