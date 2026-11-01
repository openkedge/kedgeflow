use clap::Parser;
use kedgeflow::{
    error::Result, file_custody::Material, restore::RestoreOperatorConfig,
    service_files::ServiceFiles,
};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    group(clap::ArgGroup::new("mode").args(["check", "status", "enroll_empty"]).required(true).multiple(false)),
    about = "Privileged draft restore witness check or EMPTY namespace enrollment"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Confine local configuration, TLS and authority credentials to this root.
    #[arg(long)]
    custody_root: Option<PathBuf>,
    #[arg(long, requires = "custody_root")]
    require_managed: bool,
    /// Validate local material and independent origins; no authority contact.
    #[arg(long)]
    check: bool,
    /// Query the independently retained witness and local head; writes nothing.
    #[arg(long)]
    status: bool,
    /// Reserve a fresh witness and enroll an entirely empty local namespace.
    #[arg(long)]
    enroll_empty: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = match args.custody_root {
        Some(root) => ServiceFiles::protected(&root)?,
        None => ServiceFiles::default(),
    };
    let raw = files.read(&args.config, Material::Public, 1 << 20).await?;
    let c = RestoreOperatorConfig::decode(&raw)?;
    let ledger = c.ledger_with_files(&files).await?;
    let gate = c.restore_gate.gate_with_files(&files).await?;
    // Validate independent failure domains without reading or writing authority.
    let _validated = ledger.clone().with_restore_gate(gate.clone())?;
    if args.check {
        println!("restore operator material validated; no authority state read or written");
        return Ok(());
    }
    let head = if args.enroll_empty {
        gate.enroll_empty(&ledger).await?
    } else {
        gate.check(&ledger).await?
    };
    println!("{}", serde_json::to_string(&head)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-restore: {e}");
        std::process::exit(1);
    }
}
