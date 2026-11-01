use clap::Parser;
use kedgeflow::{error::Result, governance_config::GovernanceConfig, server};
use kedgeflow::{file_custody::Material, service_files::ServiceFiles};
use std::path::PathBuf;
#[derive(Parser)]
#[command(version, about = "Draft KedgeFlow administrative control service")]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Confine configuration, credentials, TLS and witness material to this root.
    #[arg(long)]
    custody_root: Option<PathBuf>,
    /// Require role-appropriate managed authority and recovery controls.
    #[arg(long, requires = "custody_root")]
    require_managed: bool,
    #[arg(long, conflicts_with = "print_registration")]
    check: bool,
    #[arg(long)]
    print_registration: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = match args.custody_root {
        Some(root) => ServiceFiles::protected(&root)?,
        None => ServiceFiles::default(),
    };
    let c = GovernanceConfig::decode(&files.read(&args.config, Material::Public, 1 << 20).await?)?;
    if args.require_managed {
        kedgeflow::deployment::governance(&c)?;
    }
    if args.print_registration {
        println!(
            "{}",
            serde_json::to_string_pretty(&c.trust()?.registration)?
        );
        return Ok(());
    }
    let tls = files
        .server_tls(
            &c.control.certificate,
            &c.control.private_key,
            &c.control.workload_ca,
        )
        .await?;
    let service = c.service_with_files(&files).await?;
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
