use clap::Parser;
use kedgeflow::{error::Result, outcome_report_config::OutcomeReportConfig, server};
use kedgeflow::{file_custody::Material, service_files::ServiceFiles};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Draft retained outcome collector and signed delivery acknowledgements"
)]
struct Arguments {
    #[command(flatten)]
    operations: kedgeflow::operations::Arguments,
    #[arg(long)]
    config: PathBuf,
    /// Confine configuration, credentials, TLS and witness material to this root.
    #[arg(long)]
    custody_root: Option<PathBuf>,
    /// Require role-appropriate managed authority and recovery controls.
    #[arg(long, requires = "custody_root")]
    require_managed: bool,
    #[arg(long)]
    check: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = match args.custody_root {
        Some(root) => ServiceFiles::protected(&root)?,
        None => ServiceFiles::default(),
    };
    let config =
        OutcomeReportConfig::decode(&files.read(&args.config, Material::Public, 1 << 20).await?)?;
    if args.require_managed {
        kedgeflow::deployment::collector(&config)?;
    }
    let operations = args.operations.endpoint(
        &[&config.external_url],
        files.is_protected(),
        &[&config.source_id],
    )?;
    let tls = files
        .server_tls(
            &config.certificate,
            &config.private_key,
            &config.workload_ca,
        )
        .await?;
    let service = config.service_with_files(&files).await?;
    if args.check {
        println!("outcome collector material validated; no records queried or written");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let app = service.clone().router();
    let app = match operations {
        Some(endpoint) => endpoint.attach(app, kedgeflow::operations::Role::Collector, service),
        None => app,
    };
    server::serve_router(listener, tls, app).await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-outcomes: {e}");
        std::process::exit(1);
    }
}
