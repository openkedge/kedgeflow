use clap::Parser;
use kedgeflow::{
    broker_config::BrokerConfig, error::Result, file_custody::Material, server,
    service_files::ServiceFiles,
};
use std::{path::PathBuf, time::Duration};
#[derive(Parser)]
#[command(
    version,
    about = "Draft one-shot broker exchange with a reference target credential"
)]
struct Arguments {
    #[command(flatten)]
    operations: kedgeflow::operations::Arguments,
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    /// Confine all material, including live trust refresh, to this protected root.
    /// Requires a non-root Unix account and absolute, non-symlink paths.
    #[arg(long)]
    custody_root: Option<PathBuf>,
    /// Require managed authority, restore protection and signed identity refresh.
    #[arg(long, requires = "custody_root")]
    require_managed: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = match args.custody_root {
        Some(root) => ServiceFiles::protected(&root)?,
        None => ServiceFiles::default(),
    };
    let config = BrokerConfig::decode(&files.read(&args.config, Material::Public, 1 << 20).await?)?;
    if args.require_managed {
        kedgeflow::deployment::broker(&config)?;
    }
    let operations = args.operations.endpoint(
        &[&config.external_url],
        files.is_protected(),
        &[&config.registration.gateway_workload],
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
        println!("broker material validated; no records queried or written");
        return Ok(());
    }
    tokio::time::timeout(Duration::from_secs(5), service.prepare_native_history())
        .await
        .map_err(|_| {
            kedgeflow::error::Error::Unavailable("broker history preparation timed out".into())
        })??;
    let app = service.clone().router();
    let app = match operations {
        Some(endpoint) => endpoint.attach(app, kedgeflow::operations::Role::Broker, service),
        None => app,
    };
    server::serve_router(
        tokio::net::TcpListener::bind(config.listen).await?,
        tls,
        app,
    )
    .await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-broker: {e}");
        std::process::exit(1);
    }
}
