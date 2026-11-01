use clap::Parser;
use kedgeflow::{
    config::Config, error::Result, file_custody::Material, server, service_files::ServiceFiles,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(version, about = "Bounded KedgeFlow v0.9 Rust reference gateway")]
struct Arguments {
    #[command(flatten)]
    operations: kedgeflow::operations::Arguments,
    /// Operator-controlled JSON configuration (never an agent-supplied file).
    #[arg(long)]
    config: PathBuf,
    /// Confine startup and live assertion/acknowledgement material to this root.
    #[arg(long)]
    custody_root: Option<PathBuf>,
    /// Require managed control, shared proof consumption and restore protection.
    #[arg(long, requires = "custody_root")]
    require_managed: bool,
    /// Validate configuration and TLS/client material without listening.
    #[arg(long)]
    check: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = match args.custody_root {
        Some(root) => ServiceFiles::protected(&root)?,
        None => ServiceFiles::default(),
    };
    let bytes = files.read(&args.config, Material::Public, 1 << 20).await?;
    let config = Config::decode(&bytes)?;
    if args.require_managed {
        kedgeflow::deployment::gateway(&config)?;
    }
    let endpoint = config.validate()?;
    let operations = args.operations.endpoint(
        &[&config.external_url],
        files.is_protected(),
        &[&config.actor_workload],
    )?;
    let tls = files
        .server_tls(
            &config.certificate,
            &config.private_key,
            &config.workload_ca,
        )
        .await?;
    let gateway = Arc::new(config.gateway_with_files(&files).await?);
    let probe = Arc::new(
        kedgeflow::operations_gateway::GatewayProbe::load(&config, &files, gateway.clone()).await?,
    );
    if args.check {
        println!("configuration validated; remote services and authority state were not probed");
        return Ok(());
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), gateway.adapter.prepare())
        .await
        .map_err(|_| {
            kedgeflow::error::Error::Unavailable("adapter startup preparation timed out".into())
        })??;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    eprintln!(
        "KedgeFlow Rust reference gateway listening on {}",
        listener.local_addr()?
    );
    // A check-only invocation never publishes an acknowledgement. A running
    // enrolled gateway verifies the installed signer/scope before activation.
    let _renewal = if config.enforcement.is_some() {
        let mut interval = config
            .acknowledge_installation_with_files(&kedgeflow::clock::SystemClock, &files)
            .await?;
        let config = Arc::new(config);
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match config
                    .acknowledge_installation_with_files(&kedgeflow::clock::SystemClock, &files)
                    .await
                {
                    Ok(next) => interval = next,
                    Err(error) => eprintln!("gateway control renewal failed: {error}"),
                }
            }
        }))
    } else {
        None
    };
    gateway.validate()?;
    let app = server::router(gateway, endpoint);
    let app = match operations {
        Some(operations) => operations.attach(app, kedgeflow::operations::Role::Gateway, probe),
        None => app,
    };
    server::serve_router(listener, tls, app).await
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("kf-proxy: {error}");
        std::process::exit(1);
    }
}
