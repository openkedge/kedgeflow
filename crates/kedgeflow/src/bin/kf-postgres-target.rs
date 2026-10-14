use clap::Parser;
use kedgeflow::{
    error::Result, postgres_config::PostgresTargetConfig, postgres_custody::LoadedTarget,
    postgres_store::PostgresStore, server, tls,
};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Draft authenticated PostgreSQL reservation target and retained query"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    /// Contact both fixed SQL roles and read enrollment catalogs; no listener/effect.
    #[arg(long, conflicts_with = "check")]
    check_database: bool,
    /// Explicit descriptor/mode file custody root; never selected by a request.
    #[arg(long)]
    custody_root: Option<PathBuf>,
    /// Pin database kernel peer UID before sending SQL authentication bytes.
    #[arg(long, requires = "custody_root")]
    postgres_peer_uid: Option<u32>,
    /// Check protected local files only; requires explicit custody mode.
    #[arg(long,requires="custody_root",conflicts_with_all=["check","check_database"])]
    check_custody: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let (config, tls, service, custody_uid) = if let Some(root) = &args.custody_root {
        let loaded = LoadedTarget::load_with_peer(root, &args.config, args.postgres_peer_uid)?;
        (
            loaded.config,
            loaded.tls,
            loaded.service,
            Some(loaded.effective_uid),
        )
    } else {
        let config = PostgresTargetConfig::decode(&tokio::fs::read(&args.config).await?)?;
        let tls = tls::server_config(
            &config.certificate,
            &config.private_key,
            &config.workload_ca,
        )?;
        let service = config.service().await?;
        (config, tls, service, None)
    };
    if args.check_custody {
        println!(
            "{}",
            serde_json::json!({"profile":kedgeflow::postgres_custody::PROFILE,"operation":"check_custody","effective_uid":custody_uid.expect("clap requires custody root"),"files_checked":5,"status":"passed","scope":"uid_mode_descriptor_snapshot"})
        );
        return Ok(());
    }
    if args.check {
        println!("SQL target material validated; no database contacted or effect authorized");
        return Ok(());
    }
    if args.check_database {
        let store = PostgresStore::new(config.database.clone())?;
        let store = if let Some(uid) = args.postgres_peer_uid {
            store.with_peer_uid(uid)?
        } else {
            store
        };
        let report = store.check_database().await?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    server::serve_router(
        tokio::net::TcpListener::bind(config.listen).await?,
        tls,
        service.router(),
    )
    .await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-postgres-target: {e}");
        std::process::exit(1);
    }
}
