use clap::Parser;
use kedgeflow::{
    compensation_target_config::Config,
    error::{Error, Result},
    server, tls,
};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Draft fixed SQL compensation target, original query and independent target barrier"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, conflicts_with = "check_database")]
    check: bool,
    #[arg(long)]
    check_database: bool,
    #[arg(long)]
    postgres_peer_uid: Option<u32>,
}
async fn run() -> Result<()> {
    let a = Args::parse();
    let bytes = tokio::fs::read(&a.config).await?;
    if bytes.len() > 1 << 20 {
        return Err(Error::Invalid("inverse configuration exceeds bound".into()));
    }
    let c = Config::decode(&bytes)?;
    let tls = tls::server_config(&c.certificate, &c.private_key, &c.workload_ca)?;
    let service = c.service(a.postgres_peer_uid).await?;
    if a.check {
        println!("inverse target material validated; no database contacted");
        return Ok(());
    }
    if a.check_database {
        c.store(a.postgres_peer_uid)?.check_database().await?;
        println!("inverse executor/query/barrier catalog checks passed; no effect authorized");
        return Ok(());
    }
    server::serve_router(
        tokio::net::TcpListener::bind(c.listen).await?,
        tls,
        service.router(),
    )
    .await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-compensation-target: {e}");
        std::process::exit(1);
    }
}
