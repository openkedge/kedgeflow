use clap::{Parser, Subcommand};
use kedgeflow::{
    error::{Error, Result},
    kube_drain_config::Config,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
#[derive(Parser)]
#[command(
    version,
    about = "Protected Level C drain controller; acceptance and physical completion are separate"
)]
struct Args {
    #[arg(long)]
    material_root: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    operation: Operation,
}
#[derive(Subcommand)]
enum Operation {
    Check,
    State,
    Advance,
    CloseUnstarted,
    CloseAbsent {
        #[arg(long)]
        signed_grant: PathBuf,
        #[arg(long)]
        attempt: String,
    },
    Serve,
}
async fn run() -> Result<()> {
    let a = Args::parse();
    let loaded = Config::load(&a.material_root, &a.config).await?;
    let c = loaded.controller;
    match a.operation {
        Operation::Check => println!(
            "{}",
            serde_json::json!({"validated":true,"physical_mutation":false,"execution_authority":false})
        ),
        Operation::State => println!("{}", serde_json::to_string_pretty(&c.state().await?)?),
        Operation::Advance => println!("{}", serde_json::to_string_pretty(&c.advance().await?)?),
        Operation::CloseUnstarted => println!(
            "{}",
            serde_json::to_string_pretty(&c.close_unstarted().await?)?
        ),
        Operation::CloseAbsent {
            signed_grant,
            attempt,
        } => {
            let raw = std::fs::read(signed_grant)?;
            if raw.len() > 1 << 20 {
                return Err(Error::Invalid("original grant exceeds bound".into()));
            }
            let raw =
                String::from_utf8(raw).map_err(|_| Error::Invalid("original grant UTF8".into()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&c.close_absent(&raw, &attempt).await?)?
            );
        }
        Operation::Serve => {
            let service = Arc::new(kedgeflow::kube_drain_http::Service::new(
                c.clone(),
                &loaded.config.dispatch_url,
                &loaded.config.query_url,
                loaded.config.gateway_workload.clone(),
                loaded.config.query_workload.clone(),
                &loaded.query_token,
            )?);
            let worker = tokio::spawn(async move {
                let mut last_error = None;
                loop {
                    let result = async {
                        if c.state().await?.is_some() {
                            c.advance().await?;
                        }
                        Ok::<(), Error>(())
                    }
                    .await;
                    match result {
                        Ok(()) => last_error = None,
                        Err(e) => {
                            let message = e.to_string();
                            if last_error.as_ref() != Some(&message) {
                                eprintln!("drain worker retains original state: {message}");
                                last_error = Some(message);
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
            let result = kedgeflow::server::serve_router(
                tokio::net::TcpListener::bind(loaded.config.listen).await?,
                loaded.tls,
                service.router(),
            )
            .await;
            worker.abort();
            result?;
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-kube-drain: {e}");
        std::process::exit(1);
    }
}
