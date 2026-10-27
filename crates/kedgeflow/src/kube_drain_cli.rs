//! Commands shared by the explicit mechanical and managed controller binaries.
use crate::error::{Error, Result};
use clap::{Parser, Subcommand};
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
/// Shared operations; only the named managed binary selects the managed loader.
pub async fn run(managed: bool) -> Result<()> {
    let a = Args::parse();
    let loaded = if managed {
        crate::managed_drain_controller_config::Config::load(&a.material_root, &a.config).await?
    } else {
        crate::kube_drain_config::Config::load(&a.material_root, &a.config).await?
    };
    let c = loaded.controller;
    match a.operation {
        Operation::Check => {
            let mut value = serde_json::json!({"validated":true,"physical_mutation":false,"execution_authority":false});
            if managed {
                value["profile"] = serde_json::json!(crate::managed_drain::PROFILE);
            }
            println!("{value}");
        }
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
            let raw = if managed {
                crate::postgres_custody::Root::open(&a.material_root)?.read(
                    &signed_grant,
                    crate::postgres_custody::Material::Public,
                    1 << 20,
                )?
            } else {
                std::fs::read(signed_grant)?
            };
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
            let service = Arc::new(crate::kube_drain_http::Service::new(
                c.clone(),
                &loaded.config.dispatch_url,
                &loaded.config.query_url,
                loaded.config.gateway_workload.clone(),
                loaded.config.query_workload.clone(),
                &loaded.query_token,
            )?);
            // Deadline retention cannot wait for inventory/API work in the mutation
            // worker. Both tasks use the same expected-head native operating CAS.
            let timer_controller = c.clone();
            let deadline_timer = c.managed().then(|| {
                tokio::spawn(async move {
                    let mut last_error = None;
                    loop {
                        match timer_controller.managed_tick().await {
                            Ok(()) => last_error = None,
                            Err(e) => {
                                let message = e.to_string();
                                if last_error.as_ref() != Some(&message) {
                                    eprintln!(
                                        "managed drain deadline retention unavailable: {message}"
                                    );
                                    last_error = Some(message);
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                })
            });
            let worker = tokio::spawn(async move {
                let mut last_error = None;
                loop {
                    let result = async {
                        c.scheduled_advance().await?;
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
            let result = crate::server::serve_router(
                tokio::net::TcpListener::bind(loaded.config.listen).await?,
                loaded.tls,
                service.router(),
            )
            .await;
            worker.abort();
            if let Some(timer) = deadline_timer {
                timer.abort();
            }
            result?;
        }
    }
    Ok(())
}
