use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    recovery_config::RecoveryConfig,
};
use kedgeflow::{file_custody::Material, service_files::ServiceFiles};
use std::{path::PathBuf, time::Duration};
#[derive(Parser)]
#[command(
    version,
    about = "Query-only draft recovery worker; never dispatches or restores authority"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Confine configuration, credentials, TLS and witness material to this root.
    #[arg(long)]
    custody_root: Option<PathBuf>,
    /// Require role-appropriate managed authority and recovery controls.
    #[arg(long, requires = "custody_root")]
    require_managed: bool,
    /// Validate configuration/TLS/key material without querying or writing.
    #[arg(long)]
    check: bool,
    /// Process one bounded page, then exit. Nonzero if an entry is unavailable.
    #[arg(long, conflicts_with = "check")]
    once: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = match args.custody_root {
        Some(root) => ServiceFiles::protected(&root)?,
        None => ServiceFiles::default(),
    };
    let raw = files.read(&args.config, Material::Public, 1 << 20).await?;
    let config = RecoveryConfig::decode(&raw)?;
    if args.require_managed {
        kedgeflow::deployment::recovery(&config)?;
    }
    let worker = config.worker_with_files(&files).await?;
    let worker = std::sync::Arc::new(worker);
    let operations = match &config.operations {
        Some(operations) => Some(
            operations
                .load(&files, &config.source_id, worker.clone(), None)
                .await?,
        ),
        None => None,
    };
    if args.check {
        println!("recovery material validated; no remote query or state transition");
        return Ok(());
    }
    let _operations = if args.once {
        None
    } else {
        match operations {
            Some(listener) => Some(listener.start().await?),
            None => None,
        }
    };
    let mut cursor = None;
    let shutdown = kedgeflow::shutdown::wait();
    tokio::pin!(shutdown);
    loop {
        let sweep = {
            let page = worker.sweep(cursor.as_deref(), config.page_size);
            tokio::pin!(page);
            tokio::select! {
                result = &mut page => result,
                signal = &mut shutdown => {
                    signal?;
                    // Finish only the current query/delivery page, bounded by the
                    // service stop window. Timeout retains original durable attempts.
                    match tokio::time::timeout(Duration::from_secs(30), &mut page).await {
                        Ok(Ok(page)) => println!("{}", serde_json::to_string(&page)?),
                        _ => eprintln!("recovery stopped with original attempts retained"),
                    }
                    return Ok(());
                }
            }
        };
        match sweep {
            Ok(s) => {
                cursor = s.next_cursor.clone();
                println!("{}", serde_json::to_string(&s)?);
                if args.once {
                    return if s.unavailable == 0 {
                        Ok(())
                    } else {
                        Err(Error::Unavailable(
                            "recovery page contains unavailable entries".into(),
                        ))
                    };
                }
            }
            Err(e) => {
                if args.once {
                    return Err(e);
                }
                eprintln!("recovery authority unavailable; retrying bounded polling");
            }
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_millis(config.poll_interval_ms))=>(),signal=&mut shutdown=>{signal?;return Ok(());}}
    }
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-recover: {e}");
        std::process::exit(1);
    }
}
