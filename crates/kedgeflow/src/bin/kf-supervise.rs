use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    supervision_config::SupervisionConfig,
};
use kedgeflow::{file_custody::Material, service_files::ServiceFiles};
use std::{path::PathBuf, time::Duration};
#[derive(Parser)]
#[command(
    version,
    about = "Owned unknown incidents and ordered retained delivery; query-only recovery"
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
    /// Validate enrollment/TLS/key material; no remote reads, writes or reporting.
    #[arg(long)]
    check: bool,
    /// Process one bounded page and exit nonzero if an entry is unavailable.
    #[arg(long, conflicts_with = "check")]
    once: bool,
    /// Read-only bounded retained backlog; never queries targets or delivers.
    #[arg(long, conflicts_with_all = ["check", "once"])]
    observe: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let files = match args.custody_root {
        Some(root) => ServiceFiles::protected(&root)?,
        None => ServiceFiles::default(),
    };
    let raw = files.read(&args.config, Material::Public, 2 << 20).await?;
    let config = SupervisionConfig::decode(&raw)?;
    if args.require_managed {
        kedgeflow::deployment::supervisor(&config)?;
    }
    let supervisor = config.supervisor_with_files(&files).await?;
    let supervisor = std::sync::Arc::new(supervisor);
    if args.observe {
        if !files.is_protected() || !args.require_managed {
            return Err(Error::Invalid(
                "backlog observation requires protected managed custody".into(),
            ));
        }
        let report = tokio::time::timeout(
            Duration::from_secs(20),
            supervisor.observe(config.recovery.page_size),
        )
        .await
        .map_err(|_| Error::Unavailable("backlog observation timed out".into()))??;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    let operations = match &config.recovery.operations {
        Some(operations) => Some(
            operations
                .load(
                    &files,
                    &config.recovery.source_id,
                    supervisor.clone(),
                    Some(&config.delivery.collector_url),
                )
                .await?,
        ),
        None => None,
    };
    if args.check {
        println!("supervisor material validated; no remote transition or delivery");
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
            let page = supervisor.sweep(cursor.as_deref(), config.recovery.page_size);
            tokio::pin!(page);
            tokio::select! {
                result = &mut page => result,
                signal = &mut shutdown => {
                    signal?;
                    // Finish only the current query/delivery page, bounded by the
                    // service stop window. Timeout retains original durable attempts.
                    match tokio::time::timeout(Duration::from_secs(30), &mut page).await {
                        Ok(Ok(page)) => println!("{}", serde_json::to_string(&page)?),
                        _ => eprintln!("supervision stopped with original attempts retained"),
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
                            "supervision page contains unavailable entries".into(),
                        ))
                    };
                }
            }
            Err(e) => {
                if args.once {
                    return Err(e);
                }
                eprintln!("supervision authority unavailable; retaining ownership and progress");
            }
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_millis(config.recovery.poll_interval_ms))=>(),signal=&mut shutdown=>{signal?;return Ok(());}}
    }
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-supervise: {e}");
        std::process::exit(1);
    }
}
