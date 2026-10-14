use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    review_config::LoadedReview,
    server,
};
use std::path::PathBuf;
#[derive(Parser)]
#[command(version, about = "Draft protected native review evidence provider")]
struct Arguments {
    #[arg(long, required_unless_present = "print_template_digest")]
    config: Option<PathBuf>,
    #[arg(long, required_unless_present = "print_template_digest")]
    custody_root: Option<PathBuf>,
    #[arg(long,conflicts_with_all=["config","custody_root","check","enroll","revoke"])]
    print_template_digest: bool,
    #[arg(long,conflicts_with_all=["enroll","revoke"])]
    check: bool,
    #[arg(long, conflicts_with = "revoke")]
    enroll: bool,
    #[arg(long)]
    revoke: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    if args.print_template_digest {
        println!("{}", kedgeflow::review_evidence::template_digest()?);
        return Ok(());
    }
    let loaded = LoadedReview::load(
        args.custody_root
            .as_deref()
            .ok_or_else(|| Error::Invalid("missing review custody root".into()))?,
        args.config
            .as_deref()
            .ok_or_else(|| Error::Invalid("missing review config".into()))?,
    )?;
    if args.check {
        println!("review material validated; no listener, enrollment or remote operation");
        return Ok(());
    }
    if args.enroll || args.revoke {
        for enrollment in loaded.config.registration.rule.credentials.values() {
            if args.enroll {
                loaded.ledger.enroll_review(enrollment.clone()).await?;
            } else {
                loaded
                    .ledger
                    .revoke_review(&enrollment.credential_id)
                    .await?;
            }
        }
        println!("configured review enrollment operation completed");
        return Ok(());
    }
    server::serve_router(
        tokio::net::TcpListener::bind(loaded.config.listen).await?,
        loaded.tls,
        loaded.service.router(),
    )
    .await
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("kf-review: {error}");
        std::process::exit(1);
    }
}
