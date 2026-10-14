use clap::Parser;
use kedgeflow::{control_config::ControlConfig, error::Result, server, tls};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Bounded draft KedgeFlow admission and issuer service"
)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    /// Validate key/TLS/configuration material without listening or publishing.
    #[arg(long, conflicts_with = "print_pins")]
    check: bool,
    /// Print registration pins for authorized installation; publishes nothing.
    #[arg(long)]
    print_pins: bool,
    /// Privileged create-only enrollment of configured lease members.
    #[arg(long, conflicts_with_all=["check","print_pins","withdraw_lease_members","replace_lease_members"])]
    enroll_lease_members: bool,
    #[arg(long, conflicts_with_all=["check","print_pins","replace_lease_members"])]
    withdraw_lease_members: bool,
    #[arg(long, requires="expected_lease_generation", conflicts_with_all=["check","print_pins"])]
    replace_lease_members: bool,
    #[arg(long, requires = "replace_lease_members")]
    expected_lease_generation: Option<u64>,
    /// Privileged create-only enrollment of the configured native budget.
    #[arg(long, conflicts_with_all=["check","print_pins","enroll_lease_members","withdraw_lease_members","replace_lease_members","stop_reservation"])]
    enroll_reservation: bool,
    #[arg(long, conflicts_with_all=["check","print_pins","enroll_lease_members","withdraw_lease_members","replace_lease_members"])]
    stop_reservation: bool,
}
async fn run() -> Result<()> {
    let args = Arguments::parse();
    let raw = tokio::fs::read(&args.config).await?;
    let config = ControlConfig::decode(&raw)?;
    if args.print_pins {
        let (trust, _) = config.registration()?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"profile":"KF-CEDAR-LEAF-0.1-draft","policy":trust.policy,"ownership_epoch":trust.ownership_epoch,"descriptor_digest":trust.descriptor_digest,"obligation_manifest_digest":trust.obligation_manifest_digest})
            )?
        );
        return Ok(());
    }
    let tls = tls::server_config(
        &config.certificate,
        &config.private_key,
        &config.workload_ca,
    )?;
    let service = config.service().await?;
    if args.check {
        println!(
            "control material validated; no remote installation or authority state was probed"
        );
        return Ok(());
    }
    if args.enroll_reservation || args.stop_reservation {
        config.reservation_operation(args.stop_reservation).await?;
        println!("configured native reservation operation completed");
        return Ok(());
    }
    if args.enroll_lease_members || args.withdraw_lease_members || args.replace_lease_members {
        config
            .lease_members_operation(args.withdraw_lease_members, args.expected_lease_generation)
            .await?;
        println!("configured lease membership operation completed");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    eprintln!(
        "KedgeFlow draft control service listening on {}",
        listener.local_addr()?
    );
    server::serve_router(listener, tls, service.router()).await
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-control: {e}");
        std::process::exit(1);
    }
}
