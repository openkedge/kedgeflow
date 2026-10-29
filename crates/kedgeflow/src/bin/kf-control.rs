use clap::Parser;
use kedgeflow::{control_config::ControlConfig, error::Result, server, tls};
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    group(clap::ArgGroup::new("mode").args(["check","print_pins","enroll_lease_members","withdraw_lease_members","replace_lease_members","enroll_reservation","stop_reservation","print_a2a_extension","enroll_a2a_root","withdraw_a2a_root"]).multiple(false)),
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
    /// Print an extension fragment for an existing A2A peer; no core task server.
    #[arg(long)]
    print_a2a_extension: bool,
    /// Privileged create-only reader ACL enrollment for the existing root.
    #[arg(long)]
    enroll_a2a_root: bool,
    /// Permanently withdraw the configured root reader ACL.
    #[arg(long)]
    withdraw_a2a_root: bool,
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
    if args.print_a2a_extension {
        config.registration()?;
        let r = config
            .a2a
            .as_ref()
            .ok_or_else(|| kedgeflow::error::Error::Invalid("A2A root not configured".into()))?;
        println!("{}", serde_json::to_string_pretty(&r.agent_extension()?)?);
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
    if args.enroll_a2a_root || args.withdraw_a2a_root {
        config.a2a_root_operation(args.withdraw_a2a_root).await?;
        println!("configured A2A reader ACL operation completed");
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
    tokio::time::timeout(Duration::from_secs(5), service.prepare_native_history())
        .await
        .map_err(|_| {
            kedgeflow::error::Error::Unavailable("control history preparation timed out".into())
        })??;
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
