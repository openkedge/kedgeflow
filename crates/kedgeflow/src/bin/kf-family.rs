use clap::{ArgGroup, Parser};
use kedgeflow::{
    error::{Error, Result},
    family::{self, AuditTrust, Bundle, Command, Config, MAX_BYTES},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(version,about="Manage signed shared-family delegation and held child contracts; never execute parent grants",group(ArgGroup::new("operation").required(true).multiple(false).args(["check","enroll","status","apply","verify","export","enroll_witness"])))]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    enroll: bool,
    #[arg(long)]
    status: bool,
    #[arg(long, requires = "command")]
    apply: bool,
    #[arg(long)]
    command: Option<PathBuf>,
    #[arg(long,requires_all=["bundle","trust"])]
    verify: bool,
    #[arg(long)]
    bundle: Option<PathBuf>,
    #[arg(long)]
    trust: Option<PathBuf>,
    #[arg(long,requires_all=["trust","observer_id","observer_key_id","observer_key"])]
    export: bool,
    #[arg(long)]
    observer_id: Option<String>,
    #[arg(long)]
    observer_key_id: Option<String>,
    #[arg(long)]
    observer_key: Option<PathBuf>,
    #[arg(long)]
    enroll_witness: bool,
}
fn read(p: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut b = vec![];
    std::fs::File::open(p)?
        .take(limit as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > limit {
        return Err(Error::Invalid("family input exceeds bound".into()));
    }
    Ok(b)
}
fn required(p: &Option<PathBuf>) -> Result<&Path> {
    p.as_deref()
        .ok_or_else(|| Error::Invalid("required family input absent".into()))
}
async fn run() -> Result<()> {
    let a = Args::parse();
    let c = Config::decode(&read(&a.config, 1 << 20)?)?;
    if a.verify {
        let b: Bundle = serde_json::from_value(kedgeflow::contracts::strict_value(&read(
            required(&a.bundle)?,
            MAX_BYTES + 16384,
        )?)?)?;
        let t: AuditTrust = serde_json::from_value(kedgeflow::contracts::strict_value(&read(
            required(&a.trust)?,
            1 << 20,
        )?)?)?;
        family::verify(&b, &t)?;
        println!("{{\"verified\":true,\"execution_authority\":false}}");
        return Ok(());
    }
    let family = c.family().await?;
    if a.check {
        println!(
            "family configuration validated; no remote query or mutation; parent_execution=false"
        );
        return Ok(());
    }
    if a.enroll_witness {
        let g = c
            .restore_gate
            .as_ref()
            .ok_or_else(|| Error::Invalid("restore gate required".into()))?
            .gate()
            .await?;
        g.enroll_empty(&c.ledger().await?).await?;
        println!("{{\"enrolled_witness\":true}}");
        return Ok(());
    }
    let value = if a.enroll {
        family.enroll().await?;
        serde_json::json!({"enrolled":true,"parent_execution":false})
    } else if a.apply {
        serde_json::to_value(
            family
                .apply(Command::decode(&read(required(&a.command)?, 16 << 10)?)?)
                .await?,
        )?
    } else if a.export {
        let trust: AuditTrust = serde_json::from_value(kedgeflow::contracts::strict_value(
            &read(required(&a.trust)?, 1 << 20)?,
        )?)?;
        let observer = family::observer_from_file(
            a.observer_id.unwrap(),
            a.observer_key_id.unwrap(),
            required(&a.observer_key)?,
        )
        .await?;
        serde_json::to_value(family.export(&observer, &trust).await?)?
    } else {
        serde_json::to_value(family.status().await?)?
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
