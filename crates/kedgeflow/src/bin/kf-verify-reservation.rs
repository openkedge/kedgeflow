use clap::Parser;
use kedgeflow::{
    contracts::strict_value,
    error::{Error, Result},
    reserved_leaf::{Registration, verify_binding},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Offline issuer reservation statement verifier; no live authority"
)]
struct Arguments {
    /// Independently approved public registration; never inferred from the binding.
    #[arg(long)]
    registration: PathBuf,
    #[arg(long)]
    grant: PathBuf,
    #[arg(long)]
    binding: PathBuf,
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > limit {
        return Err(Error::Invalid("reservation artifact exceeds bound".into()));
    }
    Ok(raw)
}
fn run() -> Result<()> {
    let args = Arguments::parse();
    let registration: Registration =
        serde_json::from_value(strict_value(&read(&args.registration, 128 << 10)?)?)?;
    let payload = verify_binding(
        &read(&args.binding, 16384)?,
        &registration,
        &read(&args.grant, 1 << 20)?,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"profile":if registration.hierarchy.is_some(){kedgeflow::hierarchical_leaf::PROFILE}else{kedgeflow::reserved_leaf::PROFILE},"historical_issuer_statement":payload,"execution_authority":false,"live_budget_verified":false})
        )?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-reservation: {e}");
        std::process::exit(1);
    }
}
