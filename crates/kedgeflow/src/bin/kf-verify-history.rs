use clap::Parser;
use kedgeflow::{
    control_history::ControlHistoryBundle,
    control_history_config::ControlHistoryTrustConfig,
    control_history_verify::verify_control_history,
    error::{Error, Result},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Offline observer-attested governance and admission history verifier"
)]
struct Arguments {
    #[arg(long)]
    trust: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
}
fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > limit {
        return Err(Error::Invalid("offline artifact exceeds bound".into()));
    }
    Ok(raw)
}
fn run() -> Result<()> {
    let args = Arguments::parse();
    let trust =
        ControlHistoryTrustConfig::decode(&bounded_read(&args.trust, 4 << 20)?)?.registration()?;
    let bundle = ControlHistoryBundle::decode(&bounded_read(&args.bundle, 32 << 20)?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&verify_control_history(&bundle, &trust)?)?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-history: {e}");
        std::process::exit(1);
    }
}
