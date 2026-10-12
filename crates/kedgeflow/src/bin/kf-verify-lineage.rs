use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    lineage::{LineageBundle, verify_lineage},
    lineage_config::LineageTrustConfig,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Offline historical admission and outcome lineage verifier"
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
    let trust = LineageTrustConfig::decode(&bounded_read(&args.trust, 1 << 20)?)?.registration()?;
    let bundle = LineageBundle::decode(&bounded_read(&args.bundle, 16 << 20)?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&verify_lineage(&bundle, &trust)?)?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-lineage: {e}");
        std::process::exit(1);
    }
}
