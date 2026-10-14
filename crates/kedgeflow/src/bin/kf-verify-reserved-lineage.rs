use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    reservation_history::MAX_BUNDLE,
    reserved_lineage::{Bundle, TrustConfig, verify},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Offline reserved admission/outcome/budget history verifier; no execution authority"
)]
struct Arguments {
    #[arg(long)]
    trust: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
}
fn read(p: &Path, n: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    std::fs::File::open(p)?
        .take(n as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > n {
        return Err(Error::Invalid(
            "reserved audit artifact exceeds bound".into(),
        ));
    }
    Ok(raw)
}
fn run() -> Result<()> {
    let a = Arguments::parse();
    let t = TrustConfig::decode(&read(&a.trust, 1 << 20)?)?.registration()?;
    let b = Bundle::decode(&read(&a.bundle, MAX_BUNDLE)?)?;
    println!("{}", serde_json::to_string_pretty(&verify(&b, &t)?)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-reserved-lineage: {e}");
        std::process::exit(1);
    }
}
