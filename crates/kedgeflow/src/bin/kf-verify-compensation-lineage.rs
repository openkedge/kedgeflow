use clap::Parser;
use kedgeflow::{
    compensation_lineage::{Bundle, MAX_BUNDLE, TrustConfig, verify},
    error::{Error, Result},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Offline complete bounded saga/compensation lineage verifier; no execution authority"
)]
struct Arguments {
    #[arg(long)]
    trust: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
}
fn read(p: &Path, n: usize) -> Result<Vec<u8>> {
    let mut b = vec![];
    std::fs::File::open(p)?
        .take(n as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > n {
        return Err(Error::Invalid("compound audit input exceeds bound".into()));
    }
    Ok(b)
}
fn run() -> Result<()> {
    let a = Arguments::parse();
    let t = TrustConfig::decode(&read(&a.trust, 2 << 20)?)?.registration()?;
    let b = Bundle::decode(&read(&a.bundle, MAX_BUNDLE)?)?;
    println!("{}", serde_json::to_string_pretty(&verify(&b, &t)?)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-compensation-lineage: {e}");
        std::process::exit(1);
    }
}
