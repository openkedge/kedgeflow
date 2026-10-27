use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    managed_drain_audit::{Bundle, MAX_BYTES, Trust},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Independent complete managed operating/physical prefix replay; no execution authority"
)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    trust: PathBuf,
}
fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let mut b = vec![];
    std::fs::File::open(path)?
        .take(bound as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > bound {
        return Err(Error::Invalid("managed audit input exceeds bound".into()));
    }
    Ok(b)
}
fn run() -> Result<()> {
    let a = Args::parse();
    let t = Trust::decode(&read(&a.trust, 2 << 20)?)?;
    let b = Bundle::decode(&read(&a.bundle, MAX_BYTES)?)?;
    println!("{}", serde_json::to_string_pretty(&b.verify(&t)?)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-managed-drain: {e}");
        std::process::exit(1);
    }
}
