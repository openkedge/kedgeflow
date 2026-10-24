use clap::Parser;
use kedgeflow::{
    error::Result,
    physical_operations::{Bundle, MAX_BYTES, Trust},
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Offline RFC 0056 operating-history verification; no execution authority"
)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    trust: PathBuf,
}
fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take(bound as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > bound {
        return Err(kedgeflow::error::Error::Invalid(
            "operating artifact exceeds bound".into(),
        ));
    }
    Ok(raw)
}
fn run() -> Result<()> {
    let args = Args::parse();
    let bundle = Bundle::decode(&read(&args.bundle, MAX_BYTES)?)?;
    let trust = Trust::decode(&read(&args.trust, 2 << 20)?)?;
    println!("{}", serde_json::to_string_pretty(&bundle.verify(&trust)?)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
