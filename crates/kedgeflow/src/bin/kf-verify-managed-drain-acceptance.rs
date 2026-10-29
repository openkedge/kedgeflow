use clap::Parser;
use kedgeflow::{
    error::{Error, Result},
    managed_drain_acceptance::{MAX_BYTES, Proof},
    managed_drain_audit::Trust,
    managed_drain_store::Context,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Independent historical managed acceptance-source replay; no current execution authority or physical completion"
)]
struct Args {
    #[arg(long)]
    proof: PathBuf,
    /// Independently protected managed family/child enrollment, not proof-supplied trust.
    #[arg(long)]
    trust: PathBuf,
}
fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    std::fs::File::open(path)?
        .take(bound as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(Error::Invalid(
            "managed acceptance input exceeds bound".into(),
        ));
    }
    Ok(bytes)
}
fn run() -> Result<()> {
    let a = Args::parse();
    let trust = Trust::decode(&read(&a.trust, 2 << 20)?)?;
    let context = Context::from_selection(trust.selection)?;
    let proof = Proof::decode(&read(&a.proof, MAX_BYTES)?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&proof.verify(&context)?)?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-managed-drain-acceptance: {e}");
        std::process::exit(1);
    }
}
