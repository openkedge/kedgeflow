use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use kedgeflow::{
    compensation::Statement,
    compensation_target_config::EvaluatorConfig,
    contracts::strict_value,
    error::{Error, Result},
    reserved_lineage::Bundle,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Independent fixed SQL inverse applicability evaluator; produces evidence, never a grant"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    forward: PathBuf,
    #[arg(long)]
    barrier: PathBuf,
}
fn read(p: &Path, bound: usize) -> Result<Vec<u8>> {
    let mut v = vec![];
    std::fs::File::open(p)?
        .take(bound as u64 + 1)
        .read_to_end(&mut v)?;
    if v.len() > bound {
        return Err(Error::Invalid("evaluator input exceeds bound".into()));
    }
    Ok(v)
}
fn run() -> Result<()> {
    let a = Args::parse();
    let c: EvaluatorConfig = serde_json::from_value(strict_value(&read(&a.config, 1 << 20)?)?)?;
    let forward = Bundle::decode(&read(&a.forward, 512 << 10)?)?;
    let barrier: Statement = serde_json::from_value(strict_value(&read(&a.barrier, 32 << 10)?)?)?;
    let secret = read(&c.signing_key_file, 4096)?;
    let text = std::str::from_utf8(&secret)
        .map_err(|_| Error::Invalid("invalid protected evaluator key".into()))?;
    let key: [u8; 32] = STANDARD
        .decode(text.trim())
        .map_err(|_| Error::Invalid("invalid protected evaluator key".into()))?
        .try_into()
        .map_err(|_| Error::Invalid("invalid protected evaluator key".into()))?;
    let result = kedgeflow::compensation_target::applicability(
        &c.contract,
        &c.forward.registration()?,
        forward,
        barrier,
        kedgeflow::clock::Clock::now_ms(&kedgeflow::clock::SystemClock),
        &c.key_id,
        &ed25519_dalek::SigningKey::from_bytes(&key),
    )?;
    let returned_at = kedgeflow::clock::Clock::now_ms(&kedgeflow::clock::SystemClock);
    if result.applicability.payload["valid_from"]
        .as_i64()
        .is_none_or(|t| returned_at < t)
        || result.applicability.payload["expires_at"]
            .as_i64()
            .is_none_or(|t| returned_at >= t)
    {
        return Err(Error::Refused(
            "applicability window exhausted during verification".into(),
        ));
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-compensation-evaluate: {e}");
        std::process::exit(1);
    }
}
