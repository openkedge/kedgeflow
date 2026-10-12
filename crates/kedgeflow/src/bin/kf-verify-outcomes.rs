use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use kedgeflow::{
    contracts::{GrantVerifier, strict_value},
    error::{Error, Result},
    recovery::{OutcomeBundle, verify_outcomes},
};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Parser)]
#[command(
    version,
    about = "Offline grant/receipt-chain verifier; reports missing full-lineage links"
)]
struct Arguments {
    #[arg(long)]
    trust: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trust {
    gateway_audience: String,
    grant_keys: BTreeMap<String, String>,
    outcome_keys: BTreeMap<String, String>,
    source_id: String,
}
fn keys(values: BTreeMap<String, String>) -> Result<BTreeMap<String, VerifyingKey>> {
    values
        .into_iter()
        .map(|(id, k)| {
            let bytes: [u8; 32] = STANDARD
                .decode(k)
                .map_err(|_| Error::Invalid("invalid key encoding".into()))?
                .try_into()
                .map_err(|_| Error::Invalid("invalid key length".into()))?;
            Ok((
                id,
                VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| Error::Invalid("invalid public key".into()))?,
            ))
        })
        .collect()
}
fn run() -> Result<()> {
    let args = Arguments::parse();
    let trust = std::fs::read(args.trust)?;
    let raw = std::fs::read(args.bundle)?;
    if trust.len() > 1 << 20 || raw.len() > 4 << 20 {
        return Err(Error::Invalid("offline artifact exceeds bound".into()));
    }
    let trust: Trust = serde_json::from_value(strict_value(&trust)?)?;
    let bundle: OutcomeBundle = serde_json::from_value(strict_value(&raw)?)?;
    let result = verify_outcomes(
        &bundle,
        &GrantVerifier {
            keys: keys(trust.grant_keys)?,
            audience: trust.gateway_audience,
        },
        &keys(trust.outcome_keys)?,
        &trust.source_id,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kf-verify-outcomes: {e}");
        std::process::exit(1);
    }
}
