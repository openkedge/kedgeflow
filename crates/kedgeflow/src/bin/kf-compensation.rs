use clap::{ArgGroup, Parser};
use kedgeflow::{
    compensation::{MAX_PROOF, Proof, verify},
    compensation_config::CompensationConfig,
    error::{Error, Result},
};
use std::{io::Read, path::PathBuf};
#[derive(Parser)]
#[command(version,about="Verify and retain inverse prerequisites; no admission, spending or execution",group(ArgGroup::new("operation").required(true).multiple(false).args(["check","enroll","qualify","status","history","verify_proof"])))]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    #[arg(long)]
    enroll: bool,
    #[arg(long, requires = "proof")]
    qualify: bool,
    #[arg(long)]
    status: bool,
    #[arg(long)]
    history: bool,
    #[arg(long,requires_all=["proof","at"])]
    verify_proof: bool,
    #[arg(long)]
    proof: Option<PathBuf>,
    /// Explicit historical validation instant in epoch milliseconds; not current authority.
    #[arg(long, requires = "verify_proof")]
    at: Option<i64>,
}
fn read(path: &std::path::Path, bound: usize) -> Result<Vec<u8>> {
    let mut raw = vec![];
    std::fs::File::open(path)?
        .take(bound as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > bound {
        return Err(Error::Invalid("operator input exceeds bound".into()));
    }
    Ok(raw)
}
async fn run() -> Result<()> {
    let a = Arguments::parse();
    let c = CompensationConfig::decode(&read(&a.config, 1 << 20)?)?;
    if a.verify_proof {
        let proof = Proof::decode(&read(
            a.proof
                .as_deref()
                .ok_or_else(|| Error::Invalid("proof required".into()))?,
            MAX_PROOF,
        )?)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&verify(
                &c.contract,
                &c.trust.registration()?,
                &proof,
                a.at.ok_or_else(|| Error::Invalid("explicit time required".into()))?
            )?)?
        );
        return Ok(());
    }
    let q = c.qualifier().await?;
    if a.check {
        println!(
            "inverse material validated; no remote query or mutation; execution_authority=false; fresh_admission_required=true"
        );
        return Ok(());
    }
    let value = if a.enroll {
        q.enroll().await?;
        serde_json::json!({"profile":kedgeflow::compensation::PROFILE,"enrolled":true,"execution_authority":false,"fresh_admission_required":true})
    } else if a.qualify {
        serde_json::to_value(
            q.qualify(Proof::decode(&read(
                a.proof
                    .as_deref()
                    .ok_or_else(|| Error::Invalid("proof required".into()))?,
                MAX_PROOF,
            )?)?)
            .await?,
        )?
    } else if a.status {
        serde_json::to_value(q.status().await?)?
    } else {
        serde_json::to_value(q.history().await?)?
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-compensation: {e}");
        std::process::exit(1);
    }
}
