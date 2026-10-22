use clap::{Parser, Subcommand, ValueEnum};
use kedgeflow::{
    clock::{Clock, SystemClock},
    error::{Error, Result},
    family_saga::{
        AggregateBundle, AuditTrust, IntentAction, IntentPayload, PROFILE, Prepared,
        verify_aggregate,
    },
    family_saga_config::Config,
};
use serde_json::json;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Protected family saga capture, durable owner intents and original evidence; native members require independent fresh admission"
)]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    operation: Operation,
}
#[derive(Clone, ValueEnum)]
enum Action {
    Observe,
    Quiesce,
    PrepareCompensation,
}
#[derive(Subcommand)]
enum Operation {
    /// Validate protected local material without a remote query or mutation.
    Check,
    /// Enroll genesis only in an empty namespace; never adopt an orphan.
    Enroll,
    Status,
    Collect,
    Export,
    /// Save an exact signed intent durably before any submission. Never overwrite.
    Stage {
        #[arg(long)]
        action: Action,
        #[arg(long)]
        operation_key: String,
        #[arg(long)]
        owner_key_id: String,
        #[arg(long)]
        owner_key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Submit or replay the identical previously saved command.
    Apply {
        #[arg(long)]
        prepared: PathBuf,
    },
    /// Query the exact original command, including after expiry or root stop.
    Lookup {
        #[arg(long)]
        prepared: PathBuf,
    },
    /// Offline verification uses external public pins; no protected config needed.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
}
fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let mut raw = vec![];
    std::fs::File::open(path)?
        .take(bound as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > bound {
        return Err(Error::Invalid("saga input exceeds bound".into()));
    }
    Ok(raw)
}
async fn run() -> Result<()> {
    let a = Args::parse();
    if let Operation::Verify { bundle, trust } = &a.operation {
        let bundle = AggregateBundle::decode(&read(bundle, 18 << 20)?)?;
        let trust = AuditTrust::decode(&read(trust, 1 << 20)?)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&verify_aggregate(&bundle, &trust)?)?
        );
        return Ok(());
    }
    let path = a
        .config
        .as_deref()
        .ok_or_else(|| Error::Invalid("--config required".into()))?;
    let c = Config::decode(&read(path, 1 << 20)?)?;
    let saga = c.saga().await?;
    let r = saga.registration();
    let value = match a.operation {
        Operation::Check => {
            json!({"validated":true,"remote_query":false,"execution_authority":false})
        }
        Operation::Enroll => {
            c.family.family().await?.enroll().await?;
            json!({"enrolled":true,"execution_authority":false})
        }
        Operation::Status => json!(saga.status().await?),
        Operation::Collect => json!(saga.collect().await?),
        Operation::Export => json!(saga.export(&c.family_observer.load().await?).await?),
        Operation::Stage {
            action,
            operation_key,
            owner_key_id,
            owner_key,
            out,
        } => {
            // Refuse a partial or existing original before reading fresh capture.
            if out.try_exists()? {
                return Err(Error::Refused(
                    "prepared file already exists; query/replay the original".into(),
                ));
            }
            let action = match action {
                Action::Observe => IntentAction::Observe,
                Action::Quiesce => IntentAction::Quiesce,
                Action::PrepareCompensation => IntentAction::PrepareCompensation,
            };
            let capture = if action == IntentAction::Quiesce {
                None
            } else {
                Some(saga.collect().await?)
            };
            let head = match &capture {
                Some(c) => c.snapshot.phase_head.clone(),
                None => saga.status().await?.head,
            };
            let now = SystemClock.now_ms();
            let expires_at = now
                .checked_add(60000)
                .ok_or_else(|| Error::Invalid("clock exceeds bound".into()))?;
            let expires_at = if action == IntentAction::Observe {
                expires_at
            } else {
                expires_at.min(r.expires_at)
            };
            let p = Prepared::sign(
                IntentPayload {
                    family_digest: r.digest()?,
                    operation_key,
                    expected_head: head,
                    issued_at: now,
                    expires_at,
                    action,
                    proof_digest: capture.as_ref().map(|c| c.snapshot.digest()).transpose()?,
                },
                capture,
                &owner_key_id,
                &owner_key,
                r,
            )
            .await?;
            p.intent.validate_at(r, now)?;
            p.retain(&out, r)?;
            json!({"profile":PROFILE,"prepared":out,"operation_key":p.intent.payload.operation_key,"execution_authority":false})
        }
        Operation::Apply { prepared } => {
            let p = Prepared::read(&prepared)?;
            p.verify(r)?;
            json!(saga.apply(p.intent, p.capture).await?)
        }
        Operation::Lookup { prepared } => {
            let p = Prepared::read(&prepared)?;
            p.verify(r)?;
            json!({"profile":PROFILE,"operation_key":p.intent.payload.operation_key,"state":saga.lookup(&p.intent).await?,"execution_authority":false})
        }
        Operation::Verify { .. } => unreachable!(),
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kf-family-saga: {e}");
        std::process::exit(1);
    }
}
