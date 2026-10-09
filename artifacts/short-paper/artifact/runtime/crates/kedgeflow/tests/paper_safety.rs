//! Authority tests use a real etcd cluster through its v3 HTTP JSON gateway.
//! Set ETCD_ENDPOINT to the trusted test endpoint. KF_REQUIRE_ETCD=1 makes a
//! missing endpoint fail the suite; no test substitutes an in-memory ledger.

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kedgeflow::contracts::Grant;
use kedgeflow::error::{Error, Result};
use kedgeflow::ledger::{AuthoritativeObservation, AuthorityLedger, EtcdLedger, OutcomeQuerier};
use reqwest::Client;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Barrier;
use tokio::task::JoinSet;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    ledger: EtcdLedger,
    grant: Grant,
    prefix: String,
}

fn fixture() -> Option<Fixture> {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(endpoint) if !endpoint.is_empty() => endpoint,
        _ => {
            assert_ne!(
                std::env::var("KF_REQUIRE_ETCD").as_deref(),
                Ok("1"),
                "KF_REQUIRE_ETCD=1 requires ETCD_ENDPOINT pointing to a real etcd cluster"
            );
            eprintln!(
                "SKIP real-etcd test: set ETCD_ENDPOINT; KF_REQUIRE_ETCD=1 prohibits this skip"
            );
            return None;
        }
    };
    let suffix = format!(
        "{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let prefix = format!("/kf-rust-tests/{suffix}");
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let ledger = EtcdLedger::new(client, endpoint, prefix.clone()).unwrap();
    let mut envelope: Value =
        serde_json::from_str(include_str!("../../../fixtures/grant.json")).unwrap();
    let payload = &mut envelope["payload"];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    payload["issued_at"] = json!(now);
    payload["valid_from"] = json!(now.saturating_sub(1_000));
    payload["expires_at"] = json!(now + 3_600_000);
    payload["completion_mode"] = json!("dispatch_bound");
    payload["adapter_contract"]["completion_mode"] = json!("dispatch_bound");
    payload["adapter_contract"]["guard_primitive"] = json!("FencingToken");
    payload["parent_grant_digest"] = Value::Null;
    payload["saga_budget"] = Value::Null;
    let grant = serde_json::from_value(payload.clone()).unwrap();
    Some(Fixture {
        ledger,
        grant,
        prefix,
    })
}

fn part(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}
fn domain(prefix: &str, grant: &Grant) -> String {
    format!("{prefix}/domains/{}", part(&grant.conflict_domain))
}
fn root(prefix: &str, grant: &Grant) -> String {
    format!("{}/roots/{}", domain(prefix, grant), part(&grant.root_id))
}
fn next(grant: &Grant) -> Grant {
    let mut next = grant.clone();
    next.root_generation += 1;
    next.fence += 1;
    next.gid.push_str("-next");
    next.nonce.push_str("-next");
    next
}
fn refused(result: Result<()>) {
    assert!(matches!(result, Err(Error::Refused(_))), "{result:?}");
}

// Added for the compact paper. These are direct calls into the pinned Rust
// EtcdLedger; the fixture above is adapted from its integration tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paper_claim_matrix() {
    let f = fixture().expect("paper tests require real etcd");
    f.ledger.publish_policy(&f.grant).await.unwrap();
    for (roots, contenders) in [(1, 32), (1, 128), (8, 32), (8, 128), (32, 32), (32, 128)] {
        let mut grants = Vec::new();
        for r in 0..roots {
            let mut g = f.grant.clone();
            g.root_id = format!("matrix-{roots}-{contenders}-{r}");
            g.gid = g.root_id.clone();
            g.nonce = g.root_id.clone();
            f.ledger.issue(&g, DIGEST).await.unwrap();
            grants.push(g);
        }
        let barrier = Arc::new(Barrier::new(roots * contenders));
        let mut tasks = JoinSet::new();
        for (r, g) in grants.iter().enumerate() {
            for c in 0..contenders {
                let ledger = f.ledger.clone();
                let g = g.clone();
                let barrier = barrier.clone();
                tasks.spawn(async move {
                    barrier.wait().await;
                    (r, ledger.claim(&g, DIGEST, &format!("a-{r}-{c}")).await)
                });
            }
        }
        let mut wins = vec![0; roots];
        let mut refused_count = 0;
        while let Some(result) = tasks.join_next().await {
            let (r, result) = result.unwrap();
            match result {
                Ok(_) => wins[r] += 1,
                Err(Error::NonceConsumed) => refused_count += 1,
                other => panic!("unexpected transport/refusal: {other:?}"),
            }
        }
        assert_eq!(wins, vec![1; roots]);
        assert_eq!(refused_count, roots * (contenders - 1));
        for g in &grants {
            let record: Value = serde_json::from_slice(
                &f.ledger
                    .read_key(&root(&f.prefix, g))
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(record["status"], "claimed");
        }
        eprintln!(
            "PAPER_RESULT {}",
            json!({"experiment":"claim_matrix","roots":roots,"contenders":contenders,"attempts":roots*contenders,"claims":roots,"refused":refused_count,"transport_errors":0})
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paper_duplicate_issuance() {
    let f = fixture().expect("paper tests require real etcd");
    f.ledger.publish_policy(&f.grant).await.unwrap();
    let barrier = Arc::new(Barrier::new(32));
    let mut tasks = JoinSet::new();
    for _ in 0..32 {
        let ledger = f.ledger.clone();
        let g = f.grant.clone();
        let b = barrier.clone();
        tasks.spawn(async move {
            b.wait().await;
            ledger.issue(&g, DIGEST).await
        });
    }
    let mut wins = 0;
    let mut refusals = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(()) => wins += 1,
            Err(Error::Refused(_)) => refusals += 1,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!((wins, refusals), (1, 31));
    f.ledger.claim(&f.grant, DIGEST, "winner").await.unwrap();
    eprintln!(
        "PAPER_RESULT {}",
        json!({"experiment":"duplicate_issuance","contenders":32,"issued":wins,"refused":refusals})
    );
}

#[tokio::test]
async fn paper_terminal_outcomes_do_not_reopen_authority() {
    let f = fixture().expect("paper tests require real etcd");
    f.ledger.publish_policy(&f.grant).await.unwrap();
    for status in [
        "committed",
        "unknown",
        "not_dispatched",
        "state_guard_violation",
    ] {
        let mut g = f.grant.clone();
        g.root_id = status.into();
        g.gid = status.into();
        g.nonce = status.into();
        f.ledger.issue(&g, DIGEST).await.unwrap();
        let a = f.ledger.claim(&g, DIGEST, "attempt").await.unwrap();
        f.ledger.finish(&g, &a, status).await.unwrap();
        assert_eq!(f.ledger.status(&g, "attempt").await.unwrap().status, status);
        assert!(matches!(
            f.ledger.claim(&g, DIGEST, "retry").await,
            Err(Error::NonceConsumed)
        ));
        refused(f.ledger.replace(&g, &next(&g), DIGEST).await);
    }
    eprintln!(
        "PAPER_RESULT {}",
        json!({"experiment":"terminal_conservation","outcomes":4,"replays_refused":4,"replacements_refused":4})
    );
}

#[tokio::test]
async fn paper_generation_chain_retires_every_predecessor() {
    let f = fixture().expect("paper tests require real etcd");
    f.ledger.publish_policy(&f.grant).await.unwrap();
    f.ledger.issue(&f.grant, DIGEST).await.unwrap();
    let mut current = f.grant.clone();
    let mut old = Vec::new();
    for _ in 0..32 {
        let successor = next(&current);
        f.ledger
            .replace(&current, &successor, DIGEST)
            .await
            .unwrap();
        old.push(current);
        current = successor;
    }
    for g in old {
        assert!(matches!(
            f.ledger.claim(&g, DIGEST, "retired").await,
            Err(Error::Refused(_))
        ));
    }
    f.ledger.claim(&current, DIGEST, "current").await.unwrap();
    assert!(matches!(
        f.ledger.claim(&current, DIGEST, "duplicate").await,
        Err(Error::NonceConsumed)
    ));
    eprintln!(
        "PAPER_RESULT {}",
        json!({"experiment":"generation_chain","replacements":32,"retired_claims_refused":32,"current_claims":1})
    );
}

struct PaperQuery(AuthoritativeObservation);
#[async_trait]
impl OutcomeQuerier for PaperQuery {
    async fn query(&self, _: &str) -> Result<AuthoritativeObservation> {
        Ok(self.0.clone())
    }
}
#[tokio::test]
async fn paper_fresh_client_recovery_checks_all_correlation_fields() {
    let f = fixture().expect("paper tests require real etcd");
    f.ledger.publish_policy(&f.grant).await.unwrap();
    f.ledger.issue(&f.grant, DIGEST).await.unwrap();
    let a = f.ledger.claim(&f.grant, DIGEST, "recover").await.unwrap();
    f.ledger
        .authorize_dispatch(&f.grant, DIGEST, &a.id)
        .await
        .unwrap();
    f.ledger.finish(&f.grant, &a, "unknown").await.unwrap();
    // Recreate client state against the same durable cluster, without any cached attempt.
    let recovered = EtcdLedger::new(
        Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        std::env::var("ETCD_ENDPOINT").unwrap(),
        f.prefix.clone(),
    )
    .unwrap();
    assert_eq!(
        recovered.status(&f.grant, &a.id).await.unwrap().status,
        "unknown"
    );
    let good = AuthoritativeObservation {
        attempt_id: a.id.clone(),
        root_id: f.grant.root_id.clone(),
        grant_digest: DIGEST.into(),
        status: "committed".into(),
        target_reference: "target-op".into(),
    };
    for field in 0..4 {
        let mut wrong = good.clone();
        match field {
            0 => wrong.attempt_id = "wrong".into(),
            1 => wrong.root_id = "wrong".into(),
            2 => wrong.grant_digest = "b".repeat(64),
            _ => wrong.target_reference = String::new(),
        };
        assert!(matches!(
            recovered
                .reconcile(&f.grant, &a.id, &PaperQuery(wrong))
                .await,
            Err(Error::Invalid(_))
        ));
        assert_eq!(
            recovered.status(&f.grant, &a.id).await.unwrap().status,
            "unknown"
        );
    }
    let mut pending = good.clone();
    pending.status = "pending".into();
    assert_eq!(
        recovered
            .reconcile(&f.grant, &a.id, &PaperQuery(pending))
            .await
            .unwrap()
            .status,
        "unknown"
    );
    assert_eq!(
        recovered
            .reconcile(&f.grant, &a.id, &PaperQuery(good))
            .await
            .unwrap()
            .status,
        "committed"
    );
    assert!(matches!(
        recovered.claim(&f.grant, DIGEST, "retry").await,
        Err(Error::NonceConsumed)
    ));
    refused(recovered.replace(&f.grant, &next(&f.grant), DIGEST).await);
    refused(recovered.authorize_dispatch(&f.grant, DIGEST, &a.id).await);
    eprintln!(
        "PAPER_RESULT {}",
        json!({"experiment":"fresh_client_recovery","bad_correlations_refused":4,"pending_stays_unknown":true,"final_status":"committed","authority_reopened":false})
    );
}
