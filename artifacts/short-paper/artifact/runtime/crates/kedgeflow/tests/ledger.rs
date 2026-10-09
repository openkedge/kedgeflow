//! Authority tests use a real etcd cluster through its v3 HTTP JSON gateway.
//! Set ETCD_ENDPOINT to the trusted test endpoint. KF_REQUIRE_ETCD=1 makes a
//! missing endpoint fail the suite; no test substitutes an in-memory ledger.

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kedgeflow::contracts::{Grant, Policy};
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
fn outbox(prefix: &str, grant: &Grant, attempt: &str) -> String {
    format!("{}/outbox/{}", root(prefix, grant), part(attempt))
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

#[tokio::test]
async fn authority_records_preserve_go_layout_and_consumption() {
    let Some(f) = fixture() else {
        return;
    };
    f.ledger.publish_policy(&f.grant).await.unwrap();
    f.ledger.issue(&f.grant, DIGEST).await.unwrap();
    refused(f.ledger.issue(&f.grant, DIGEST).await);
    let stored: Value = serde_json::from_slice(
        &f.ledger
            .read_key(&root(&f.prefix, &f.grant))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        stored,
        json!({"generation": f.grant.root_generation, "fence": f.grant.fence,
        "active_gid": f.grant.gid, "status": "unclaimed"})
    );
    assert!(matches!(
        f.ledger.status(&f.grant, "missing").await,
        Err(Error::Unknown(_))
    ));
    let attempt = f.ledger.claim(&f.grant, DIGEST, "attempt/π").await.unwrap();
    assert_eq!(
        f.ledger.status(&f.grant, &attempt.id).await.unwrap(),
        attempt
    );
    assert_eq!(
        f.ledger
            .read_key(&outbox(&f.prefix, &f.grant, &attempt.id))
            .await
            .unwrap()
            .unwrap(),
        b"claimed_not_dispatched"
    );
    assert_eq!(
        f.ledger
            .read_key(&format!(
                "{}/nonces/{}",
                root(&f.prefix, &f.grant),
                part(&f.grant.nonce)
            ))
            .await
            .unwrap()
            .unwrap(),
        attempt.id.as_bytes()
    );
    f.ledger
        .authorize_dispatch(&f.grant, DIGEST, &attempt.id)
        .await
        .unwrap();
    assert_eq!(
        f.ledger
            .read_key(&outbox(&f.prefix, &f.grant, &attempt.id))
            .await
            .unwrap()
            .unwrap(),
        b"dispatch_authorized"
    );
    refused(
        f.ledger
            .authorize_dispatch(&f.grant, DIGEST, &attempt.id)
            .await,
    );
    f.ledger
        .finish(&f.grant, &attempt, "committed")
        .await
        .unwrap();
    assert_eq!(
        f.ledger.status(&f.grant, &attempt.id).await.unwrap().status,
        "committed"
    );
    refused(f.ledger.finish(&f.grant, &attempt, "unknown").await);
    assert!(matches!(
        f.ledger.claim(&f.grant, DIGEST, "replay").await,
        Err(Error::NonceConsumed)
    ));
    refused(f.ledger.replace(&f.grant, &next(&f.grant), DIGEST).await);
    let stored: Value = serde_json::from_slice(
        &f.ledger
            .read_key(&root(&f.prefix, &f.grant))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stored["status"], "claimed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_gateway_claims_have_exactly_one_winner_per_root() {
    let Some(f) = fixture() else {
        return;
    };
    f.ledger.publish_policy(&f.grant).await.unwrap();
    let mut grants = Vec::new();
    for i in 0..8 {
        let mut grant = f.grant.clone();
        grant.root_id = format!("root-{i}");
        grant.gid = format!("grant-{i}");
        grant.nonce = format!("nonce-{i}");
        f.ledger.issue(&grant, DIGEST).await.unwrap();
        grants.push(grant);
    }
    let barrier = Arc::new(Barrier::new(8 * 32));
    let mut tasks = JoinSet::new();
    for (root_index, grant) in grants.into_iter().enumerate() {
        for contender in 0..32 {
            let ledger = f.ledger.clone();
            let grant = grant.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                (
                    root_index,
                    ledger
                        .claim(&grant, DIGEST, &format!("attempt-{root_index}-{contender}"))
                        .await,
                )
            });
        }
    }
    let mut wins = [0; 8];
    let mut refused_count = 0;
    while let Some(result) = tasks.join_next().await {
        let (root_index, result) = result.unwrap();
        match result {
            Ok(_) => wins[root_index] += 1,
            Err(Error::NonceConsumed) => refused_count += 1,
            other => panic!("unexpected claim result: {other:?}"),
        }
    }
    assert_eq!(wins, [1; 8]);
    assert_eq!(refused_count, 248);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_etcd_members_coordinate_one_shared_root() {
    let Some(f) = fixture() else {
        return;
    };
    let endpoints: Vec<String> = std::env::var("ETCD_ENDPOINTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .collect();
    if endpoints.len() != 3 {
        assert_ne!(
            std::env::var("KF_REQUIRE_ETCD").as_deref(),
            Ok("1"),
            "KF_REQUIRE_ETCD=1 requires ETCD_ENDPOINTS listing all three real etcd members"
        );
        eprintln!("SKIP cross-member authority test: set ETCD_ENDPOINTS to three member URLs");
        return;
    }
    let mut unique = endpoints.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 3, "ETCD_ENDPOINTS must name distinct members");
    let mut ledgers = Vec::new();
    for endpoint in endpoints {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        ledgers.push(EtcdLedger::new(client, endpoint, f.prefix.clone()).unwrap());
    }
    ledgers[0].publish_policy(&f.grant).await.unwrap();
    ledgers[0].issue(&f.grant, DIGEST).await.unwrap();
    let barrier = Arc::new(Barrier::new(96));
    let mut tasks = JoinSet::new();
    for (member, ledger) in ledgers.iter().enumerate() {
        for contender in 0..32 {
            let ledger = ledger.clone();
            let grant = f.grant.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                ledger
                    .claim(
                        &grant,
                        DIGEST,
                        &format!("member-{member}-attempt-{contender}"),
                    )
                    .await
            });
        }
    }
    let mut winner = None;
    let mut consumed = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(attempt) => assert!(winner.replace(attempt).is_none()),
            Err(Error::NonceConsumed) => consumed += 1,
            other => panic!("unexpected cross-member claim result: {other:?}"),
        }
    }
    let winner = winner.expect("one member must claim the shared root");
    assert_eq!(consumed, 95);
    // Default etcd range reads are linearizable: each independent endpoint must
    // observe the same retained attempt and refuse a replacement of its root.
    for ledger in &ledgers {
        assert_eq!(ledger.status(&f.grant, &winner.id).await.unwrap(), winner);
        refused(ledger.replace(&f.grant, &next(&f.grant), DIGEST).await);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_and_replacement_race_share_one_atomic_root() {
    let Some(f) = fixture() else {
        return;
    };
    f.ledger.publish_policy(&f.grant).await.unwrap();
    for i in 0..32 {
        let mut old = f.grant.clone();
        old.root_id = format!("race-root-{i}");
        old.gid = format!("race-grant-{i}");
        old.nonce = format!("race-nonce-{i}");
        let successor = next(&old);
        f.ledger.issue(&old, DIGEST).await.unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let ledger = f.ledger.clone();
        let claim_grant = old.clone();
        let claim_barrier = barrier.clone();
        let claim = tokio::spawn(async move {
            claim_barrier.wait().await;
            ledger.claim(&claim_grant, DIGEST, "race-attempt").await
        });
        let ledger = f.ledger.clone();
        let replace_old = old.clone();
        let replace_next = successor.clone();
        let replace = tokio::spawn(async move {
            barrier.wait().await;
            ledger.replace(&replace_old, &replace_next, DIGEST).await
        });
        let (claimed, replaced) = (claim.await.unwrap(), replace.await.unwrap());
        assert_ne!(
            claimed.is_ok(),
            replaced.is_ok(),
            "claim/replacement must have one exclusive winner"
        );
        if claimed.is_ok() {
            refused(replaced);
            assert!(matches!(
                f.ledger.claim(&old, DIGEST, "duplicate").await,
                Err(Error::NonceConsumed)
            ));
            assert!(matches!(
                f.ledger.claim(&successor, DIGEST, "stale-successor").await,
                Err(Error::Refused(_))
            ));
        } else {
            assert!(matches!(claimed, Err(Error::Refused(_))));
            replaced.unwrap();
            f.ledger
                .claim(&successor, DIGEST, "successor-attempt")
                .await
                .unwrap();
            assert!(matches!(
                f.ledger.claim(&old, DIGEST, "retired-parent").await,
                Err(Error::Refused(_))
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn monotonic_policy_and_ownership_updates_fence_claimed_dispatch() {
    let Some(f) = fixture() else {
        return;
    };
    f.ledger.publish_policy(&f.grant).await.unwrap();
    f.ledger.issue(&f.grant, DIGEST).await.unwrap();
    let attempt = f
        .ledger
        .claim(&f.grant, DIGEST, "before-policy-update")
        .await
        .unwrap();
    let mut newer = f.grant.clone();
    newer.policy.epoch += 1;
    newer.policy.digest = "b".repeat(64);
    newer.ownership_epoch += 1;
    f.ledger.publish_policy(&newer).await.unwrap();
    refused(
        f.ledger
            .authorize_dispatch(&f.grant, DIGEST, &attempt.id)
            .await,
    );
    refused(f.ledger.publish_policy(&f.grant).await);
    let mut conflicting = newer.clone();
    conflicting.policy.digest = "c".repeat(64);
    refused(f.ledger.publish_policy(&conflicting).await);
    f.ledger
        .finish(&f.grant, &attempt, "not_dispatched")
        .await
        .unwrap();
    assert!(matches!(
        f.ledger.claim(&f.grant, DIGEST, "after-update").await,
        Err(Error::NonceConsumed)
    ));

    let mut high = newer.clone();
    high.policy.epoch += 2;
    high.policy.digest = "d".repeat(64);
    high.ownership_epoch += 2;
    let mut low = newer.clone();
    low.policy.epoch += 1;
    low.policy.digest = "e".repeat(64);
    low.ownership_epoch += 1;
    let barrier = Arc::new(Barrier::new(2));
    let ledger = f.ledger.clone();
    let low_grant = low.clone();
    let low_barrier = barrier.clone();
    let low_task = tokio::spawn(async move {
        low_barrier.wait().await;
        ledger.publish_policy(&low_grant).await
    });
    let ledger = f.ledger.clone();
    let high_grant = high.clone();
    let high_task = tokio::spawn(async move {
        barrier.wait().await;
        ledger.publish_policy(&high_grant).await
    });
    let low_result = low_task.await.unwrap();
    let high_result = high_task.await.unwrap();
    assert!(low_result.is_ok() || matches!(low_result, Err(Error::Refused(_))));
    assert!(high_result.is_ok() || matches!(high_result, Err(Error::Refused(_))));
    assert!(low_result.is_ok() || high_result.is_ok());
    let stored: Policy = serde_json::from_slice(
        &f.ledger
            .read_key(&format!("{}/policy", domain(&f.prefix, &f.grant)))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(stored.epoch >= low.policy.epoch);
    if high_result.is_ok() {
        assert_eq!(stored.epoch, high.policy.epoch);
    }
    // A compare race can refuse the newer writer. Its authority-side caller can
    // read/retry; the ledger never retries a mutation or silently rolls back.
    f.ledger.publish_policy(&high).await.unwrap();
    refused(f.ledger.publish_policy(&low).await);
    let ownership = f
        .ledger
        .read_key(&format!("{}/ownership", domain(&f.prefix, &f.grant)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ownership, high.ownership_epoch.to_string().as_bytes());
}

#[derive(Clone)]
struct Query(AuthoritativeObservation);
#[async_trait]
impl OutcomeQuerier for Query {
    async fn query(&self, _attempt_id: &str) -> Result<AuthoritativeObservation> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn unknown_reconciliation_is_correlated_query_only_and_keeps_consumption() {
    let Some(f) = fixture() else {
        return;
    };
    f.ledger.publish_policy(&f.grant).await.unwrap();
    f.ledger.issue(&f.grant, DIGEST).await.unwrap();
    let attempt = f
        .ledger
        .claim(&f.grant, DIGEST, "unknown-attempt")
        .await
        .unwrap();
    f.ledger
        .authorize_dispatch(&f.grant, DIGEST, &attempt.id)
        .await
        .unwrap();
    f.ledger
        .finish(&f.grant, &attempt, "unknown")
        .await
        .unwrap();
    let observation = AuthoritativeObservation {
        attempt_id: attempt.id.clone(),
        root_id: f.grant.root_id.clone(),
        grant_digest: DIGEST.into(),
        status: "committed".into(),
        target_reference: "target-op-42".into(),
    };
    let mut wrong = observation.clone();
    wrong.root_id = "another-root".into();
    assert!(matches!(
        f.ledger
            .reconcile(&f.grant, &attempt.id, &Query(wrong))
            .await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        f.ledger.status(&f.grant, &attempt.id).await.unwrap().status,
        "unknown"
    );
    let mut pending = observation.clone();
    pending.status = "pending".into();
    assert_eq!(
        f.ledger
            .reconcile(&f.grant, &attempt.id, &Query(pending))
            .await
            .unwrap()
            .status,
        "unknown"
    );
    let committed = f
        .ledger
        .reconcile(&f.grant, &attempt.id, &Query(observation))
        .await
        .unwrap();
    assert_eq!(committed.status, "committed");
    assert_eq!(
        f.ledger
            .read_key(&outbox(&f.prefix, &f.grant, &attempt.id))
            .await
            .unwrap()
            .unwrap(),
        b"committed"
    );
    let observed: Value = serde_json::from_slice(
        &f.ledger
            .read_key(&format!(
                "{}/attempts/{}/observation",
                root(&f.prefix, &f.grant),
                part(&attempt.id)
            ))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(observed["AttemptID"], attempt.id);
    assert_eq!(observed["TargetReference"], "target-op-42");
    assert!(matches!(
        f.ledger.claim(&f.grant, DIGEST, "after-reconcile").await,
        Err(Error::NonceConsumed)
    ));
    refused(f.ledger.replace(&f.grant, &next(&f.grant), DIGEST).await);
    refused(
        f.ledger
            .authorize_dispatch(&f.grant, DIGEST, &attempt.id)
            .await,
    );
    assert!(matches!(
        f.ledger
            .reconcile(
                &f.grant,
                &attempt.id,
                &Query(AuthoritativeObservation {
                    attempt_id: attempt.id.clone(),
                    root_id: f.grant.root_id.clone(),
                    grant_digest: DIGEST.into(),
                    status: "committed".into(),
                    target_reference: "op-42".into()
                })
            )
            .await,
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn unreachable_etcd_cannot_bootstrap_local_authority() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", socket.local_addr().unwrap());
    drop(socket);
    let ledger = EtcdLedger::new(
        Client::builder()
            .timeout(Duration::from_millis(500))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        endpoint,
        "/unavailable-test",
    )
    .unwrap();
    let envelope: Value =
        serde_json::from_str(include_str!("../../../fixtures/grant.json")).unwrap();
    let grant: Grant = serde_json::from_value(envelope["payload"].clone()).unwrap();
    assert!(matches!(
        ledger.publish_policy(&grant).await,
        Err(Error::Unavailable(_))
    ));
    assert!(matches!(
        ledger.issue(&grant, DIGEST).await,
        Err(Error::Unavailable(_))
    ));
    assert!(matches!(
        ledger.claim(&grant, DIGEST, "attempt").await,
        Err(Error::Unavailable(_))
    ));
    assert!(matches!(
        ledger.status(&grant, "attempt").await,
        Err(Error::Unavailable(_))
    ));
}
