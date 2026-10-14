use kedgeflow::{
    coordination::{Coordination, ReservationEnrollment, ReservationScope, ReservationState},
    ledger::EtcdLedger,
};
use std::{collections::BTreeSet, sync::Arc};
fn ledger() -> Option<EtcdLedger> {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
            eprintln!("SKIP coordination real-etcd tests: ETCD_ENDPOINT missing");
            return None;
        }
    };
    Some(
        EtcdLedger::new(
            reqwest::Client::new(),
            &endpoint,
            format!("/coordination-test-{:016x}", rand::random::<u64>()),
        )
        .unwrap(),
    )
}
fn scope(resources: &[&str]) -> ReservationScope {
    ReservationScope {
        actions: BTreeSet::from(["postgres.reservation.set.v1".into()]),
        resources: resources.iter().map(|s| (*s).into()).collect(),
    }
}
fn enrollment(forward: u64, compensation: u64) -> ReservationEnrollment {
    ReservationEnrollment {
        tenant: "tenant".into(),
        conflict_domain: "complete-fixture-predicate".into(),
        scope: scope(&["one", "two"]),
        forward,
        compensation,
    }
}
fn op(n: u8) -> String {
    format!("{n:064x}")
}
#[tokio::test]
async fn last_slot_competitors_cannot_both_allocate_and_operation_replay_is_stable() {
    let Some(ledger) = ledger() else {
        return;
    };
    let c = Arc::new(Coordination::new(ledger.clone(), "root").unwrap());
    c.enroll(enrollment(1, 1)).await.unwrap();
    // A different root ID cannot invent a second budget for this domain.
    let other = Coordination::new(ledger.clone(), "other-root").unwrap();
    assert!(other.enroll(enrollment(1, 1)).await.is_err());
    assert!(other.status().await.is_err());
    let mut tasks = Vec::new();
    for n in 1..17 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            c.allocate(&op(n), None, scope(&["one"]), 1, 1).await
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Ok(winner) = task.await.unwrap() {
            winners.push(winner);
        }
    }
    assert_eq!(winners.len(), 1);
    let winner = &winners[0];
    let recreated = Coordination::new(ledger, "root").unwrap();
    assert_eq!(
        recreated
            .allocate(&winner.operation_digest, None, scope(&["one"]), 1, 1)
            .await
            .unwrap(),
        *winner
    );
    assert!(
        recreated
            .allocate(&winner.operation_digest, None, scope(&["two"]), 1, 1)
            .await
            .is_err()
    );
    assert!(recreated.enroll(enrollment(100, 100)).await.is_err());
    assert_eq!(recreated.status().await.unwrap().allocations.len(), 1);
}
#[tokio::test]
async fn nested_scope_and_budgets_conserve_unknown_and_known_consumption() {
    let Some(ledger) = ledger() else {
        return;
    };
    let c = Coordination::new(ledger.clone(), "root").unwrap();
    c.enroll(enrollment(5, 2)).await.unwrap();
    c.allocate(&op(1), None, scope(&["one", "two"]), 5, 2)
        .await
        .unwrap();
    c.allocate(&op(2), Some(&op(1)), scope(&["one"]), 3, 1)
        .await
        .unwrap();
    c.allocate(&op(3), Some(&op(1)), scope(&["two"]), 2, 1)
        .await
        .unwrap();
    assert!(
        c.allocate(&op(4), Some(&op(1)), scope(&["one"]), 1, 0)
            .await
            .is_err()
    );
    assert!(c.consume(&op(1), "composite-parent").await.is_err());
    assert!(
        c.allocate(&op(4), Some(&op(2)), scope(&["two"]), 1, 0)
            .await
            .is_err()
    );
    c.allocate(&op(4), Some(&op(2)), scope(&["one"]), 2, 1)
        .await
        .unwrap();
    assert!(
        c.allocate(&op(5), Some(&op(2)), scope(&["one"]), 1, 1)
            .await
            .is_err()
    );
    c.allocate(&op(5), Some(&op(2)), scope(&["one"]), 1, 0)
        .await
        .unwrap();
    let consumed = c.consume(&op(4), "original").await.unwrap();
    assert_eq!(consumed.state, ReservationState::Unknown);
    assert_eq!(c.consume(&op(4), "original").await.unwrap(), consumed);
    assert!(c.consume(&op(4), "another").await.is_err());
    assert!(
        c.allocate(&op(6), None, scope(&["one"]), 1, 0)
            .await
            .is_err()
    );
    assert!(
        c.allocate(&op(6), Some(&op(4)), scope(&["one"]), 1, 0)
            .await
            .is_err()
    );
    c.observe(&op(4), "original", ReservationState::Committed)
        .await
        .unwrap();
    assert!(
        c.observe(&op(4), "original", ReservationState::ProvenNoEffect)
            .await
            .is_err()
    );
    c.consume(&op(3), "second").await.unwrap();
    c.observe(&op(3), "second", ReservationState::ProvenNoEffect)
        .await
        .unwrap();
    assert!(
        c.allocate(&op(6), None, scope(&["two"]), 1, 0)
            .await
            .is_err()
    );
    let recreated = Coordination::new(ledger, "root").unwrap();
    let state = recreated.status().await.unwrap();
    assert!(!state.execution_authority);
    assert_eq!(state.allocations[&op(4)].state, ReservationState::Committed);
    assert_eq!(
        state.allocations[&op(3)].state,
        ReservationState::ProvenNoEffect
    );
}
#[tokio::test]
async fn stopped_roots_bad_scope_overflow_and_unavailable_state_refuse() {
    let Some(ledger) = ledger() else {
        return;
    };
    let c = Coordination::new(ledger, "root").unwrap();
    assert!(c.enroll(enrollment(u64::MAX, 0)).await.is_err());
    c.enroll(enrollment(3, 1)).await.unwrap();
    assert!(
        c.allocate(&op(1), None, scope(&["other"]), 1, 0)
            .await
            .is_err()
    );
    assert!(
        c.allocate(&op(1), None, scope(&["one"]), 0, 0)
            .await
            .is_err()
    );
    assert!(
        c.allocate(&op(1), None, scope(&["one"]), 1, 2)
            .await
            .is_err()
    );
    c.allocate(&op(1), None, scope(&["one"]), 1, 0)
        .await
        .unwrap();
    c.consume(&op(1), "attempt").await.unwrap();
    c.allocate(&op(2), None, scope(&["one"]), 1, 0)
        .await
        .unwrap();
    c.stop().await.unwrap();
    assert!(c.consume(&op(2), "new").await.is_err());
    assert!(
        c.allocate(&op(3), None, scope(&["one"]), 1, 0)
            .await
            .is_err()
    );
    c.observe(&op(1), "attempt", ReservationState::Committed)
        .await
        .unwrap();
    assert_eq!(
        c.consume(&op(1), "attempt").await.unwrap().state,
        ReservationState::Committed
    );
    let offline = Coordination::new(
        EtcdLedger::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(100))
                .build()
                .unwrap(),
            "http://127.0.0.1:1",
            "/offline",
        )
        .unwrap(),
        "root",
    )
    .unwrap();
    assert!(offline.enroll(enrollment(1, 0)).await.is_err());
}
