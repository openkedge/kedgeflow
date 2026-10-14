//! Synthetic authenticator signatures + real etcd; no hardware ceremony claim.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kedgeflow::{
    clock::Clock,
    contracts::Subject,
    ledger::EtcdLedger,
    review::{Approval, ReviewAssertion, ReviewEnrollment},
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::json;
use sha2::{Digest, Sha256};
const NOW: i64 = 1_800_000_000_000;
struct Time;
impl Clock for Time {
    fn now_ms(&self) -> i64 {
        NOW
    }
}
fn ledger() -> Option<EtcdLedger> {
    let endpoint = match std::env::var("ETCD_ENDPOINT") {
        Ok(v) => v,
        Err(_) => {
            assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
            eprintln!("SKIP review real-etcd tests: ETCD_ENDPOINT missing");
            return None;
        }
    };
    Some(
        EtcdLedger::new(
            reqwest::Client::new(),
            &endpoint,
            format!("/review-test-{:016x}", rand::random::<u64>()),
        )
        .unwrap(),
    )
}
fn fixture() -> (EcdsaKeyPair, ReviewEnrollment, Approval) {
    let rng = SystemRandom::new();
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der.as_ref(), &rng).unwrap();
    let reviewer = Subject {
        iss: "https://login.example".into(),
        sub: "reviewer".into(),
    };
    let enrollment = ReviewEnrollment {
        credential_id: URL_SAFE_NO_PAD.encode(b"credential"),
        reviewer: reviewer.clone(),
        rp_id: "review.example".into(),
        origin: "https://review.example".into(),
        public_key_sec1: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        user_handle: URL_SAFE_NO_PAD.encode(b"reviewer-handle"),
        hardware_bound_required: false,
    };
    let approval = Approval {
        proposal_digest: "a".repeat(64),
        policy_epoch: 1,
        reviewer,
        rendering_template_digest: "b".repeat(64),
        rendered_digest: "c".repeat(64),
        parameters_digest: "d".repeat(64),
        reviewed_at: 0,
        expires_at: NOW + 60_000,
        verdict: "approve".into(),
        nonce: String::new(),
        rp_id: enrollment.rp_id.clone(),
    };
    (key, enrollment, approval)
}
fn assertion(
    key: &EcdsaKeyPair,
    enrollment: &ReviewEnrollment,
    approval: &Approval,
    count: u32,
    flags: u8,
    origin: &str,
) -> ReviewAssertion {
    // Whitespace is intentional: signature hashes the original bytes, not JCS.
    let client=format!(" {{\n\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{origin}\",\"crossOrigin\":false}} ",approval.challenge().unwrap()).into_bytes();
    let mut auth = Sha256::digest(approval.rp_id.as_bytes()).to_vec();
    auth.push(flags);
    auth.extend_from_slice(&count.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    ReviewAssertion {
        credential_id: enrollment.credential_id.clone(),
        client_data_json: URL_SAFE_NO_PAD.encode(&client),
        authenticator_data: URL_SAFE_NO_PAD.encode(&auth),
        signature: URL_SAFE_NO_PAD
            .encode(key.sign(&SystemRandom::new(), &signed).unwrap().as_ref()),
        user_handle: Some(enrollment.user_handle.clone()),
    }
}
#[tokio::test]
async fn replicas_restart_counter_and_revocation_preserve_one_consumption() {
    let Some(ledger) = ledger() else {
        return;
    };
    let (key, enrollment, approval) = fixture();
    ledger.enroll_review(enrollment.clone()).await.unwrap();
    assert!(ledger.enroll_review(enrollment.clone()).await.is_err());
    let issued = ledger
        .issue_review(&enrollment.credential_id, approval.clone(), &Time)
        .await
        .unwrap();
    let proof = assertion(&key, &enrollment, &issued, 1, 5, &enrollment.origin);
    let mut jobs = Vec::new();
    for _ in 0..12 {
        let ledger = ledger.clone();
        let issued = issued.clone();
        let proof = proof.clone();
        jobs.push(tokio::spawn(async move {
            ledger.consume_review(&issued, &proof, &Time).await
        }));
    }
    let mut winners = 0;
    for job in jobs {
        if let Ok(verified) = job.await.unwrap() {
            winners += 1;
            assert_eq!(verified.approval(), &issued);
            assert_eq!(verified.sign_count(), 1);
            assert_eq!(verified.assertion_digest().len(), 64);
        }
    }
    assert_eq!(winners, 1);
    let recreated = ledger.clone();
    assert!(
        recreated
            .consume_review(&issued, &proof, &Time)
            .await
            .is_err()
    );
    let next = recreated
        .issue_review(&enrollment.credential_id, approval.clone(), &Time)
        .await
        .unwrap();
    let stale = assertion(&key, &enrollment, &next, 1, 5, &enrollment.origin);
    assert!(
        recreated
            .consume_review(&next, &stale, &Time)
            .await
            .is_err()
    );
    let fresh = assertion(&key, &enrollment, &next, 2, 5, &enrollment.origin);
    recreated
        .consume_review(&next, &fresh, &Time)
        .await
        .unwrap();
    let third = recreated
        .issue_review(&enrollment.credential_id, approval, &Time)
        .await
        .unwrap();
    recreated
        .revoke_review(&enrollment.credential_id)
        .await
        .unwrap();
    assert!(
        recreated
            .consume_review(
                &third,
                &assertion(&key, &enrollment, &third, 3, 5, &enrollment.origin),
                &Time
            )
            .await
            .is_err()
    );
    assert!(
        recreated
            .issue_review(&enrollment.credential_id, third, &Time)
            .await
            .is_err()
    );
    assert!(recreated.enroll_review(enrollment).await.is_err());
}
#[tokio::test]
async fn assertion_negatives_do_not_consume_the_original_challenge() {
    let Some(ledger) = ledger() else {
        return;
    };
    let (key, enrollment, approval) = fixture();
    ledger.enroll_review(enrollment.clone()).await.unwrap();
    let issued = ledger
        .issue_review(&enrollment.credential_id, approval, &Time)
        .await
        .unwrap();
    let good = assertion(&key, &enrollment, &issued, 1, 5, &enrollment.origin);
    let mut negatives = vec![
        assertion(&key, &enrollment, &issued, 1, 1, &enrollment.origin),
        assertion(&key, &enrollment, &issued, 1, 0x0d, &enrollment.origin),
        assertion(&key, &enrollment, &issued, 0, 5, &enrollment.origin),
        assertion(&key, &enrollment, &issued, 1, 5, "https://evil.example"),
    ];
    let mut wrong = good.clone();
    wrong.user_handle = Some("wrong".into());
    negatives.push(wrong);
    let mut wrong = good.clone();
    wrong.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    negatives.push(wrong);
    let mut wrong = good.clone();
    wrong.client_data_json =
        URL_SAFE_NO_PAD.encode(b"{\"type\":\"webauthn.get\",\"type\":\"webauthn.get\"}");
    negatives.push(wrong);
    let mut wrong = good.clone();
    wrong.client_data_json = URL_SAFE_NO_PAD.encode(vec![b' '; 8193]);
    negatives.push(wrong);
    for negative in negatives {
        assert!(
            ledger
                .consume_review(&issued, &negative, &Time)
                .await
                .is_err()
        );
    }
    for field in [
        "parameters",
        "proposal",
        "rendering",
        "policy",
        "reviewer",
        "expiry",
        "rp",
    ] {
        let mut changed = issued.clone();
        match field {
            "parameters" => changed.parameters_digest = "e".repeat(64),
            "proposal" => changed.proposal_digest = "e".repeat(64),
            "rendering" => changed.rendered_digest = "e".repeat(64),
            "policy" => changed.policy_epoch += 1,
            "reviewer" => changed.reviewer.sub = "other".into(),
            "expiry" => changed.expires_at = NOW,
            "rp" => changed.rp_id = "other.example".into(),
            _ => unreachable!(),
        }
        assert!(ledger.consume_review(&changed, &good, &Time).await.is_err());
    }
    ledger.consume_review(&issued, &good, &Time).await.unwrap();
    struct Crossing(std::sync::atomic::AtomicBool);
    impl Clock for Crossing {
        fn now_ms(&self) -> i64 {
            if self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                NOW + 60_001
            } else {
                NOW
            }
        }
    }
    let late = ledger
        .issue_review(&enrollment.credential_id, issued.clone(), &Time)
        .await
        .unwrap();
    let late_proof = assertion(&key, &enrollment, &late, 2, 5, &enrollment.origin);
    assert!(
        ledger
            .consume_review(
                &late,
                &late_proof,
                &Crossing(std::sync::atomic::AtomicBool::new(false))
            )
            .await
            .is_err()
    );
    assert!(
        ledger
            .consume_review(&late, &late_proof, &Time)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn hardware_request_origin_mismatch_and_unavailable_state_refuse() {
    let Some(ledger) = ledger() else {
        return;
    };
    let (_, mut enrollment, approval) = fixture();
    enrollment.hardware_bound_required = true;
    assert!(ledger.enroll_review(enrollment.clone()).await.is_err());
    enrollment.hardware_bound_required = false;
    enrollment.origin = "http://review.example".into();
    assert!(ledger.enroll_review(enrollment.clone()).await.is_err());
    enrollment.origin = "https://evil.example".into();
    assert!(ledger.enroll_review(enrollment.clone()).await.is_err());
    let offline = EtcdLedger::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap(),
        "http://127.0.0.1:1",
        "/review-unavailable",
    )
    .unwrap();
    assert!(
        offline
            .issue_review(&enrollment.credential_id, approval, &Time)
            .await
            .is_err()
    );
    let mut value = serde_json::to_value(enrollment).unwrap();
    value["execution_authority"] = json!(true);
    assert!(serde_json::from_value::<ReviewEnrollment>(value).is_err());
}
