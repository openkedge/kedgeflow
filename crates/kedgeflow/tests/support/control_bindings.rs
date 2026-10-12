//! Native etcd/control transitions; observer and outcome keys are software fixtures.
use super::*;
use kedgeflow::control_bindings::{ControlBindingsBundle, verify_control_bindings};

impl HistoryHarness {
    async fn bindings(&self) -> ControlBindingsBundle {
        self.h
            .ledger
            .export_control_bindings(&self.c, &self.key, &Self::observer(), &Time(NOW + 120000))
            .await
            .unwrap()
    }
    fn check_bindings(
        &self,
        b: &ControlBindingsBundle,
    ) -> kedgeflow::error::Result<kedgeflow::control_bindings::ControlBindingsVerification> {
        verify_control_bindings(
            b,
            &ControlHistoryTrustConfig::decode(&serde_json::to_vec(&self.trust).unwrap())?
                .registration()?,
        )
    }
    fn binding_key(&self, phase: &str) -> String {
        match phase {
            "admission" => format!(
                "{}/admission-control/{}",
                self.h.ledger.namespace(),
                self.key
            ),
            "issuance" => format!(
                "{}/issuance-control/{}",
                self.h.ledger.namespace(),
                self.key
            ),
            _ => format!(
                "{}/domains/{}/roots/{}/control-bindings/{}/{phase}",
                self.h.ledger.namespace(),
                URL_SAFE_NO_PAD.encode(self.c.grant.conflict_domain.as_bytes()),
                URL_SAFE_NO_PAD.encode(self.c.grant.root_id.as_bytes()),
                URL_SAFE_NO_PAD.encode(self.c.attempt_id.as_bytes())
            ),
        }
    }
}
fn sign_bindings(b: &mut ControlBindingsBundle) {
    let c = &mut b.checkpoint;
    c.payload.history_digest =
        kedgeflow::contracts::digest("control-bindings-history", &json!(b.history)).unwrap();
    c.payload.bindings_digest =
        kedgeflow::contracts::digest("control-bindings-records", &json!(b.bindings)).unwrap();
    let mut raw = b"KedgeFlow:KF-CONTROL-BINDINGS-0.1-draft\0".to_vec();
    raw.extend(
        canonical(
            &json!({"profile":c.profile,"kind":c.kind,"key_id":c.key_id,"payload":c.payload}),
        )
        .unwrap(),
    );
    c.signature = URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[17; 32]).sign(&raw).to_bytes());
}
async fn delete_binding(h: &HistoryHarness, phase: &str) {
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    assert!(reqwest::Client::new().post(format!("{endpoint}/v3/kv/deleterange"))
        .json(&json!({"key":base64::engine::general_purpose::STANDARD.encode(h.binding_key(phase))}))
        .send().await.unwrap().status().is_success());
}
#[tokio::test]
async fn control_bindings_native_undispatched_retry_and_offline_cli() {
    let Some(h) = HistoryHarness::new().await else {
        return;
    };
    let b = h.bindings().await;
    let result = h.check_bindings(&b).unwrap();
    assert_eq!(result.phases_verified, ["admission", "issuance", "claim"]);
    assert_eq!(result.history_sequences, [4, 4, 4]);
    assert_eq!(result.history.lineage.reported_status, "not_dispatched");
    assert!(
        result
            .history
            .lineage
            .missing_links
            .iter()
            .any(|s| s.contains("clock trust"))
    );
    assert!(
        !result
            .history
            .lineage
            .missing_links
            .iter()
            .any(|s| s.contains("operation-bound installation"))
    );
    let before =
        h.h.ledger
            .read_key(&h.binding_key("issuance"))
            .await
            .unwrap();
    h.h.clock.0.store(NOW + 2, Ordering::SeqCst);
    let (installed, _) =
        h.h.ledger
            .control_snapshot(&h.c.grant.conflict_domain)
            .await
            .unwrap();
    assert!(
        h.h.post(&h.h.ack(&installed.unwrap()), true)
            .await
            .0
            .is_success()
    );
    assert!(h.h.issue().await.unwrap().reused);
    assert_eq!(
        h.h.ledger
            .read_key(&h.binding_key("issuance"))
            .await
            .unwrap(),
        before
    );
    h.held().await;
    assert!(
        h.h.ledger
            .read_key(&h.binding_key("dispatch"))
            .await
            .unwrap()
            .is_none()
    );
    let b = h.bindings().await;
    h.check_bindings(&b).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let trust = dir.path().join("trust.json");
    let bundle = dir.path().join("bundle.json");
    std::fs::write(&trust, serde_json::to_vec(&h.trust).unwrap()).unwrap();
    std::fs::write(&bundle, serde_json::to_vec(&b).unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-control-bindings"))
        .args([
            "--trust",
            trust.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["phases_verified"],
        json!(["admission", "issuance", "claim"])
    );
    let mut bad = b;
    bad.bindings[0].control.history_digest = "a".repeat(64);
    sign_bindings(&mut bad);
    std::fs::write(&bundle, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(
        !std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-control-bindings"))
            .args([
                "--trust",
                trust.to_str().unwrap(),
                "--bundle",
                bundle.to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
}
#[tokio::test]
async fn control_bindings_native_dispatch_retains_new_ack_and_later_same_clock_revocation() {
    let Some(h) = HistoryHarness::with_dispatch(true).await else {
        return;
    };
    let b = h.bindings().await;
    let result = h.check_bindings(&b).unwrap();
    assert_eq!(
        result.phases_verified,
        ["admission", "issuance", "claim", "dispatch"]
    );
    assert_eq!(result.history_sequences, [4, 4, 4, 5]);
    assert_ne!(
        b.bindings[2].control.acknowledgement_digest,
        b.bindings[3].control.acknowledgement_digest
    );
    assert_eq!(result.history.lineage.reported_status, "committed");
    h.h.revoke(RevocationTarget::Grant {
        id: h.c.grant.gid.clone(),
    })
    .await;
    let after = h.bindings().await;
    assert_eq!(
        after.history.events.last().unwrap().accepted_at,
        b.bindings[3].control.checked_at
    );
    h.check_bindings(&after).unwrap();
    // Same recorded clock, but the exact governance sequence proves this event
    // comes after the retained dispatch snapshot within the observer assertion.
    let mut forged = after;
    forged.bindings[3].control.history_sequence = 6;
    forged.bindings[3].control.history_digest = forged.history.events[5].digest().unwrap();
    sign_bindings(&mut forged);
    assert!(
        h.check_bindings(&forged)
            .unwrap_err()
            .to_string()
            .contains("revocation precedes")
    );
    assert!(
        h.h.ledger
            .authorize_dispatch(&h.c.grant, &h.grant_digest, &h.c.attempt_id)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn control_bindings_resigned_negative_snapshots_and_closed_carriage() {
    let Some(h) = HistoryHarness::with_dispatch(true).await else {
        return;
    };
    let b = h.bindings().await;
    for change in 0..19 {
        let mut bad = b.clone();
        match change {
            0 => {
                bad.bindings.remove(0);
            }
            1 => {
                bad.bindings.swap(0, 1);
            }
            2 => {
                bad.bindings[0].authority_digest = bad.bindings[1].authority_digest.clone();
            }
            3 => {
                bad.bindings[2].attempt_id = Some("other".into());
            }
            4 => {
                bad.bindings[0]
                    .control
                    .absent_revocations
                    .push(RevocationTarget::Root {
                        id: h.c.grant.root_id.clone(),
                    });
            }
            5 => {
                bad.bindings[1].control.absent_revocations.pop();
            }
            6 => {
                bad.bindings[2].control.history_sequence = 3;
                bad.bindings[2].control.history_digest = bad.history.events[2].digest().unwrap();
            }
            7 => {
                bad.bindings[3].control.acknowledgement_digest =
                    bad.bindings[2].control.acknowledgement_digest.clone();
            }
            8 => {
                bad.bindings[0].control.installation_digest = "a".repeat(64);
            }
            9 => {
                bad.bindings[3].control.history_digest = "b".repeat(64);
            }
            10 => {
                bad.bindings[3].control.history_sequence = 64;
            }
            11 => {
                bad.bindings[3].control.checked_at = h.c.grant.expires_at;
            }
            12 => {
                bad.bindings[2].control.checked_at = NOW;
            }
            13 => {
                bad.bindings[3].control.checked_at = NOW + 120001;
            }
            14 => {
                bad.checkpoint.payload.operation_key = "d".repeat(64);
            }
            15 => {
                bad.checkpoint.payload.namespace = "/wrong".into();
            }
            16 => {
                bad.checkpoint.payload.tenant = "other".into();
            }
            17 => {
                bad.checkpoint.payload.attempt_id = "other".into();
            }
            _ => {
                bad.bindings[3].control.absent_revocations.reverse();
            }
        };
        sign_bindings(&mut bad);
        assert!(
            h.check_bindings(&bad).is_err(),
            "accepted alteration {change}"
        );
    }
    let mut raw = json!(b);
    raw["bindings"][0]["control"]["non_revoked_forever"] = json!(true);
    assert!(ControlBindingsBundle::decode(&serde_json::to_vec(&raw).unwrap()).is_err());
    let mut bad = b.clone();
    bad.checkpoint.signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
    assert!(h.check_bindings(&bad).is_err());
    let mut wrong_trust = h.trust.clone();
    wrong_trust["observer_keys"]["observer-17"] = json!(
        base64::engine::general_purpose::STANDARD
            .encode(SigningKey::from_bytes(&[18; 32]).verifying_key().as_bytes())
    );
    let trust = ControlHistoryTrustConfig::decode(&serde_json::to_vec(&wrong_trust).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    assert!(verify_control_bindings(&b, &trust).is_err());
    let raw = serde_json::to_string(&b).unwrap();
    let duplicate = raw.replacen(
        "\"profile\":",
        "\"profile\":\"KF-CONTROL-BINDINGS-0.1-draft\",\"profile\":",
        1,
    );
    assert!(ControlBindingsBundle::decode(duplicate.as_bytes()).is_err());
    assert!(ControlBindingsBundle::decode(&vec![b' '; (40 << 20) + 1]).is_err());
}
#[tokio::test]
async fn control_bindings_missing_retention_refuses_without_synthesis() {
    let Some(h) = HistoryHarness::new().await else {
        return;
    };
    let original = h.bundle().await;
    delete_binding(&h, "claim").await;
    assert!(
        h.h.ledger
            .export_control_bindings(
                &h.c,
                &h.key,
                &HistoryHarness::observer(),
                &Time(NOW + 120000)
            )
            .await
            .is_err()
    );
    // Older lineage/history exports continue to work, without pretending that
    // they authenticated an operation-bound control comparison.
    h.verify(&original).unwrap();
    assert!(
        h.h.ledger
            .read_key(&h.binding_key("claim"))
            .await
            .unwrap()
            .is_none()
    );
    h.held().await;
}

#[tokio::test]
async fn control_bindings_ack_renewal_between_admission_and_issuance() {
    let Some(h) = HistoryHarness::with_mode(true, true).await else {
        return;
    };
    let b = h.bindings().await;
    assert!(h.verify(&b.history).is_err()); // Old profile requires one ack covering both samples.
    let result = h.check_bindings(&b).unwrap();
    assert_eq!(result.history_sequences, [4, 5, 5, 6]);
    assert_eq!(b.bindings[0].control.checked_at, NOW);
    assert_eq!(b.bindings[1].control.checked_at, NOW + 2);
    assert_ne!(
        b.bindings[0].control.acknowledgement_digest,
        b.bindings[1].control.acknowledgement_digest
    );
    let mut bad = b;
    bad.bindings[1].control.history_sequence = 4;
    bad.bindings[1].control.history_digest = bad.history.events[3].digest().unwrap();
    bad.bindings[1].control.acknowledgement_digest =
        bad.bindings[0].control.acknowledgement_digest.clone();
    sign_bindings(&mut bad);
    assert!(h.check_bindings(&bad).is_err());
}
