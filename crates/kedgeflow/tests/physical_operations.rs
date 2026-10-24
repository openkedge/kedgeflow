//! Offline record prerequisite over pinned immutable real-cluster evidence.
//! These tests do not enable a managed controller, persist a CAS, or deliver incidents.
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use kedgeflow::{
    contracts::{canonical, digest},
    physical_operations::*,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
const ROOT: &str = "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts";
fn public(n: u8) -> String {
    STANDARD.encode(SigningKey::from_bytes(&[n; 32]).verifying_key().as_bytes())
}
fn policy() -> Policy {
    Policy {
        profile: PROFILE.into(),
        tenant: "tenant-42".into(),
        resource_owner_id: "team:platform-owner".into(),
        on_call_team_id: "team:platform-oncall".into(),
        incident_sink: IncidentSink {
            id: "incident:platform".into(),
            url: "https://incident.test/physical".into(),
            acknowledgement_keys: BTreeMap::from([("sink-92".into(), public(92))]),
            maximum_delivery_attempts: 3,
        },
        initial_backoff_ms: 10,
        maximum_backoff_ms: 20,
        maximum_automated_queries: 2,
        reconcile_for_ms: 60000,
        post_deadline_observation: PostDeadline::QueryOnly {
            maximum_queries: 2,
            observe_for_ms: 50,
        },
        expiry_action: ExpiryAction::StopConsequentialWork,
    }
}
fn fixture(name: &str, p: &Policy) -> (Trust, kedgeflow::family_saga::AggregateBundle) {
    let input = |file: &str| {
        let path = format!("{ROOT}/{name}/{file}");
        let bytes = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(&path),
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            input_pin(&path),
            "immutable historical input changed"
        );
        bytes
    };
    let physical = kedgeflow::family_saga::AuditTrust::decode(&input("audit-trust.json")).unwrap();
    let aggregate =
        kedgeflow::family_saga::AggregateBundle::decode(&input("aggregate.json")).unwrap();
    let policy_digest = p.digest().unwrap();
    let enrollment_digest=digest("physical-operating-record-prerequisite",&json!({"family":physical.registration.digest().unwrap(),"policy":policy_digest,"scope":"O1 record/replay only; no managed controller enablement"})).unwrap();
    (
        Trust {
            profile: PROFILE.into(),
            enrollment_digest,
            policy_digest,
            child_id: "child-1".into(),
            physical,
            observer: kedgeflow::family_saga::ObserverPin {
                id: "operating-history-observer".into(),
                keys: BTreeMap::from([("operating-91".into(), public(91))]),
            },
        },
        aggregate,
    )
}
fn unknown(p: &Policy) -> (Trust, History, i64) {
    let (t, b) = fixture("kube-drain-sdk-unknown", p);
    let at = b.checkpoint.captured_at;
    let h = History::open(p.clone(), &t, b, at).unwrap();
    (t, h, at)
}
fn sign(h: History, t: &Trust, at: i64) -> Bundle {
    Bundle::sign(h, t, "operating-91", &SigningKey::from_bytes(&[91; 32]), at).unwrap()
}
#[test]
fn physical_operating_policy_is_closed_and_safe_integer_bounded() {
    let good = policy();
    let value = json!(good);
    assert_eq!(Policy::decode(&canonical(&value).unwrap()).unwrap(), good);
    for (field, bad) in [
        ("profile", json!("KF-KUBE-DRAIN-0.1-draft")),
        ("tenant", json!("")),
        ("initial_backoff_ms", json!(0)),
        ("maximum_backoff_ms", json!(9)),
        ("maximum_automated_queries", json!(65)),
        ("reconcile_for_ms", json!(0)),
        ("expiry_action", json!("retry")),
        (
            "post_deadline_observation",
            json!({"mode":"disabled","maximum_queries":1}),
        ),
        (
            "post_deadline_observation",
            json!({"mode":"query_only","maximum_queries":0,"observe_for_ms":10}),
        ),
        ("incident_sink", json!(null)),
        ("extra", json!(true)),
    ] {
        let mut v = value.clone();
        v[field] = bad;
        assert!(
            Policy::decode(&canonical(&v).unwrap()).is_err(),
            "accepted {field}"
        );
    }
    for field in value.as_object().unwrap().keys() {
        let mut v = value.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(Policy::decode(&canonical(&v).unwrap()).is_err());
    }
    for url in [
        "http://incident.test/physical",
        "https://user@incident.test/physical",
        "https://incident.test/physical?q=1",
    ] {
        let mut p = good.clone();
        p.incident_sink.url = url.into();
        assert!(p.validate().is_err());
    }
    let raw = String::from_utf8(canonical(&value).unwrap()).unwrap();
    for raw in [
        raw.replace("60000", "6e4"),
        raw.replace("60000", "60000.0"),
        raw.replace("60000", "9007199254740992"),
        raw.replacen("{", "{\"profile\":\"duplicate\",", 1),
    ] {
        assert!(Policy::decode(raw.as_bytes()).is_err());
    }
}
#[test]
fn physical_operating_native_committed_is_not_physical_resolution_or_a_new_deadline() {
    let (t, h, at) = unknown(&policy());
    let s = h.replay(&t).unwrap();
    assert_eq!(s.observation.native_status, "committed");
    assert_eq!(s.observation.resolution, Resolution::Unresolved);
    assert_eq!(s.deadline, h.original.dispatched_at + 60000);
    assert!(!s.execution_authority);
    assert!(!s.stop_required);
    let restarted = History::decode(&canonical(&json!(h)).unwrap()).unwrap();
    assert_eq!(restarted.replay(&t).unwrap(), s);
    assert!(
        Bundle::sign(
            restarted.clone(),
            &t,
            "operating-91",
            &SigningKey::from_bytes(&[91; 32]),
            s.deadline
        )
        .is_err()
    );
    let stopped = restarted.escalate(&t, s.deadline).unwrap();
    let stopped_state = stopped.replay(&t).unwrap();
    assert!(stopped_state.stop_required);
    assert_eq!(stopped_state.observation.resolution, Resolution::Unresolved);
    let i = stopped_state.incident.unwrap();
    assert_eq!(i.resource_owner_id, "team:platform-owner");
    assert_eq!(i.on_call_team_id, "team:platform-oncall");
    assert_eq!(
        sign(stopped, &t, s.deadline).verify(&t).unwrap().deadline,
        s.deadline
    );
    assert!(h.escalate(&t, at).is_err());
}
#[test]
fn physical_operating_query_slot_survives_restart_and_is_consumed_before_io() {
    let (t, h, at) = unknown(&policy());
    let pending = h.reserve_query(&t, at).unwrap();
    let pending = History::decode(&canonical(&json!(pending)).unwrap()).unwrap();
    assert!(pending.reserve_query(&t, at + 100).is_err());
    let s = pending.replay(&t).unwrap();
    assert_eq!(s.before_queries, 1);
    assert_eq!(s.pending.unwrap().number, 1);
    let h = pending
        .record_unavailable(&t, at + 1, Unavailable::Interrupted)
        .unwrap();
    assert!(h.reserve_query(&t, at + 9).is_err());
    let h = h
        .reserve_query(&t, at + 10)
        .unwrap()
        .record_unavailable(&t, at + 11, Unavailable::Malformed)
        .unwrap();
    assert!(h.reserve_query(&t, at + 100).is_err());
    let s = sign(h, &t, at + 11).verify(&t).unwrap();
    assert_eq!(s.before_queries, 2);
    assert_eq!(s.after_queries, 0);
    assert_eq!(s.next_allowed_at, at + 30);
    assert_eq!(s.observation.resolution, Resolution::Unresolved);
}
#[test]
fn physical_operating_post_deadline_queries_require_an_owned_stop_and_finite_budget() {
    let (t, h, _) = unknown(&policy());
    let deadline = h.replay(&t).unwrap().deadline;
    let h = h.reserve_query(&t, deadline).unwrap();
    let s = h.replay(&t).unwrap();
    assert!(s.stop_required);
    assert!(s.incident.is_some());
    assert_eq!(s.after_queries, 1);
    let h = h
        .record_unavailable(&t, deadline + 1, Unavailable::Transport)
        .unwrap()
        .reserve_query(&t, deadline + 10)
        .unwrap()
        .record_unavailable(&t, deadline + 11, Unavailable::Interrupted)
        .unwrap();
    assert!(h.reserve_query(&t, deadline + 30).is_err());
    assert!(h.reserve_query(&t, deadline + 50).is_err());
    assert!(h.escalate(&t, deadline + 40).is_err());
    let mut p = policy();
    p.post_deadline_observation = PostDeadline::Disabled;
    let (t, h, _) = unknown(&p);
    let deadline = h.replay(&t).unwrap().deadline;
    assert!(h.reserve_query(&t, deadline).is_err());
    let h = h.escalate(&t, deadline).unwrap();
    assert!(h.reserve_query(&t, deadline).is_err());
    assert!(sign(h, &t, deadline).verify(&t).unwrap().stop_required);
}
#[test]
fn physical_operating_only_complete_signed_original_physical_evidence_resolves() {
    let (t, h, at) = unknown(&policy());
    let same = h.aggregates.values().next().unwrap().clone();
    let h = h
        .reserve_query(&t, at)
        .unwrap()
        .record_observation(&t, at + 1, same.clone())
        .unwrap();
    assert_eq!(
        h.replay(&t).unwrap().observation.resolution,
        Resolution::Unresolved
    );
    let mut bad = same.clone();
    bad.evidence
        .current
        .snapshot
        .members
        .get_mut("child-1")
        .unwrap()
        .physical
        .as_mut()
        .unwrap()
        .controller
        .as_mut()
        .unwrap()
        .body
        .steps
        .clear();
    assert!(
        h.reserve_query(&t, at + 10)
            .unwrap()
            .record_observation(&t, at + 11, bad)
            .is_err()
    );
    let (_, different) = fixture("kube-drain-sdk-completed", &policy());
    assert!(
        h.reserve_query(&t, at + 10)
            .unwrap()
            .record_observation(&t, at + 11, different)
            .is_err()
    );
    for (name, resolution) in [
        ("kube-drain-sdk-completed", Resolution::ObservedCompleted),
        ("kube-drain-no-effect", Resolution::NoPhysicalEffect),
        ("kube-drain-process-absent", Resolution::NoPhysicalDispatch),
    ] {
        let (t, b) = fixture(name, &policy());
        let at = b.checkpoint.captured_at;
        let h = History::open(policy(), &t, b, at).unwrap();
        let s = sign(h.clone(), &t, at).verify(&t).unwrap();
        assert_eq!(s.observation.resolution, resolution);
        assert!(s.stop_required);
        assert!(h.reserve_query(&t, at + 1).is_err());
        assert!(!s.execution_authority);
    }
}
#[test]
fn physical_operating_replay_refuses_forged_correlations_omissions_and_clock_changes() {
    let (t, h, at) = unknown(&policy());
    let h = h
        .reserve_query(&t, at)
        .unwrap()
        .record_unavailable(&t, at + 1, Unavailable::Interrupted)
        .unwrap();
    let original = json!(h);
    for path in [
        "sequence",
        "original_digest",
        "policy_digest",
        "previous_digest",
        "at",
        "change",
    ] {
        let mut v = original.clone();
        v["events"][1][path] = match path {
            "sequence" => json!(99),
            "at" => json!(at - 1),
            "change" => json!({"kind":"query_reserved","number":9,"stage":"before_deadline"}),
            _ => json!("a".repeat(64)),
        };
        let bad = History::decode(&canonical(&v).unwrap()).unwrap();
        assert!(bad.replay(&t).is_err(), "accepted {path}");
    }
    let mut bad = h.clone();
    bad.original.attempt_id = "replacement".into();
    assert!(bad.replay(&t).is_err());
    let mut bad = h.clone();
    bad.events.remove(1);
    assert!(bad.replay(&t).is_err());
    let mut bad = h.clone();
    let b = bad.aggregates.values().next().unwrap().clone();
    bad.aggregates.insert("a".repeat(64), b);
    assert!(bad.replay(&t).is_err());
    let mut bad = h;
    bad.policy.maximum_automated_queries = 3;
    assert!(bad.replay(&t).is_err());
}
#[test]
fn physical_operating_checkpoints_require_separate_pins_and_exact_complete_history() {
    let (t, h, at) = unknown(&policy());
    let b = sign(h, &t, at);
    assert!(b.verify(&t).is_ok());
    let mut wrong = t.clone();
    wrong
        .observer
        .keys
        .insert("operating-91".into(), public(90));
    assert!(b.verify(&wrong).is_err());
    let mut wrong = t.clone();
    wrong.observer = t
        .physical
        .registration
        .composition
        .as_ref()
        .unwrap()
        .observer
        .clone();
    assert!(b.verify(&wrong).is_err());
    for field in [
        "profile",
        "event_count",
        "head_digest",
        "history_digest",
        "original_digest",
        "enrollment_digest",
        "signature",
        "captured_at",
    ] {
        let mut v = json!(b);
        v["checkpoint"][field] = match field {
            "event_count" => json!(0),
            "captured_at" => json!(at - 1),
            _ => json!("b".repeat(64)),
        };
        assert!(
            Bundle::decode(&canonical(&v).unwrap())
                .unwrap()
                .verify(&t)
                .is_err(),
            "accepted {field}"
        );
    }
    for field in ["profile", "history", "checkpoint"] {
        let mut v = json!(b);
        v.as_object_mut().unwrap().remove(field);
        assert!(Bundle::decode(&canonical(&v).unwrap()).is_err());
    }
    let mut v = json!(b);
    v["checkpoint"]["extra"] = json!(null);
    assert!(Bundle::decode(&canonical(&v).unwrap()).is_err());
    let mut v = json!(b);
    v["history"]["events"][0]
        .as_object_mut()
        .unwrap()
        .remove("previous_digest");
    assert!(Bundle::decode(&canonical(&v).unwrap()).is_err());
}
#[test]
fn physical_operating_shipping_offline_verifier_replays_original_unknown_completed_and_no_effect() {
    for (name, fixture_name) in [
        ("unknown", "kube-drain-sdk-unknown"),
        ("completed", "kube-drain-sdk-completed"),
        ("no-effect", "kube-drain-no-effect"),
        ("no-dispatch", "kube-drain-process-absent"),
    ] {
        let p = policy();
        let (t, b) = fixture(fixture_name, &p);
        let at = b.checkpoint.captured_at;
        let mut h = History::open(p, &t, b, at).unwrap();
        let captured = if name == "unknown" {
            let d = h.replay(&t).unwrap().deadline;
            h = h
                .reserve_query(&t, d)
                .unwrap()
                .record_unavailable(&t, d + 1, Unavailable::Interrupted)
                .unwrap();
            d + 1
        } else {
            at
        };
        let b = sign(h, &t, captured);
        let s = b.verify(&t).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("bundle.json"), canonical(&json!(b)).unwrap()).unwrap();
        std::fs::write(dir.join("trust.json"), canonical(&json!(t)).unwrap()).unwrap();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_kf-physical-operations"))
            .arg("--bundle")
            .arg(dir.join("bundle.json"))
            .arg("--trust")
            .arg(dir.join("trust.json"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&out.stdout).unwrap(),
            json!(s)
        );
        if let Some(root) = std::env::var_os("KF_CONFORMANCE_ARTIFACTS") {
            let public = PathBuf::from(root).join("physical-operating").join(name);
            std::fs::create_dir_all(&public).unwrap();
            for file in ["bundle.json", "trust.json"] {
                std::fs::copy(dir.join(file), public.join(file)).unwrap();
            }
            std::fs::write(public.join("verification.json"), out.stdout).unwrap();
        }
    }
}

fn input_pin(path: &str) -> &str {
    match path {
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-sdk-unknown/aggregate.json" => {
            "7d85356c98211a872b4a18b4dd87c97bb60e6ef25327365d09e95a368b44592b"
        }
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-sdk-unknown/audit-trust.json" => {
            "70541c61c7ef7e6bf7508d0ab01f513c098504421a13d2d0335607b03d888dd5"
        }
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-sdk-completed/aggregate.json" => {
            "0688c5e0cdcadf58ef7a3ec48f66faa240931a50a4da79abb1bf85ba59ce72b0"
        }
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-sdk-completed/audit-trust.json" => {
            "ab91c29f90dfd84d8e6fe05fef4afef055823962679793f1a8b78d22d71872db"
        }
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-no-effect/aggregate.json" => {
            "2c10fc73a80f7591eaa592b360aa9111fb7ce8dca1c3b2b01dd4988f4a76fe91"
        }
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-no-effect/audit-trust.json" => {
            "77493daae9782621fd65e7b217108a3f57f9ee25c78b858b98d32b2150b4bf87"
        }
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-process-absent/aggregate.json" => {
            "31b2ad879adfeacb52393ce5cab8ed86a316c0e129888352774467cbc64914c9"
        }
        "results/verification/rfc-m8-kubernetes-sdk-2026-10-23/native-artifacts/kube-drain-process-absent/audit-trust.json" => {
            "25c505a73d5100843296319cc6b827e3f068c51ab08e2c7f10883f05ec9b8c6f"
        }
        _ => panic!("unregistered historical evidence input"),
    }
}

#[test]
fn physical_operating_full_64_plus_64_budget_has_a_complete_bounded_history() {
    let mut p = policy();
    p.initial_backoff_ms = 1;
    p.maximum_backoff_ms = 1;
    p.maximum_automated_queries = 64;
    p.post_deadline_observation = PostDeadline::QueryOnly {
        maximum_queries: 64,
        observe_for_ms: 1000,
    };
    let (t, mut h, at) = unknown(&p);
    for i in 0..64 {
        h = h
            .reserve_query(&t, at + i)
            .unwrap()
            .record_unavailable(&t, at + i, Unavailable::Interrupted)
            .unwrap();
    }
    let deadline = h.replay(&t).unwrap().deadline;
    for i in 0..64 {
        h = h
            .reserve_query(&t, deadline + i)
            .unwrap()
            .record_unavailable(&t, deadline + i, Unavailable::Malformed)
            .unwrap();
    }
    assert_eq!(h.events.len(), MAX_EVENTS);
    assert!(h.reserve_query(&t, deadline + 64).is_err());
    let b = sign(
        History::decode(&canonical(&json!(h)).unwrap()).unwrap(),
        &t,
        deadline + 64,
    );
    let s = b.verify(&t).unwrap();
    assert_eq!((s.before_queries, s.after_queries), (64, 64));
    assert!(s.stop_required);
    assert!(s.incident.is_some());
    assert_eq!(s.observation.resolution, Resolution::Unresolved);
}
#[test]
fn physical_operating_historical_cache_never_hides_changed_policy_or_role_pins() {
    let p = policy();
    let (t, h, at) = unknown(&p);
    assert!(h.replay(&t).is_ok());
    let mut bad = t.clone();
    bad.enrollment_digest = "f".repeat(64);
    assert!(h.replay(&bad).is_err());
    let mut p = p;
    p.incident_sink
        .acknowledgement_keys
        .insert("sink-92".into(), public(1));
    let (bad, b) = fixture("kube-drain-sdk-unknown", &p);
    assert!(History::open(p, &bad, b, at).is_err());
    let mut bad = t;
    bad.physical
        .registration
        .composition
        .as_mut()
        .unwrap()
        .nodes
        .iter_mut()
        .find(|n| n.child_id == "child-1")
        .unwrap()
        .physical
        .as_mut()
        .unwrap()
        .observer
        .keys
        .insert("replacement".into(), public(90));
    assert!(h.replay(&bad).is_err());
}
