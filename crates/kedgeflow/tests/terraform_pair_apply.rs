use kedgeflow::{
    contracts::{Action, Resource, validate_action_adapter},
    terraform_pair, terraform_pair_apply as pair,
};
use serde_json::json;
fn manifest() -> terraform_pair::Manifest {
    terraform_pair::Manifest::decode(include_bytes!(
        "../../../fixtures/terraform-pair-plan/manifest.json"
    ))
    .unwrap()
}
#[test]
fn pair_action_is_separate_and_binds_both_incarnations() {
    let mut m = manifest();
    let first = pair::incarnation(&m).unwrap();
    m.members[1].target.uid = "another-second-uid".into();
    assert_ne!(first, pair::incarnation(&m).unwrap());
    let r = Resource {
        id: format!("terraform-pair:{}", "a".repeat(64)),
        incarnation: first,
    };
    let a = Action {
        id: pair::ACTION.into(),
        version: "1.0".into(),
        digest: "a".repeat(64),
    };
    assert!(validate_action_adapter(&a, &pair::adapter_contract(), &r, None).is_ok());
    assert!(
        validate_action_adapter(
            &a,
            &kedgeflow::terraform_apply::adapter_contract(),
            &r,
            None
        )
        .is_err()
    );
    let schema = pair::parameter_schema(&"a".repeat(64), &"b".repeat(64), &r.id).unwrap();
    kedgeflow::leaf_action::validate_schema(pair::ACTION, "1.0", &schema).unwrap();
    let params = json!({"node":r.id,"expected_version":1,"manifest_digest":"a".repeat(64),"effect_digest":"b".repeat(64)});
    assert_eq!(
        kedgeflow::leaf_action::bind(pair::ACTION, "1.0", &params, &r, "expected_version").unwrap(),
        1
    );
    let mut bad = params;
    bad["command"] = json!("apply");
    assert!(
        kedgeflow::leaf_action::bind(pair::ACTION, "1.0", &bad, &r, "expected_version").is_err()
    );
}
fn outcome(states: [&str; 2], tool: Option<bool>, backend: bool) -> pair::Outcome {
    let mut o = pair::Outcome::started(&manifest());
    o.tool_succeeded = tool;
    o.backend_progress = backend;
    for (m, state) in o.members.iter_mut().zip(states) {
        m.state = state.into();
        m.observation_digest = Some("a".repeat(64));
        m.observed_at = Some(1);
    }
    o
}
#[test]
fn observations_never_promote_failed_or_unfinished_tool_to_committed() {
    for (states, tool, backend, expected) in [
        (["desired", "desired"], Some(true), true, "applied"),
        (
            ["desired", "original_observed"],
            Some(false),
            true,
            "partial_observed",
        ),
        (
            ["original_observed", "desired"],
            Some(false),
            true,
            "unknown",
        ),
        (["desired", "desired"], Some(false), true, "unknown"),
        (["desired", "original_observed"], None, true, "unknown"),
        (
            ["desired", "original_observed"],
            Some(false),
            false,
            "unknown",
        ),
        (["desired", "unresolved"], Some(false), true, "unknown"),
        (
            ["original_observed", "original_observed"],
            Some(false),
            false,
            "unknown",
        ),
    ] {
        let o = outcome(states, tool, backend);
        assert_eq!(o.state(), expected);
        o.validate(&manifest(), expected).unwrap();
        if expected != "applied" {
            assert!(o.validate(&manifest(), "applied").is_err());
        }
    }
}
#[test]
fn retained_member_observations_are_exact_and_closed() {
    let m = manifest();
    pair::Outcome::started(&m).validate(&m, "started").unwrap();
    let valid = outcome(["desired", "original_observed"], Some(false), true);
    let mut bad = valid.clone();
    bad.members.reverse();
    assert!(bad.validate(&m, "partial_observed").is_err());
    let mut bad = valid.clone();
    bad.members[1].target_uid = "other".into();
    assert!(bad.validate(&m, "partial_observed").is_err());
    let mut bad = valid.clone();
    bad.members[0].observation_digest = None;
    assert!(bad.validate(&m, "partial_observed").is_err());
    let mut bad = serde_json::to_value(valid).unwrap();
    bad["members"][0]["execution_credential"] = json!("no");
    assert!(serde_json::from_value::<pair::Outcome>(bad).is_err());
}
