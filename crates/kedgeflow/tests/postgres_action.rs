use kedgeflow::postgres_action::{ACTION, DispatchRequest, Outcome, PROFILE, Parameters, validate};
use serde_json::{Value, json};

fn request() -> Value {
    json!({"profile":PROFILE,"action":ACTION,"tenant":"tenant-42",
        "conflict_domain":"tenant-42:reservations","attempt_id":"attempt-1",
        "grant_digest":"a".repeat(64),"root_id":"root-1",
        "resource":{"id":"slot-1","incarnation":"incarnation-1"},
        "expected_version":1,"fence":1,"reservation":"booking-1",
        "gateway_workload":"spiffe://example.org/gateway","expires_at":2_000_000_000_000u64})
}
fn raw(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn registered_action_records_are_closed_and_integer_bounded() {
    let q = request();
    let decoded = DispatchRequest::decode(&raw(&q)).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), q);
    for (field, value) in [
        ("action", json!("arbitrary.sql")),
        ("profile", json!("KF-JSON-0.2")),
        ("fence", json!(0)),
        ("expected_version", json!(9_007_199_254_740_991u64)),
        ("expires_at", json!(-1)),
        ("grant_digest", json!("not-a-digest")),
        ("gateway_workload", json!("identity-header")),
        ("reservation", json!("x; DROP TABLE resource")),
    ] {
        let mut bad = q.clone();
        bad[field] = value;
        assert!(DispatchRequest::decode(&raw(&bad)).is_err(), "{field}");
    }
    let mut bad = q.clone();
    bad["sql"] = json!("DELETE FROM resource");
    assert!(validate(&bad).is_err());
    bad = q.clone();
    bad["resource"]["route"] = json!("other-target");
    assert!(validate(&bad).is_err());
    bad = q;
    bad.as_object_mut().unwrap().remove("root_id");
    assert!(validate(&bad).is_err());
}

#[test]
fn duplicate_and_floating_wire_fields_are_refused() {
    let q = String::from_utf8(raw(&request())).unwrap();
    let duplicate = q.replacen('{', "{\"fence\":2,", 1);
    assert!(DispatchRequest::decode(duplicate.as_bytes()).is_err());
    let floating = q.replace("\"fence\":1", "\"fence\":1.0");
    assert_ne!(floating, q);
    assert!(DispatchRequest::decode(floating.as_bytes()).is_err());
    assert!(DispatchRequest::decode(&vec![b' '; 32 * 1024 + 1]).is_err());
}

#[test]
fn application_parameters_cannot_supply_target_authority() {
    let q = json!({"resource_id":"slot-1","expected_version":1,"reservation":"booking-1"});
    assert!(Parameters::decode(&raw(&q)).is_ok());
    for key in [
        "fence",
        "attempt_id",
        "grant_digest",
        "gateway_workload",
        "tenant",
    ] {
        let mut bad = q.clone();
        bad[key] = json!("caller-supplied");
        assert!(Parameters::decode(&raw(&bad)).is_err());
    }
}

#[test]
fn terminal_outcomes_bind_every_original_request_field() {
    let q = request();
    let expected = DispatchRequest::decode(&raw(&q)).unwrap();
    let committed = json!({"profile":PROFILE,"request":q,"status":"committed","post_version":2});
    assert!(Outcome::verify(&raw(&committed), &expected).is_ok());
    for field in [
        "tenant",
        "root_id",
        "attempt_id",
        "reservation",
        "gateway_workload",
    ] {
        let mut bad = committed.clone();
        bad["request"][field] = if field == "gateway_workload" {
            json!("spiffe://example.org/other")
        } else {
            json!("substituted")
        };
        assert!(Outcome::verify(&raw(&bad), &expected).is_err(), "{field}");
    }
    for post in [json!(1), json!(3), Value::Null] {
        let mut bad = committed.clone();
        bad["post_version"] = post;
        assert!(Outcome::verify(&raw(&bad), &expected).is_err());
    }
    let mut refused = committed;
    refused["status"] = json!("guard_rejected");
    assert!(Outcome::verify(&raw(&refused), &expected).is_err());
    refused["post_version"] = Value::Null;
    assert!(Outcome::verify(&raw(&refused), &expected).is_ok());
}
