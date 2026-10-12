use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use kedgeflow::contracts::{
    Envelope, Grant, GrantVerifier, MAX_SAFE_INTEGER, PROFILE, canonical, digest, record_digest,
    sign_grant, signature_input, strict_value, verify_envelope,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(format!("{name}.json")),
    )
    .unwrap()
}

fn executable_grant() -> Grant {
    let envelope: Envelope =
        serde_json::from_value(strict_value(&fixture("grant")).unwrap()).unwrap();
    let mut grant: Grant = serde_json::from_value(envelope.payload).unwrap();
    grant.completion_mode = "dispatch_bound".into();
    grant.parent_grant_digest = None;
    grant.saga_budget = Value::Null;
    grant.predicate_descriptor = json!({
        "id": "node-version",
        "version": "1.0",
        "language": "kf-conjunction-v1",
        "clauses": [{
            "kind": "version_eq",
            "resource": grant.resources[0],
            "expected_version": "241"
        }]
    });
    grant.adapter_contract = json!({
        "level": "Level_A",
        "guard_primitive": "FencingToken",
        "fence_parameter": "kf_fence",
        "guard_scope": [grant.resources[0].id],
        "completion_mode": "dispatch_bound",
        "commit_point": "mock atomic version+fence+mutation",
        "idempotency": {
            "mode": "resource_key",
            "parameter": "kf_attempt_id",
            "retention_ms": 60000
        }
    });
    grant
}

fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

fn verifier(grant: &Grant, key: &SigningKey) -> GrantVerifier {
    GrantVerifier {
        keys: BTreeMap::from([("issuer-test".into(), key.verifying_key())]),
        audience: grant.audience.clone(),
    }
}

fn resign(value: Value, key: &SigningKey) -> Vec<u8> {
    let mut envelope: Envelope = serde_json::from_value(value).unwrap();
    envelope.signature =
        URL_SAFE_NO_PAD.encode(key.sign(&signature_input(&envelope).unwrap()).to_bytes());
    canonical(&serde_json::to_value(envelope).unwrap()).unwrap()
}

#[test]
fn retained_grant_authentication_never_establishes_execution_validity() {
    let g = executable_grant();
    let key = test_key();
    let v = verifier(&g, &key);
    let raw = sign_grant(&g, "issuer-test", &key).unwrap();
    assert!(v.verify(&raw, g.expires_at).is_err());
    assert!(v.verify(&raw, g.valid_from - 1).is_err());
    assert_eq!(v.verify_retained(&raw).unwrap().grant, g);
    let mut wrong = g.clone();
    wrong.expires_at = wrong.valid_from;
    assert!(
        v.verify_retained(&sign_grant(&wrong, "issuer-test", &key).unwrap())
            .is_err()
    );
    wrong = g;
    wrong.audience = "https://other.test/mcp".into();
    assert!(
        v.verify_retained(&sign_grant(&wrong, "issuer-test", &key).unwrap())
            .is_err()
    );
}

#[test]
fn all_thirteen_published_envelopes_match_signature_and_digest_vectors() {
    let registry = strict_value(&fixture("public-test-keys")).unwrap();
    let mut keys = BTreeMap::new();
    for (id, entry) in registry.as_object().unwrap() {
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(entry["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        keys.insert(id.clone(), VerifyingKey::from_bytes(&bytes).unwrap());
    }
    assert_eq!(keys.len(), 9);
    let expected = strict_value(&fixture("fixture-digests")).unwrap();
    assert_eq!(expected.as_object().unwrap().len(), 13);
    for (kind, expected_digest) in expected.as_object().unwrap() {
        let raw = fixture(kind);
        let envelope = verify_envelope(&raw, &keys).unwrap();
        assert_eq!(&envelope.kind, kind);
        assert_eq!(
            record_digest(&envelope).unwrap(),
            expected_digest.as_str().unwrap()
        );
        // Whitespace and object property order do not alter signed bytes.
        let compact = canonical(&strict_value(&raw).unwrap()).unwrap();
        assert_eq!(verify_envelope(&compact, &keys).unwrap(), envelope);
    }
    // The pinned fixture remains a valid broader record, not an executable
    // promise of saga or asynchronous commit support in this restricted slice.
    let grant: Grant =
        serde_json::from_value(verify_envelope(&fixture("grant"), &keys).unwrap().payload).unwrap();
    let runtime = GrantVerifier {
        keys,
        audience: grant.audience,
    };
    assert!(runtime.verify(&fixture("grant"), grant.valid_from).is_err());
}

#[test]
fn published_parameter_digest_and_signature_domain_are_unchanged() {
    let proposal = strict_value(&fixture("proposal")).unwrap();
    let grant = strict_value(&fixture("grant")).unwrap();
    assert_eq!(
        digest("parameters", &proposal["payload"]["parameters"]).unwrap(),
        grant["payload"]["parameters_digest"].as_str().unwrap()
    );
    let value = json!({"a": 1, "b": null});
    let encoded = canonical(&value).unwrap();
    let mut expected = Sha256::new();
    expected.update(b"KedgeFlow/KF-JSON-0.2/parameters\0");
    expected.update(&encoded);
    assert_eq!(
        digest("parameters", &value).unwrap(),
        hex::encode(expected.finalize())
    );
    assert_ne!(
        digest("parameters", &value).unwrap(),
        digest("grant", &value).unwrap()
    );
    assert_ne!(
        digest("parameters", &value).unwrap(),
        hex::encode(Sha256::digest(&encoded))
    );
}

#[test]
fn unicode_property_order_uses_utf16_without_normalization() {
    let value = strict_value(
        r#"{"\ue000":"bmp","\ud800\udc00":"supp","\r":"control","1":"digit","ö":"latin","€":"euro","😀":"face"}"#
            .as_bytes(),
    )
    .unwrap();
    let expected = "{\"\\r\":\"control\",\"1\":\"digit\",\"ö\":\"latin\",\"€\":\"euro\",\"𐀀\":\"supp\",\"😀\":\"face\",\"\u{e000}\":\"bmp\"}";
    assert_eq!(
        String::from_utf8(canonical(&value).unwrap()).unwrap(),
        expected
    );
    assert_ne!(
        canonical(&json!("é")).unwrap(),
        canonical(&json!("e\u{301}")).unwrap()
    );
    assert_eq!(
        canonical(&strict_value(br#"{"s":"\/\b\f\n\r\t\u0000"}"#).unwrap()).unwrap(),
        br#"{"s":"/\b\f\n\r\t\u0000"}"#
    );
}

#[test]
fn strict_json_rejects_duplicate_unicode_numeric_and_trailing_ambiguity() {
    for raw in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#.as_slice(),
        br#"{"nested":[{"x":true,"x":false}]}"#.as_slice(),
        br#"{"s":"\ud800"}"#.as_slice(),
        br#"{"s":"\udc00"}"#.as_slice(),
        b"1.0".as_slice(),
        b"1e0".as_slice(),
        b"-0.0".as_slice(),
        b"1E2".as_slice(),
        b"9007199254740992".as_slice(),
        b"-9007199254740992".as_slice(),
        b"18446744073709551616".as_slice(),
        b"NaN".as_slice(),
        b"Infinity".as_slice(),
        b"{} {}".as_slice(),
        b"[] garbage".as_slice(),
        b"{\"s\":\"\xff\"}".as_slice(),
    ] {
        assert!(strict_value(raw).is_err(), "accepted {:?}", raw);
    }
    for raw in [
        b"null".as_slice(),
        b"true".as_slice(),
        b"false".as_slice(),
        b"-0".as_slice(),
        b"9007199254740991".as_slice(),
        b"-9007199254740991".as_slice(),
        br#"{"text":"1.0 1e9", "negative":-2}"#.as_slice(),
    ] {
        assert!(strict_value(raw).is_ok(), "rejected {:?}", raw);
    }
    assert_eq!(canonical(&strict_value(b"-0").unwrap()).unwrap(), b"0");
    assert!(canonical(&json!(1.0)).is_err());
    assert!(canonical(&json!(MAX_SAFE_INTEGER + 1)).is_err());
}

#[test]
fn exact_grant_signing_round_trip_preserves_raw_and_digest() {
    let grant = executable_grant();
    let key = test_key();
    let raw = sign_grant(&grant, "issuer-test", &key).unwrap();
    let verified = verifier(&grant, &key)
        .verify(&raw, grant.valid_from)
        .unwrap();
    assert_eq!(verified.grant, grant);
    assert_eq!(verified.raw, raw);
    assert_eq!(
        verified.digest,
        digest("grant", &strict_value(&raw).unwrap()).unwrap()
    );
    let envelope: Envelope = serde_json::from_value(strict_value(&raw).unwrap()).unwrap();
    assert!(
        signature_input(&envelope)
            .unwrap()
            .starts_with(b"KedgeFlow/KF-JSON-0.2\0")
    );
    assert_eq!(sign_grant(&grant, "issuer-test", &key).unwrap(), raw);
}

#[test]
fn every_grant_field_remains_required_including_nullable_fields() {
    let grant = executable_grant();
    let key = test_key();
    let raw = sign_grant(&grant, "issuer-test", &key).unwrap();
    let value = strict_value(&raw).unwrap();
    let verifier = verifier(&grant, &key);
    for field in value["payload"].as_object().unwrap().keys() {
        let mut altered = value.clone();
        altered["payload"].as_object_mut().unwrap().remove(field);
        assert!(
            verifier
                .verify(&resign(altered, &key), grant.valid_from)
                .is_err(),
            "omitted required grant field {field}"
        );
    }
}

#[test]
fn required_closed_envelope_and_nested_identity_fields_are_enforced() {
    let grant = executable_grant();
    let key = test_key();
    let raw = sign_grant(&grant, "issuer-test", &key).unwrap();
    let value = strict_value(&raw).unwrap();
    let verifier = verifier(&grant, &key);
    for field in value.as_object().unwrap().keys() {
        let mut altered = value.clone();
        altered.as_object_mut().unwrap().remove(field);
        assert!(
            verifier
                .verify(&serde_json::to_vec(&altered).unwrap(), grant.valid_from)
                .is_err()
        );
    }
    let mut extra = value.clone();
    extra["unexpected"] = json!(true);
    assert!(
        verifier
            .verify(&serde_json::to_vec(&extra).unwrap(), grant.valid_from)
            .is_err()
    );
    for field in ["subject", "action", "policy"] {
        let mut altered = value.clone();
        altered["payload"][field]["unexpected"] = json!(true);
        assert!(
            verifier
                .verify(&resign(altered, &key), grant.valid_from)
                .is_err()
        );
    }
    let mut altered = value.clone();
    altered["payload"]["resources"][0]["unexpected"] = json!(true);
    assert!(
        verifier
            .verify(&resign(altered, &key), grant.valid_from)
            .is_err()
    );
    let mut case_alias = value.clone();
    let gid = case_alias["payload"]
        .as_object_mut()
        .unwrap()
        .remove("gid")
        .unwrap();
    case_alias["payload"]["GID"] = gid;
    assert!(
        verifier
            .verify(&resign(case_alias, &key), grant.valid_from)
            .is_err()
    );
    for pointer in [
        "/payload/subject",
        "/payload/action",
        "/payload/policy",
        "/payload/resources/0",
        "/payload/predicate_descriptor",
        "/payload/predicate_descriptor/clauses/0",
        "/payload/predicate_descriptor/clauses/0/resource",
        "/payload/adapter_contract",
        "/payload/adapter_contract/idempotency",
    ] {
        for field in value.pointer(pointer).unwrap().as_object().unwrap().keys() {
            let mut altered = value.clone();
            altered
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                verifier
                    .verify(&resign(altered, &key), grant.valid_from)
                    .is_err(),
                "omitted required field {pointer}/{field}"
            );
        }
    }
}

#[test]
fn cryptographic_and_envelope_substitution_is_refused() {
    let grant = executable_grant();
    let key = test_key();
    let raw = sign_grant(&grant, "issuer-test", &key).unwrap();
    let value = strict_value(&raw).unwrap();
    let verifier = verifier(&grant, &key);
    let mut tampered = value.clone();
    tampered["payload"]["fence"] = json!(grant.fence + 1);
    assert!(
        verifier
            .verify(&canonical(&tampered).unwrap(), grant.valid_from)
            .is_err()
    );
    let mut tampered = value.clone();
    tampered["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
    assert!(
        verifier
            .verify(&canonical(&tampered).unwrap(), grant.valid_from)
            .is_err()
    );
    let mut tampered = value.clone();
    tampered["signature"] = json!(format!("{}==", value["signature"].as_str().unwrap()));
    assert!(
        verifier
            .verify(&canonical(&tampered).unwrap(), grant.valid_from)
            .is_err()
    );
    let mut wrong_key = verifier.clone();
    wrong_key.keys.insert(
        "issuer-test".into(),
        SigningKey::from_bytes(&[3; 32]).verifying_key(),
    );
    assert!(wrong_key.verify(&raw, grant.valid_from).is_err());
    for (field, replacement) in [
        ("profile", "KF-JSON-0.1"),
        ("kind", "unknown"),
        ("schema", "https://attacker.test/schema"),
        ("key_id", "unknown-key"),
    ] {
        let mut altered = value.clone();
        altered[field] = json!(replacement);
        assert!(
            verifier
                .verify(&resign(altered, &key), grant.valid_from)
                .is_err(),
            "{field}"
        );
    }
    let mut wrong_audience = verifier.clone();
    wrong_audience.audience = "https://other.example.org/execute".into();
    assert!(wrong_audience.verify(&raw, grant.valid_from).is_err());
    assert_eq!(value["profile"], PROFILE);
}

#[test]
fn grant_time_validity_is_exclusive_at_expiry() {
    let grant = executable_grant();
    let key = test_key();
    let raw = sign_grant(&grant, "issuer-test", &key).unwrap();
    let verifier = verifier(&grant, &key);
    assert!(verifier.verify(&raw, grant.valid_from).is_ok());
    assert!(verifier.verify(&raw, grant.expires_at - 1).is_ok());
    assert!(verifier.verify(&raw, grant.valid_from - 1).is_err());
    assert!(verifier.verify(&raw, grant.expires_at).is_err());
    for field in ["valid_from", "expires_at", "issued_at"] {
        let mut altered = grant.clone();
        match field {
            "valid_from" => altered.valid_from = -1,
            "expires_at" => altered.expires_at = altered.valid_from,
            "issued_at" => altered.issued_at = altered.valid_from + 1,
            _ => unreachable!(),
        }
        assert!(
            verifier
                .verify(
                    &sign_grant(&altered, "issuer-test", &key).unwrap(),
                    grant.valid_from
                )
                .is_err()
        );
    }
}

#[test]
fn restricted_execution_profile_refuses_unsupported_authority_and_guards() {
    let grant = executable_grant();
    let key = test_key();
    let value = strict_value(&sign_grant(&grant, "issuer-test", &key).unwrap()).unwrap();
    let verifier = verifier(&grant, &key);
    type GrantMutation = (&'static str, fn(&mut Value));
    let cases: &[GrantMutation] = &[
        ("commit_bound", |v| {
            v["payload"]["completion_mode"] = json!("commit_bound")
        }),
        ("saga", |v| {
            v["payload"]["saga_budget"] = json!({"root_id": "saga"})
        }),
        ("delegated", |v| {
            v["payload"]["parent_grant_digest"] = json!("1".repeat(64))
        }),
        ("no_resource", |v| v["payload"]["resources"] = json!([])),
        ("two_resources", |v| {
            let resource = v["payload"]["resources"][0].clone();
            v["payload"]["resources"]
                .as_array_mut()
                .unwrap()
                .push(resource);
        }),
        ("zero_generation", |v| {
            v["payload"]["root_generation"] = json!(0)
        }),
        ("zero_fence", |v| v["payload"]["fence"] = json!(0)),
        ("zero_policy_epoch", |v| {
            v["payload"]["policy"]["epoch"] = json!(0)
        }),
        ("zero_ownership", |v| {
            v["payload"]["ownership_epoch"] = json!(0)
        }),
        ("empty_subject", |v| {
            v["payload"]["subject"]["sub"] = json!("")
        }),
        ("empty_workload", |v| {
            v["payload"]["workload_id"] = json!("")
        }),
        ("empty_proof_key", |v| v["payload"]["dpop_jkt"] = json!("")),
        ("bad_digest", |v| {
            v["payload"]["certificate_digest"] = json!("z".repeat(64))
        }),
        ("unknown_predicate_language", |v| {
            v["payload"]["predicate_descriptor"]["language"] = json!("javascript")
        }),
        ("unknown_predicate_field", |v| {
            v["payload"]["predicate_descriptor"]["script"] = json!("true")
        }),
        ("unknown_clause_field", |v| {
            v["payload"]["predicate_descriptor"]["clauses"][0]["script"] = json!("true")
        }),
        ("unknown_clause", |v| {
            v["payload"]["predicate_descriptor"]["clauses"][0]["kind"] = json!("always")
        }),
        ("wrong_incarnation", |v| {
            v["payload"]["predicate_descriptor"]["clauses"][0]["resource"]["incarnation"] =
                json!("recreated")
        }),
        ("noncanonical_version", |v| {
            v["payload"]["predicate_descriptor"]["clauses"][0]["expected_version"] = json!("0241")
        }),
        ("level_b", |v| {
            v["payload"]["adapter_contract"]["level"] = json!("Level_B")
        }),
        ("sql_guard", |v| {
            v["payload"]["adapter_contract"]["guard_primitive"] = json!("SQL_CAS")
        }),
        ("wrong_guard_scope", |v| {
            v["payload"]["adapter_contract"]["guard_scope"] = json!(["other-resource"])
        }),
        ("commit_adapter", |v| {
            v["payload"]["adapter_contract"]["completion_mode"] = json!("commit_bound")
        }),
        ("unknown_adapter_field", |v| {
            v["payload"]["adapter_contract"]["fallback"] = json!(true)
        }),
        ("unknown_idempotency_field", |v| {
            v["payload"]["adapter_contract"]["idempotency"]["retry_anyway"] = json!(true)
        }),
        ("no_idempotency", |v| {
            v["payload"]["adapter_contract"]["idempotency"]["mode"] = json!("none")
        }),
    ];
    for (name, mutate) in cases {
        let mut altered = value.clone();
        mutate(&mut altered);
        assert!(
            verifier
                .verify(&resign(altered, &key), grant.valid_from)
                .is_err(),
            "{name}"
        );
    }
    for field in ["root_generation", "fence", "ownership_epoch"] {
        let mut altered = value.clone();
        altered["payload"][field] = json!(MAX_SAFE_INTEGER + 1);
        assert!(
            verifier
                .verify(&serde_json::to_vec(&altered).unwrap(), grant.valid_from)
                .is_err(),
            "{field}"
        );
    }
}
