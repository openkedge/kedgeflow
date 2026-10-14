//! Software lease/provider membership, real TLS/DPoP/etcd and shipping offline CLI.
use super::*;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use kedgeflow::{
    ledger::{AuthoritativeObservation, OutcomeQuerier},
    lineage::{LEASE_PROFILE, LineageBundle, verify_lineage},
    lineage_config::LineageTrustConfig,
    recovery::{Candidate, ExecutionRecord, RecoveryWorker},
};
struct Pending;
#[async_trait]
impl OutcomeQuerier for Pending {
    async fn query(&self, _: &str) -> kedgeflow::error::Result<AuthoritativeObservation> {
        panic!("undispatched attempt cannot query target")
    }
}
impl Leases {
    fn audit_trust(&self) -> Value {
        let encoded = |map: &std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>| {
            map.iter()
                .map(|(id, k)| (id.clone(), STANDARD.encode(k.as_bytes())))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let t = &self.h.f.trust;
        let evidence: std::collections::BTreeMap<_,_> = t.evidence.iter().map(|(id,r)| (id.clone(),json!({"obligation":r.obligation,"provider_id":r.provider_id,"provider_version":r.provider_version,"keys":encoded(&r.keys),"question":r.question,"result_schema_ref":r.result_schema_ref,"result_schema":r.result_schema,"max_age_ms":r.max_age_ms,"predicates":r.predicates}))).collect();
        json!({"tenant":t.tenant,"workload_id":t.proposal_workload_id,"subjects":[self.h.f.identity.subject],"delegation_audience":AUDIENCE,"gateway_audience":self.h.f.descriptor["gateway_audience"],"action_scope":t.required_scope,"proposal_keys":encoded(&t.proposal_keys),"registry_keys":encoded(&t.registry_keys),"manifest_keys":encoded(&t.manifest_keys),"admission_keys":encoded(&keys(6)),"grant_keys":encoded(&keys(5)),"outcome_keys":encoded(&keys(14)),"source_id":"spiffe://test/outcome","descriptor_digest":t.descriptor_digest,"ownership_epoch":t.ownership_epoch,"max_proposal_age_ms":t.max_proposal_age_ms,"policy":{"id":self.h.definition.policy_id,"epoch":t.policy.epoch,"cedar":self.h.definition.cedar,"max_certificate_lifetime_ms":self.h.definition.max_certificate_lifetime_ms},"evidence":evidence,"leases":{"keys":encoded(&keys(6)),"max_lifetime_ms":4000,"jit_max_age_ms":2000}})
    }
    async fn audit(&self, with_lease: bool) -> (Candidate, String, LineageBundle) {
        self.audit_format(with_lease, false).await
    }
    async fn audit_format(
        &self,
        with_lease: bool,
        pretty: bool,
    ) -> (Candidate, String, LineageBundle) {
        let s = self.start().await;
        let lease = if with_lease {
            Some(self.prevalidate(&s).await)
        } else {
            None
        };
        let mut body = self.request(false, NOW, lease.as_deref());
        if pretty {
            for field in ["proposal", "descriptor", "manifest", "lease"] {
                let record: Value = serde_json::from_str(body[field].as_str().unwrap()).unwrap();
                body[field] = json!(serde_json::to_string_pretty(&record).unwrap());
            }
            for raw in body["witnesses"].as_array_mut().unwrap() {
                let record: Value = serde_json::from_str(raw.as_str().unwrap()).unwrap();
                *raw = json!(serde_json::to_string_pretty(&record).unwrap());
            }
        }
        let (code, out) = if with_lease {
            self.post(&s.leases, &body).await
        } else {
            let packet = self.packet(false, NOW, None);
            let mut body = self.h.admission("no-lease");
            body["proposal"] = json!(packet.proposal);
            body["descriptor"] = json!(packet.descriptor);
            body["manifest"] = json!(packet.manifest);
            body["witnesses"] = json!(packet.witnesses);
            self.post(&s.admit, &body).await
        };
        assert_eq!(code, reqwest::StatusCode::OK, "{out}");
        let (code, out) = self
            .post(
                &s.issue,
                &self
                    .h
                    .issuance("audit", out["certificate"].as_str().unwrap()),
            )
            .await;
        assert_eq!(code, reqwest::StatusCode::OK, "{out}");
        let raw = out["grant"].as_str().unwrap();
        let grants = GrantVerifier {
            keys: keys(5),
            audience: self.h.f.descriptor["gateway_audience"]
                .as_str()
                .unwrap()
                .into(),
        };
        let g = grants.verify_retained(raw.as_bytes()).unwrap();
        let c = Candidate {
            grant: g.grant,
            attempt_id: "lease-audit".into(),
        };
        self.h
            .ledger
            .claim_recorded(
                &c.grant,
                &g.digest,
                &c.attempt_id,
                &ExecutionRecord {
                    signed_grant: raw.into(),
                    tool: "capacity.reserve".into(),
                    parameters: self.h.f.proposal["parameters"].clone(),
                },
            )
            .await
            .unwrap();
        RecoveryWorker::new(
            self.h.ledger.clone(),
            grants,
            Arc::new(Pending),
            "key-14".into(),
            SigningKey::from_bytes(&[14; 32]),
            "spiffe://test/outcome".into(),
            Arc::new(Time(NOW + 120000)),
        )
        .unwrap()
        .recover(&c)
        .await
        .unwrap();
        let key = self
            .h
            .f
            .trust
            .operation_key(
                &self.h.f.identity,
                self.packet(false, NOW, lease.as_deref())
                    .proposal
                    .as_bytes(),
            )
            .unwrap();
        let bundle = self.h.ledger.export_lineage(&c, &key).await.unwrap();
        (c, key, bundle)
    }
}
#[tokio::test]
async fn leased_lineage_native_export_offline_cli_and_withdrawal_preserve_history() {
    let Some(l) = Leases::new().await else { return };
    let (c, key, b) = l.audit(true).await;
    assert_eq!(b.profile, LEASE_PROFILE);
    let tv = l.audit_trust();
    let trust = LineageTrustConfig::decode(&serde_json::to_vec(&tv).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    let r = verify_lineage(&b, &trust).unwrap();
    assert_eq!(r.profile, LEASE_PROFILE);
    assert_eq!(r.witnesses_verified, 2);
    assert_eq!(r.reported_status, "not_dispatched");
    let before = serde_json::to_vec(&b).unwrap();
    l.h.ledger
        .withdraw_lease_member(&l.h.f.trust, &l.h.f.identity.subject)
        .await
        .unwrap();
    let after = l.h.ledger.export_lineage(&c, &key).await.unwrap();
    assert_eq!(before, serde_json::to_vec(&after).unwrap());
    verify_lineage(&after, &trust).unwrap();
    l.h.ledger
        .replace_lease_member(&l.h.f.trust, &l.h.f.identity.subject, 2)
        .await
        .unwrap();
    verify_lineage(&l.h.ledger.export_lineage(&c, &key).await.unwrap(), &trust).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tp = dir.path().join("trust.json");
    let bp = dir.path().join("bundle.json");
    std::fs::write(&tp, serde_json::to_vec(&tv).unwrap()).unwrap();
    std::fs::write(&bp, before).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kf-verify-lineage"))
        .args([
            "--trust",
            tp.to_str().unwrap(),
            "--bundle",
            bp.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["profile"],
        LEASE_PROFILE
    );
}
#[tokio::test]
async fn leased_lineage_static_cache_generation_phases_times_and_downgrades_refuse() {
    let Some(l) = Leases::new().await else { return };
    let (_, _, b) = l.audit(true).await;
    let trust = LineageTrustConfig::decode(&serde_json::to_vec(&l.audit_trust()).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    let original = json!(b);
    for change in [
        "generation",
        "registered",
        "active",
        "static_packet",
        "static_binding",
        "cache_binding",
        "lease",
        "phase",
        "digest",
        "early",
        "expired",
        "out_of_order",
        "missing",
        "downgrade",
        "unrecognized",
        "null_cache",
    ] {
        let mut v = original.clone();
        match change {
            "generation" => {
                for i in 0..2 {
                    v["lease_authority"][i]["member"]["generation"] = json!(3);
                    v["lease_authority"][i]["cache"]["member"]["generation"] = json!(3);
                }
            }
            "registered" => {
                v["lease_authority"][0]["member"]["registration_binding"] = json!("a".repeat(64))
            }
            "active" => v["lease_authority"][0]["member"]["active"] = json!(false),
            "static_packet" => {
                v["lease_authority"][0]["cache"]["packet"]["manifest"] =
                    v["packet"]["manifest"].clone()
            }
            "static_binding" => {
                v["lease_authority"][0]["cache"]["inputs_binding"] = json!("a".repeat(64))
            }
            "cache_binding" => v["lease_authority"][0]["cache"]["binding"] = json!("a".repeat(64)),
            "lease" => v["lease_authority"][0]["cache"]["signed_lease"] = json!("{}"),
            "phase" => v["lease_authority"][0]["phase"] = json!("issuance"),
            "digest" => {
                v["lease_authority"][1]["authority_digest"] =
                    v["admission"]["certificate_digest"].clone()
            }
            "early" => v["lease_authority"][0]["checked_at"] = json!(NOW - 1),
            "expired" => v["lease_authority"][0]["checked_at"] = json!(NOW + 4000),
            "out_of_order" => {
                v["lease_authority"][0]["checked_at"] = json!(NOW + 1);
            }
            "missing" => {
                v.as_object_mut().unwrap().remove("lease_authority");
            }
            "downgrade" => v["profile"] = json!(kedgeflow::lineage::PROFILE),
            "unrecognized" => v["profile"] = json!("KF-ADMISSION-LINEAGE-0.3-draft"),
            "null_cache" => v["lease_authority"][0]["cache"] = Value::Null,
            _ => unreachable!(),
        }
        if let Ok(t) = LineageBundle::decode(&serde_json::to_vec(&v).unwrap()) {
            assert!(verify_lineage(&t, &trust).is_err(), "{change}");
        }
    }
    let mut no_trust = trust;
    no_trust.admission.leases = None;
    assert!(verify_lineage(&b, &no_trust).is_err());
    let legacy: Value = serde_json::from_str(include_str!(
        "../../../../spec/drafts/admission-lineage-v0.1.schema.json"
    ))
    .unwrap();
    assert!(
        !jsonschema::validator_for(&legacy)
            .unwrap()
            .is_valid(&original)
    );
}
#[tokio::test]
async fn lease_enabled_full_evidence_audit_retains_membership_and_missing_phase_is_not_synthesized()
{
    let Some(l) = Leases::new().await else { return };
    let (c, key, b) = l.audit(false).await;
    let trust = LineageTrustConfig::decode(&serde_json::to_vec(&l.audit_trust()).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    verify_lineage(&b, &trust).unwrap();
    assert!(b.packet.lease.is_none());
    assert!(
        json!(b)["lease_authority"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["cache"].is_null())
    );
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    reqwest::Client::new().post(format!("{endpoint}/v3/kv/deleterange")).json(&json!({"key":STANDARD.encode(format!("{}/lease-authority/{key}/issuance",l.h.prefix))})).send().await.unwrap().error_for_status().unwrap();
    assert!(l.h.ledger.export_lineage(&c, &key).await.is_err());
}

#[tokio::test]
async fn leased_lineage_canonical_signed_record_variants_preserve_native_audit() {
    let Some(l) = Leases::new().await else { return };
    let (_, _, b) = l.audit_format(true, true).await;
    let v = json!(b);
    assert_ne!(
        v["packet"]["proposal"],
        v["lease_authority"][0]["cache"]["packet"]["proposal"]
    );
    assert_ne!(
        v["packet"]["witnesses"][0],
        v["lease_authority"][0]["cache"]["packet"]["witnesses"][0]
    );
    let trust = LineageTrustConfig::decode(&serde_json::to_vec(&l.audit_trust()).unwrap())
        .unwrap()
        .registration()
        .unwrap();
    verify_lineage(&b, &trust).unwrap();
}
