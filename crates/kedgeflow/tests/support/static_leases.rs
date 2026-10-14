//! Native TLS/DPoP and real etcd. Membership and providers are software fixtures.
use super::*;
use kedgeflow::{
    admission::{AdmissionPacket, EvidencePredicate, StoredAdmissionPacket},
    clock::Clock,
    issuance::AdmissionContext,
    leases::{LeaseTrust, PROFILE},
};
struct Leases {
    h: Harness,
    now: i64,
    static_evidence: Value,
}
struct LeaseServer {
    leases: String,
    admit: String,
    issue: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for LeaseServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Leases {
    async fn new() -> Option<Self> {
        Self::new_at(NOW).await
    }
    async fn new_at(now: i64) -> Option<Self> {
        let mut h = Harness::new().await?;
        h.credentials = Arc::new(Credentials::new_at(
            &h.f.identity.subject,
            "capacity.reserve kf.admit kf.issue kf.lease",
            now,
        ));
        let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(h.pki.client.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        let workload = WorkloadIdentity::from_verified_cert_der(cert.as_ref()).unwrap();
        h.f.identity = h
            .credentials
            .auth("https://control.test/admission")
            .authenticate_at(
                &h.credentials.headers("https://control.test/admission"),
                &workload,
                now / 1000,
            )
            .unwrap();
        h.f.proposal["delegation"] = h.credentials.delegation.clone();
        h.f.proposal["created_at"] = json!(now - 10);
        h.f.proposal["baseline_state"][0]["observed_at"] = json!(now - 12);
        h.f.proposal["baseline_state"][0]["expires_at"] = json!(now + 60000);
        h.f.evidence["observed_at"] = json!(now);
        h.f.evidence["expires_at"] = json!(now + 30000);
        let mut r = h.f.trust.evidence["capacity"].clone();
        r.provider_id = "provider:eligibility".into();
        r.keys = keys(30);
        r.obligation.stage = "static".into();
        r.result_schema = json!({"type":"object","additionalProperties":false,"properties":{"eligible":{"type":"boolean"}},"required":["eligible"]});
        r.result_schema_ref.digest = digest("result-schema", &r.result_schema).unwrap();
        r.result_schema_ref.id = "schema:eligibility".into();
        r.question.id = "question:eligibility".into();
        r.predicates = vec![EvidencePredicate::BooleanEquals {
            field: "eligible".into(),
            expected: true,
        }];
        r.obligation.predicate_digest = digest("evidence-predicate", &json!(r.predicates)).unwrap();
        let mut static_evidence = h.f.evidence.clone();
        static_evidence["wid"] = json!("w:eligibility");
        static_evidence["provider_id"] = json!(r.provider_id);
        static_evidence["question_ref"] = json!(r.question);
        static_evidence["result_schema"] = json!(r.result_schema_ref);
        static_evidence["result"] = json!({"eligible":true});
        static_evidence["observed_at"] = json!(now - 5);
        static_evidence["expires_at"] = json!(now + 10000);
        h.f.trust.evidence.insert("eligibility".into(), r);
        h.f.trust.leases = Some(LeaseTrust {
            keys: keys(6),
            max_lifetime_ms: 4000,
            jit_max_age_ms: 2000,
        });
        h.f.trust.obligation_manifest_digest = h.f.trust.registered_obligations_digest().unwrap();
        h.definition.obligation_manifest_digest = h.f.trust.obligation_manifest_digest.clone();
        h.f.trust.policy = h.definition.reference(7).unwrap();
        h.ledger = h.ledger.clone().with_clock(Arc::new(Time(now)));
        h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
        h.ledger
            .enroll_lease_member(&h.f.trust, &h.f.identity.subject)
            .await
            .unwrap();
        Some(Self {
            h,
            now,
            static_evidence,
        })
    }
    fn packet(
        &self,
        static_only: bool,
        jit_observed: i64,
        lease: Option<&str>,
    ) -> StoredAdmissionPacket {
        let proposal = signed("proposal", self.h.f.proposal.clone(), 1);
        let descriptor = signed("ctd", self.h.f.descriptor.clone(), 2);
        let pd = record_hash(&proposal);
        let mut witnesses = vec![];
        let mut entries = vec![];
        let mut e = self.static_evidence.clone();
        e["proposal_digest"] = json!(pd);
        let raw = signed("evidence", e.clone(), 30);
        entries.push(json!({"witness":{"id":e["wid"],"schema":serde_json::from_slice::<Value>(&raw).unwrap()["schema"],"digest":record_hash(&raw)},"obligation_id":"eligibility","execution_relevant":true,"expires_at":e["expires_at"]}));
        witnesses.push(String::from_utf8(raw).unwrap());
        if !static_only {
            let mut e = self.h.f.evidence.clone();
            e["proposal_digest"] = json!(pd);
            e["observed_at"] = json!(jit_observed);
            let raw = signed("evidence", e.clone(), 4);
            entries.push(json!({"witness":{"id":e["wid"],"schema":serde_json::from_slice::<Value>(&raw).unwrap()["schema"],"digest":record_hash(&raw)},"obligation_id":"capacity","execution_relevant":true,"expires_at":e["expires_at"]}));
            witnesses.push(String::from_utf8(raw).unwrap());
        }
        let manifest = signed(
            "manifest",
            json!({"mid":if static_only{"lease:static"}else{"lease:full"},"proposal_digest":pd,"policy":self.h.f.trust.policy,"witnesses":entries,"assembled_at":self.now.max(jit_observed)}),
            3,
        );
        StoredAdmissionPacket {
            proposal: String::from_utf8(proposal).unwrap(),
            descriptor: String::from_utf8(descriptor).unwrap(),
            manifest: String::from_utf8(manifest).unwrap(),
            witnesses,
            lease: lease.map(str::to_owned),
        }
    }
    fn request(&self, static_only: bool, jit_observed: i64, lease: Option<&str>) -> Value {
        let packet = self.packet(static_only, jit_observed, lease);
        let mut body = json!({"profile":PROFILE,"operation":if static_only{"prevalidate"}else{"admit"},"request_id":"lease-test","proposal":packet.proposal,"descriptor":packet.descriptor,"manifest":packet.manifest,"witnesses":packet.witnesses});
        if let Some(lease) = lease {
            body["lease"] = json!(lease);
        }
        body
    }
    fn controller(&self) -> AdmissionController {
        AdmissionController::new(
            CedarAdmissionPolicy::new(self.h.definition.clone(), self.h.f.trust.policy.clone())
                .unwrap(),
            "key-6".into(),
            SigningKey::from_bytes(&[6; 32]),
        )
        .unwrap()
    }
    async fn start(&self) -> LeaseServer {
        self.start_at(self.now).await
    }
    async fn start_at(&self, now: i64) -> LeaseServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let leases = format!("{origin}/leases");
        let admit = format!("{origin}/admission");
        let issue = format!("{origin}/issuance");
        let issuer = GrantAuthority::new(
            IssuanceVerifier {
                tenant: self.h.f.trust.tenant.clone(),
                admission_keys: keys(6),
                grants: GrantVerifier {
                    keys: keys(5),
                    audience: self.h.f.descriptor["gateway_audience"]
                        .as_str()
                        .unwrap()
                        .into(),
                },
            },
            "key-5".into(),
            SigningKey::from_bytes(&[5; 32]),
        )
        .unwrap();
        let service = Arc::new(
            ControlService::new(
                Arc::new(self.h.f.trust.clone()),
                self.controller(),
                issuer,
                self.h.ledger.clone(),
                Arc::new(Time(now)),
                self.h.credentials.auth(&admit),
                self.h.credentials.auth(&issue),
                ControlPermissions {
                    subjects: vec![self.h.f.identity.subject.clone()],
                    admission_scope: "kf.admit".into(),
                    issuance_scope: "kf.issue".into(),
                },
            )
            .unwrap()
            .with_leases(self.h.credentials.auth(&leases), "kf.lease".into())
            .unwrap(),
        );
        let tls = kedgeflow::tls::server_config_pem(
            self.h.pki.server.as_bytes(),
            self.h.pki.server_key.as_bytes(),
            self.h.pki.ca.as_bytes(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, tls, service.router())
                .await
                .unwrap();
        });
        LeaseServer {
            leases,
            admit,
            issue,
            task,
        }
    }
    async fn post(&self, url: &str, body: &Value) -> (reqwest::StatusCode, Value) {
        let response = self
            .h
            .client()
            .post(url)
            .headers(self.h.credentials.headers(url))
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let value: Value = response.json().await.unwrap();
        if value["profile"] == PROFILE {
            let mut schema: Value = serde_json::from_str(include_str!(
                "../../../../spec/drafts/static-lease-http-v0.1.schema.json"
            ))
            .unwrap();
            schema["$ref"] = json!("#/$defs/Response");
            assert!(
                jsonschema::validator_for(&schema).unwrap().is_valid(&value),
                "{value}"
            );
        }
        (status, value)
    }
    async fn prevalidate(&self, s: &LeaseServer) -> String {
        let (code, out) = self
            .post(&s.leases, &self.request(true, self.now, None))
            .await;
        assert_eq!(code, reqwest::StatusCode::OK, "{out}");
        out["lease"].as_str().unwrap().into()
    }
    fn member_key(&self) -> String {
        format!("{}/lease-members/{}",self.h.prefix,digest("lease-member",&json!({"tenant":self.h.f.trust.tenant,"subject":self.h.f.identity.subject,"workload":self.h.f.identity.workload_id})).unwrap())
    }
}

#[tokio::test]
async fn static_leases_native_prevalidation_retries_recreation_and_final_issuance() {
    let Some(l) = Leases::new().await else { return };
    let s = l.start().await;
    let replica = l.start().await;
    let mut jobs = tokio::task::JoinSet::new();
    for i in 0..16 {
        let client = l.h.client();
        let url = if i % 2 == 0 {
            s.leases.clone()
        } else {
            replica.leases.clone()
        };
        let headers = l.h.credentials.headers(&url);
        let body = l.request(true, NOW, None);
        jobs.spawn(async move {
            let response = client
                .post(&url)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            response.json::<Value>().await.unwrap()["lease"]
                .as_str()
                .unwrap()
                .to_owned()
        });
    }
    let mut leases = Vec::new();
    while let Some(result) = jobs.join_next().await {
        leases.push(result.unwrap());
    }
    assert!(leases.iter().all(|lease| lease == &leases[0]));
    let lease = leases[0].clone();
    drop(replica);
    let envelope = verify_record(lease.as_bytes(), "lease", &keys(6)).unwrap();
    assert_eq!(envelope.payload["execution_authority"], false);
    assert_eq!(
        envelope.payload["pending_jit_obligations"],
        json!(["capacity"])
    );
    assert_eq!(
        envelope.payload["static_discharges"][0]["obligation_id"],
        "eligibility"
    );
    assert!(
        l.h.ledger
            .read_key(&l.h.counter_key())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        GrantVerifier {
            keys: keys(6),
            audience: "irrelevant".into()
        }
        .verify(lease.as_bytes(), NOW)
        .is_err()
    );
    let (_, retry) = l.post(&s.leases, &l.request(true, NOW, None)).await;
    assert_eq!(retry["lease"], lease);
    drop(s);
    let s = l.start_at(NOW + 100).await;
    let (_, retry) = l.post(&s.leases, &l.request(true, NOW, None)).await;
    assert_eq!(retry["lease"], lease);
    let body = l.request(false, NOW + 100, Some(&lease));
    let (code, out) = l.post(&s.leases, &body).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{out}");
    let certificate = out["certificate"].as_str().unwrap();
    let c = verify_record(certificate.as_bytes(), "certificate", &keys(6)).unwrap();
    assert_eq!(c.payload["lease_digest"], record_hash(lease.as_bytes()));
    assert_eq!(c.payload["discharges"].as_array().unwrap().len(), 2);
    let issue = l.h.issuance("lease-issue", certificate);
    let (code, out) = l.post(&s.issue, &issue).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{out}");
    let grant = out["grant"].as_str().unwrap();
    let verified = GrantVerifier {
        keys: keys(5),
        audience: l.h.f.descriptor["gateway_audience"]
            .as_str()
            .unwrap()
            .into(),
    }
    .verify(grant.as_bytes(), NOW + 100)
    .unwrap();
    assert_eq!(verified.grant.fence, 1);
    let (_, retry) = l.post(&s.issue, &issue).await;
    assert_eq!(retry["grant"], grant);
    let context = AdmissionContext {
        tenant: l.h.f.trust.tenant.clone(),
        qid: l.h.f.proposal["qid"].as_str().unwrap().into(),
        subject: l.h.f.identity.subject.clone(),
        workload_id: l.h.f.identity.workload_id.clone(),
        dpop_jkt: l.h.f.identity.dpop_jkt.clone(),
        proposal_digest: c.payload["proposal_digest"].as_str().unwrap().into(),
        delegation_digest: l.h.f.identity.delegation_digest.clone(),
        descriptor_digest: l.h.f.trust.descriptor_digest.clone(),
        obligation_manifest_digest: l.h.f.trust.obligation_manifest_digest.clone(),
        evidence_manifest_digest: c.payload["evidence_manifest_digest"]
            .as_str()
            .unwrap()
            .into(),
        policy: l.h.f.trust.policy.clone(),
        ownership_epoch: l.h.f.trust.ownership_epoch,
        audience: verified.grant.audience.clone(),
        conflict_domain: verified.grant.conflict_domain.clone(),
        obligations: l
            .h
            .f
            .trust
            .evidence
            .iter()
            .map(|(id, r)| (id.clone(), r.obligation.clone()))
            .collect(),
    };
    assert!(
        IssuanceVerifier {
            tenant: context.tenant.clone(),
            admission_keys: keys(6),
            grants: GrantVerifier {
                keys: keys(5),
                audience: context.audience.clone()
            }
        }
        .validate(
            &context,
            certificate.as_bytes(),
            grant.as_bytes(),
            NOW + 100
        )
        .is_err()
    );
    let key =
        l.h.f
            .trust
            .operation_key(
                &l.h.f.identity,
                l.packet(false, NOW + 100, None).proposal.as_bytes(),
            )
            .unwrap();
    let retained =
        l.h.ledger
            .admission_bundle(&key, &Time(NOW + 100))
            .await
            .unwrap();
    assert_eq!(retained.packet.lease.as_deref(), Some(lease.as_str()));
    l.h.ledger
        .withdraw_lease_member(&l.h.f.trust, &l.h.f.identity.subject)
        .await
        .unwrap();
    assert_eq!(
        l.post(&s.leases, &body).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.post(&s.issue, &issue).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.h.ledger
            .read_key(&l.h.counter_key())
            .await
            .unwrap()
            .unwrap(),
        b"1"
    );
}

#[tokio::test]
async fn static_leases_membership_withdrawal_replacement_and_no_omission_bypass() {
    let Some(l) = Leases::new().await else { return };
    let s = l.start().await;
    let lease = l.prevalidate(&s).await;
    assert!(
        l.h.ledger
            .enroll_lease_member(&l.h.f.trust, &l.h.f.identity.subject)
            .await
            .is_err()
    );
    l.h.ledger
        .withdraw_lease_member(&l.h.f.trust, &l.h.f.identity.subject)
        .await
        .unwrap();
    assert_eq!(
        l.post(&s.leases, &l.request(true, NOW, None)).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    let mut ordinary = l.request(false, NOW, None);
    ordinary["profile"] = json!(kedgeflow::control::PROFILE);
    assert_eq!(
        l.post(&s.admit, &ordinary).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(
        l.h.ledger
            .replace_lease_member(&l.h.f.trust, &l.h.f.identity.subject, 1)
            .await
            .is_err()
    );
    l.h.ledger
        .replace_lease_member(&l.h.f.trust, &l.h.f.identity.subject, 2)
        .await
        .unwrap();
    assert_eq!(
        l.post(&s.leases, &l.request(false, NOW, Some(&lease)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    // A corrupted cache cannot rewrite its original member generation to the
    // new active generation without conflicting with its signed cache identity.
    use base64::engine::general_purpose::STANDARD;
    let current = l.h.ledger.read_key(&l.member_key()).await.unwrap().unwrap();
    let old: Value = serde_json::from_str(&lease).unwrap();
    let cache_key = format!(
        "{}/leases/{}",
        l.h.prefix,
        old["payload"]["lid"]
            .as_str()
            .unwrap()
            .strip_prefix("kf-lease:")
            .unwrap()
    );
    let mut cache: Value =
        serde_json::from_slice(&l.h.ledger.read_key(&cache_key).await.unwrap().unwrap()).unwrap();
    cache["member"] = serde_json::from_slice(&current).unwrap();
    let result: Value = reqwest::Client::new().post(format!("{}/v3/kv/txn",std::env::var("ETCD_ENDPOINT").unwrap())).json(&json!({"compare":[],"success":[{"request_put":{"key":STANDARD.encode(&cache_key),"value":STANDARD.encode(canonical(&cache).unwrap())}}],"failure":[]})).send().await.unwrap().json().await.unwrap();
    assert_eq!(result["succeeded"], true);
    assert_eq!(
        l.post(&s.leases, &l.request(false, NOW, Some(&lease)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    let new = l.prevalidate(&s).await;
    assert_ne!(lease, new);
    let (code, out) = l.post(&s.leases, &l.request(false, NOW, Some(&new))).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{out}");
    let member: Value =
        serde_json::from_slice(&l.h.ledger.read_key(&l.member_key()).await.unwrap().unwrap())
            .unwrap();
    assert_eq!(member["generation"], 3);
}

#[tokio::test]
async fn static_leases_closed_inputs_exact_context_fresh_jit_and_expiry_refuse() {
    let Some(mut l) = Leases::new().await else {
        return;
    };
    let s = l.start().await;
    let lease = l.prevalidate(&s).await;
    for field in ["root_id", "nonce", "expires_at", "lease"] {
        let mut body = l.request(true, NOW, None);
        body[field] = json!("caller");
        assert_eq!(
            l.post(&s.leases, &body).await.0,
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    let mut body = l.request(true, NOW, None);
    body["profile"] = json!(kedgeflow::control::PROFILE);
    assert_eq!(
        l.post(&s.leases, &body).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        l.post(&s.leases, &l.request(false, NOW - 1, Some(&lease)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(
        !l.post(&s.leases, &l.request(false, NOW, None))
            .await
            .0
            .is_success()
    );
    let mut body = l.request(false, NOW, Some(&lease));
    body["profile"] = json!(kedgeflow::control::PROFILE);
    assert_eq!(
        l.post(&s.admit, &body).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    let full = l.request(false, NOW, Some(&lease));
    assert!(
        !l.post(&s.leases, &{
            let mut x = full.clone();
            x["witnesses"].as_array_mut().unwrap().pop();
            x
        })
        .await
        .0
        .is_success()
    );
    let mut wrong: Value = serde_json::from_str(&lease).unwrap();
    wrong["payload"]["execution_authority"] = json!(true);
    let fake = String::from_utf8(canonical(&wrong).unwrap()).unwrap();
    assert!(
        !l.post(&s.leases, &l.request(false, NOW, Some(&fake)))
            .await
            .0
            .is_success()
    );
    let mut wrong: Value = serde_json::from_str(&lease).unwrap();
    wrong["payload"]["proposal_digest"] = json!("e".repeat(64));
    let fake = String::from_utf8(signed("lease", wrong["payload"].clone(), 6)).unwrap();
    assert_eq!(
        l.post(&s.leases, &l.request(false, NOW, Some(&fake)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    l.h.f.proposal["parameters"]["expected_version"] = json!(242);
    assert_eq!(
        l.post(&s.leases, &l.request(false, NOW, Some(&lease)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    l.h.f.proposal["parameters"]["expected_version"] = json!(241);
    drop(s);
    let s = l.start_at(NOW + 2500).await;
    assert_eq!(
        l.post(&s.leases, &l.request(false, NOW, Some(&lease)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    drop(s);
    let s = l.start_at(NOW + 4001).await;
    assert_eq!(
        l.post(&s.leases, &l.request(false, NOW + 4001, Some(&lease)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    let (code, out) = l.post(&s.leases, &l.request(true, NOW, None)).await;
    assert_eq!(
        code,
        reqwest::StatusCode::FORBIDDEN,
        "expired cached output renewed: {out}"
    );
    drop(s);
    let s = l.start_at(NOW + 10001).await;
    assert_eq!(
        l.post(&s.leases, &l.request(true, NOW, None)).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(
        l.h.ledger
            .read_key(&l.h.counter_key())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn static_leases_changed_pins_false_static_predicate_and_cedar_denial() {
    let Some(mut l) = Leases::new().await else {
        return;
    };
    let s = l.start().await;
    let lease = l.prevalidate(&s).await;
    l.static_evidence["result"]["eligible"] = json!(false);
    assert_eq!(
        l.post(&s.leases, &l.request(true, NOW, None)).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    l.static_evidence["result"]["eligible"] = json!(true);
    l.h.f.trust.evidence.get_mut("eligibility").unwrap().keys = keys(31);
    l.h.f.trust.obligation_manifest_digest = l.h.f.trust.registered_obligations_digest().unwrap();
    l.h.definition.obligation_manifest_digest = l.h.f.trust.obligation_manifest_digest.clone();
    l.h.f.trust.policy = l.h.definition.reference(8).unwrap();
    l.h.ledger.publish_policy(&l.h.bootstrap()).await.unwrap();
    drop(s);
    let s = l.start().await;
    assert!(
        !l.post(&s.leases, &l.request(false, NOW, Some(&lease)))
            .await
            .0
            .is_success()
    );
    assert_eq!(
        l.post(&s.leases, &l.request(true, NOW, None)).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    let mut body = l.request(true, NOW, None);
    let e: Value = serde_json::from_str(body["witnesses"][0].as_str().unwrap()).unwrap();
    let raw = signed("evidence", e["payload"].clone(), 31);
    body["witnesses"][0] = json!(String::from_utf8(raw.clone()).unwrap());
    let mut m: Value = serde_json::from_str(body["manifest"].as_str().unwrap()).unwrap();
    m["payload"]["witnesses"][0]["witness"]["digest"] = json!(record_hash(&raw));
    body["manifest"] =
        json!(String::from_utf8(signed("manifest", m["payload"].clone(), 3)).unwrap());
    assert_eq!(
        l.post(&s.leases, &body).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    let Some(mut denied) = Leases::new().await else {
        return;
    };
    denied.h.definition.cedar = "forbid(principal, action, resource);".into();
    denied.h.f.trust.policy = denied.h.definition.reference(8).unwrap();
    denied
        .h
        .ledger
        .publish_policy(&denied.h.bootstrap())
        .await
        .unwrap();
    denied
        .h
        .ledger
        .replace_lease_member(&denied.h.f.trust, &denied.h.f.identity.subject, 1)
        .await
        .unwrap();
    let s = denied.start().await;
    let lease = denied.prevalidate(&s).await;
    assert_eq!(
        denied
            .post(&s.leases, &denied.request(false, NOW, Some(&lease)))
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(
        denied
            .h
            .ledger
            .read_key(&denied.h.counter_key())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn static_leases_permissions_proof_replay_headers_and_expired_delegation() {
    let Some(mut l) = Leases::new().await else {
        return;
    };
    let mut pki = support::pki_for_workloads(&["spiffe://test/agent", "spiffe://test/other"]);
    let other = pki.pop().unwrap();
    l.h.pki = pki.pop().unwrap();
    let s = l.start().await;
    let body = l.request(true, NOW, None);
    let client = l.h.client();
    let headers = l.h.credentials.headers(&s.leases);
    let response = client
        .post(&s.leases)
        .headers(headers.clone())
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        client
            .post(&s.leases)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let weak = Credentials::new(&l.h.f.identity.subject, "capacity.reserve kf.admit");
    assert_eq!(
        client
            .post(&s.leases)
            .headers(weak.headers(&s.leases))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let mut subject = l.h.f.identity.subject.clone();
    subject.sub = "different-subject".into();
    let wrong = Credentials::new(&subject, "capacity.reserve kf.lease");
    assert_eq!(
        client
            .post(&s.leases)
            .headers(wrong.headers(&s.leases))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let wrong = kedgeflow::tls::pinned_http_client_pem(
        other.ca.as_bytes(),
        other.client.as_bytes(),
        other.client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(
        wrong
            .post(&s.leases)
            .headers(l.h.credentials.headers(&s.leases))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    for (header, value, code) in [
        (
            "origin",
            "https://client.example",
            reqwest::StatusCode::FORBIDDEN,
        ),
        (
            "mcp-kedgeflow-grant",
            "caller-grant",
            reqwest::StatusCode::BAD_REQUEST,
        ),
        (
            "host",
            "evil.example",
            reqwest::StatusCode::MISDIRECTED_REQUEST,
        ),
    ] {
        assert_eq!(
            client
                .post(&s.leases)
                .headers(l.h.credentials.headers(&s.leases))
                .header(header, value)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            code
        );
    }
    let url = format!("{}?alias=1", s.leases);
    assert_eq!(
        client
            .post(&url)
            .headers(l.h.credentials.headers(&url))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let packet = l.packet(true, NOW, None);
    let evidence: Vec<_> = packet
        .witnesses
        .iter()
        .map(|r| r.as_bytes().to_vec())
        .collect();
    assert!(
        l.h.ledger
            .prevalidate_lease(
                &l.h.f.trust,
                &l.controller(),
                &l.h.f.identity,
                AdmissionPacket {
                    lease: None,
                    proposal: packet.proposal.as_bytes(),
                    descriptor: packet.descriptor.as_bytes(),
                    manifest: packet.manifest.as_bytes(),
                    evidence: &evidence
                },
                &Time(NOW + 60001)
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn static_leases_descriptor_ownership_and_evidence_changes_cannot_reuse() {
    for change in ["descriptor", "ownership", "evidence", "delegation"] {
        let Some(mut l) = Leases::new().await else {
            return;
        };
        let s = l.start().await;
        let lease = l.prevalidate(&s).await;
        drop(s);
        match change {
            "descriptor" => {
                l.h.f.descriptor["rendering"]["id"] = json!("changed-template-id");
                l.h.f.repin_descriptor();
            }
            "ownership" => {
                l.h.f.trust.ownership_epoch += 1;
                l.h.f.descriptor["ownership_epoch"] = json!(l.h.f.trust.ownership_epoch);
                l.h.f.repin_descriptor();
            }
            "evidence" => l.static_evidence["wid"] = json!("w:replacement-eligibility"),
            "delegation" => {
                l.h.f.proposal["delegation"]["expires_at"] = json!(NOW + 59000);
                l.h.f.identity.delegation_digest =
                    digest("delegation", &l.h.f.proposal["delegation"]).unwrap();
            }
            _ => unreachable!(),
        }
        l.h.ledger.publish_policy(&l.h.bootstrap()).await.unwrap();
        // A synthetic trusted identity is enough to independently exercise raw
        // context verification when a changed delegation cannot match OAuth.
        let packet = l.packet(false, NOW, Some(&lease));
        let evidence: Vec<_> = packet
            .witnesses
            .iter()
            .map(|r| r.as_bytes().to_vec())
            .collect();
        assert!(
            l.h.f
                .trust
                .verify_inputs(
                    &l.h.f.identity,
                    AdmissionPacket {
                        lease: packet.lease.as_deref().map(str::as_bytes),
                        proposal: packet.proposal.as_bytes(),
                        descriptor: packet.descriptor.as_bytes(),
                        manifest: packet.manifest.as_bytes(),
                        evidence: &evidence
                    },
                    &Time(NOW)
                )
                .is_err(),
            "accepted {change}"
        );
        if change != "delegation" {
            let s = l.start().await;
            assert_eq!(
                l.post(&s.leases, &l.request(false, NOW, Some(&lease)))
                    .await
                    .0,
                reqwest::StatusCode::FORBIDDEN
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_leases_membership_withdrawal_races_cache_admission_fence_and_issuance() {
    use axum::{Json, Router, response::IntoResponse, routing::post};
    use base64::engine::general_purpose::STANDARD;
    use std::sync::atomic::AtomicBool;
    for phase in ["leases", "admission", "fence-allocation", "issuance"] {
        let Some(mut l) = Leases::new().await else {
            return;
        };
        let s = l.start().await;
        let lease = if phase != "leases" {
            Some(l.prevalidate(&s).await)
        } else {
            None
        };
        let certificate = if phase == "fence-allocation" || phase == "issuance" {
            let (code, out) = l
                .post(&s.leases, &l.request(false, NOW, lease.as_deref()))
                .await;
            assert_eq!(code, reqwest::StatusCode::OK, "{out}");
            Some(out["certificate"].as_str().unwrap().to_owned())
        } else {
            None
        };
        drop(s);
        let direct = l.h.ledger.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let block = Arc::new(AtomicBool::new(true));
        let prefix = l.h.prefix.clone();
        let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
        let router = Router::new().route(
            "/v3/kv/txn",
            post({
                let entered = entered.clone();
                let release = release.clone();
                move |Json(value): Json<Value>| {
                    let entered = entered.clone();
                    let release = release.clone();
                    let block = block.clone();
                    let prefix = prefix.clone();
                    let endpoint = endpoint.clone();
                    async move {
                        let selected = value["success"].as_array().is_some_and(|ops| {
                            ops.iter().any(|op| {
                                op["request_put"]["key"]
                                    .as_str()
                                    .and_then(|s| STANDARD.decode(s).ok())
                                    .is_some_and(|k| {
                                        String::from_utf8_lossy(&k)
                                            .starts_with(&format!("{prefix}/{phase}/"))
                                    })
                            })
                        });
                        if selected && block.swap(false, Ordering::SeqCst) {
                            entered.notify_one();
                            release.notified().await;
                        }
                        let response = reqwest::Client::new()
                            .post(format!("{endpoint}/v3/kv/txn"))
                            .json(&value)
                            .send()
                            .await
                            .unwrap();
                        let code = response.status();
                        let bytes = response.bytes().await.unwrap();
                        (code, [("content-type", "application/json")], bytes).into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let proxy = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        l.h.ledger = EtcdLedger::new(
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            endpoint,
            &l.h.prefix,
        )
        .unwrap()
        .with_clock(Arc::new(Time(NOW)));
        let s = l.start().await;
        let (url, body) = if let Some(c) = certificate {
            (s.issue.clone(), l.h.issuance("race", &c))
        } else {
            (
                s.leases.clone(),
                l.request(phase == "leases", NOW, lease.as_deref()),
            )
        };
        let client = l.h.client();
        let headers = l.h.credentials.headers(&url);
        let request = tokio::spawn(async move {
            let response = client
                .post(&url)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .unwrap();
            let code = response.status();
            let body: Value = response.json().await.unwrap();
            (code, body)
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        direct
            .withdraw_lease_member(&l.h.f.trust, &l.h.f.identity.subject)
            .await
            .unwrap();
        release.notify_one();
        let (code, out) = request.await.unwrap();
        assert_eq!(code, reqwest::StatusCode::FORBIDDEN, "{phase}: {out}");
        if phase == "issuance" {
            assert_eq!(
                direct.read_key(&l.h.counter_key()).await.unwrap().unwrap(),
                b"1"
            );
        } else {
            assert!(direct.read_key(&l.h.counter_key()).await.unwrap().is_none());
        }
        let key =
            l.h.f
                .trust
                .operation_key(
                    &l.h.f.identity,
                    l.packet(false, NOW, None).proposal.as_bytes(),
                )
                .unwrap();
        assert!(
            direct
                .read_key(&format!("{}/issuance/{key}", l.h.prefix))
                .await
                .unwrap()
                .is_none()
        );
        if phase == "admission" {
            assert!(
                direct
                    .read_key(&format!("{}/admission/{key}", l.h.prefix))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        proxy.abort();
    }
}

#[cfg(unix)]
struct Process(std::process::Child);
#[cfg(unix)]
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_leases_shipping_process_lost_reply_restart_and_member_cli() {
    use axum::{Extension, Json, Router, response::IntoResponse, routing::post};
    use base64::engine::general_purpose::STANDARD;
    use std::{
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        sync::atomic::AtomicBool,
    };
    let now = kedgeflow::clock::SystemClock.now_ms();
    let Some(mut l) = Leases::new_at(now).await else {
        return;
    };
    l.h.f.trust.leases.as_mut().unwrap().max_lifetime_ms = 30000;
    l.h.f.trust.leases.as_mut().unwrap().jit_max_age_ms = 10000;
    l.static_evidence["expires_at"] = json!(now + 60000);
    l.h.f.trust.obligation_manifest_digest = l.h.f.trust.registered_obligations_digest().unwrap();
    l.h.definition.obligation_manifest_digest = l.h.f.trust.obligation_manifest_digest.clone();
    l.h.f.trust.policy = l.h.definition.reference(8).unwrap();
    l.h.prefix = format!("/kf-lease-process-{:016x}", rand::random::<u64>());
    l.h.ledger = EtcdLedger::new(
        reqwest::Client::new(),
        std::env::var("ETCD_ENDPOINT").unwrap(),
        &l.h.prefix,
    )
    .unwrap();
    l.h.ledger.publish_policy(&l.h.bootstrap()).await.unwrap();
    let pki = support::pki_with_workload("spiffe://test/control-service");
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let block = Arc::new(AtomicBool::new(true));
    let prefix = l.h.prefix.clone();
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let router = Router::new().route(
        "/v3/kv/txn",
        post({
            let entered = entered.clone();
            let release = release.clone();
            move |Extension(workload): Extension<WorkloadIdentity>,
                  headers: http::HeaderMap,
                  Json(value): Json<Value>| {
                let entered = entered.clone();
                let release = release.clone();
                let block = block.clone();
                let prefix = prefix.clone();
                let endpoint = endpoint.clone();
                async move {
                    if workload.as_str() != "spiffe://test/control-service"
                        || headers.get("authorization").and_then(|v| v.to_str().ok())
                            != Some("control-etcd-token")
                    {
                        return reqwest::StatusCode::FORBIDDEN.into_response();
                    }
                    let selected = value["success"].as_array().is_some_and(|ops| {
                        ops.iter().any(|op| {
                            op["request_put"]["key"]
                                .as_str()
                                .and_then(|s| STANDARD.decode(s).ok())
                                .is_some_and(|k| {
                                    String::from_utf8_lossy(&k)
                                        .starts_with(&format!("{prefix}/leases/"))
                                })
                        })
                    });
                    let response = reqwest::Client::new()
                        .post(format!("{endpoint}/v3/kv/txn"))
                        .json(&value)
                        .send()
                        .await
                        .unwrap();
                    let code = response.status();
                    let bytes = response.bytes().await.unwrap();
                    if selected && block.swap(false, Ordering::SeqCst) {
                        entered.notify_one();
                        release.notified().await;
                        return reqwest::StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    (code, [("content-type", "application/json")], bytes).into_response()
                }
            }
        }),
    );
    let proxy = support::serve_tls(&pki, router).await;
    let dir = tempfile::Builder::new()
        .prefix("kf-leases-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let root = dir.path();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, value: &[u8]| {
        let p = root.join(name);
        std::fs::write(&p, value).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    };
    let certificate = write("server.pem", l.h.pki.server.as_bytes());
    let private_key = write("server-key.pem", l.h.pki.server_key.as_bytes());
    let workload_ca = write("workload-ca.pem", l.h.pki.ca.as_bytes());
    let etcd_ca = write("etcd-ca.pem", pki.ca.as_bytes());
    let etcd_certificate = write("etcd-client.pem", pki.client.as_bytes());
    let etcd_private_key = write("etcd-key.pem", pki.client_key.as_bytes());
    let etcd_token_file = write("etcd-token", b"control-etcd-token");
    let admission_signing_key_file = write("admission-seed", STANDARD.encode([6; 32]).as_bytes());
    let issuer_signing_key_file = write("issuer-seed", STANDARD.encode([5; 32]).as_bytes());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = listener.local_addr().unwrap();
    drop(listener);
    let origin = format!("https://{listen}");
    let leases = format!("{origin}/leases");
    let issue = format!("{origin}/issuance");
    let encoded = |map: &std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>| {
        map.iter()
            .map(|(id, key)| (id.clone(), STANDARD.encode(key.as_bytes())))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let evidence:std::collections::BTreeMap<_,_>=l.h.f.trust.evidence.iter().map(|(id,r)|(id,json!({"obligation":r.obligation,"provider_id":r.provider_id,"provider_version":r.provider_version,"keys":encoded(&r.keys),"question":r.question,"result_schema_ref":r.result_schema_ref,"result_schema":r.result_schema,"max_age_ms":r.max_age_ms,"predicates":r.predicates}))).collect();
    let mut config = json!({"listen":listen.to_string(),"admission_url":format!("{origin}/admission"),"issuance_url":issue,"delegation_audience":AUDIENCE,"gateway_audience":l.h.f.descriptor["gateway_audience"],"certificate":certificate,"private_key":private_key,"workload_ca":workload_ca,"oidc_issuer":l.h.f.identity.subject.iss,"oidc_public_key_base64":STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes())});
    let material = json!({"etcd_endpoint":proxy.url,"etcd_prefix":l.h.prefix,"etcd_ca":etcd_ca,"etcd_certificate":etcd_certificate,"etcd_private_key":etcd_private_key,"etcd_token_file":etcd_token_file,"admission_key_id":"key-6","admission_signing_key_file":admission_signing_key_file,"issuer_key_id":"key-5","issuer_signing_key_file":issuer_signing_key_file});
    let context = json!({"tenant":l.h.f.trust.tenant,"workload_id":l.h.f.identity.workload_id,"subjects":[l.h.f.identity.subject],"admission_scope":"kf.admit","issuance_scope":"kf.issue","action_scope":"capacity.reserve","proposal_keys":encoded(&l.h.f.trust.proposal_keys),"registry_keys":encoded(&l.h.f.trust.registry_keys),"manifest_keys":encoded(&l.h.f.trust.manifest_keys),"descriptor_digest":l.h.f.trust.descriptor_digest,"ownership_epoch":l.h.f.trust.ownership_epoch,"max_proposal_age_ms":60000});
    for group in [material, context] {
        config
            .as_object_mut()
            .unwrap()
            .extend(group.as_object().unwrap().clone());
    }
    config["policy"] = json!({"id":l.h.definition.policy_id,"epoch":l.h.f.trust.policy.epoch,"cedar":l.h.definition.cedar,"max_certificate_lifetime_ms":l.h.definition.max_certificate_lifetime_ms});
    config["evidence"] = json!(evidence);
    config["leases"] = json!({"url":leases,"scope":"kf.lease","registration":{"keys":encoded(&keys(6)),"max_lifetime_ms":30000,"jit_max_age_ms":10000}});
    let path = write("control.json", &serde_json::to_vec(&config).unwrap());
    let command = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kf-control"));
        c.arg("--config").arg(&path);
        c
    };
    let parsed =
        kedgeflow::control_config::ControlConfig::decode(&serde_json::to_vec(&config).unwrap())
            .unwrap();
    assert_eq!(
        parsed.registration().unwrap().0.obligation_manifest_digest,
        l.h.f.trust.obligation_manifest_digest
    );
    assert!(command().arg("--check").output().unwrap().status.success());
    assert!(
        l.h.ledger
            .read_key(&l.member_key())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        command()
            .arg("--enroll-lease-members")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !command()
            .arg("--enroll-lease-members")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !command()
            .arg("--replace-lease-members")
            .output()
            .unwrap()
            .status
            .success()
    );
    let log = root.join("process.log");
    let spawn = || {
        Process(
            command()
                .stdout(Stdio::null())
                .stderr(
                    std::fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&log)
                        .unwrap(),
                )
                .spawn()
                .unwrap(),
        )
    };
    let ready = || async {
        for _ in 0..100 {
            if let Ok(response) = l.h.client().get(&leases).send().await
                && response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!(
            "control startup: {}",
            std::fs::read_to_string(&log).unwrap()
        );
    };
    let process = spawn();
    ready().await;
    let request_body = l.request(true, now, None);
    let client = l.h.client();
    let headers = l.h.credentials.headers(&leases);
    let url = leases.clone();
    let body = request_body.clone();
    let request =
        tokio::spawn(async move { client.post(&url).headers(headers).json(&body).send().await });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let response:Value=reqwest::Client::new().post(format!("{}/v3/kv/range",std::env::var("ETCD_ENDPOINT").unwrap())).json(&json!({"key":STANDARD.encode(format!("{}/leases/",l.h.prefix)),"range_end":STANDARD.encode(format!("{}/leases0",l.h.prefix))})).send().await.unwrap().json().await.unwrap();
    assert_eq!(response["kvs"].as_array().unwrap().len(), 1);
    let cached: Value = serde_json::from_slice(
        &STANDARD
            .decode(response["kvs"][0]["value"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let lease = cached["signed_lease"].as_str().unwrap().to_owned();
    let original = verify_record(lease.as_bytes(), "lease", &keys(6)).unwrap();
    assert!(
        l.h.ledger
            .read_key(&l.h.counter_key())
            .await
            .unwrap()
            .is_none()
    );
    drop(process);
    request.abort();
    release.notify_one();
    let process = spawn();
    ready().await;
    let (code, out) = l.post(&leases, &request_body).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{out}");
    assert_eq!(out["lease"], lease);
    assert_eq!(
        verify_record(out["lease"].as_str().unwrap().as_bytes(), "lease", &keys(6))
            .unwrap()
            .payload["expires_at"],
        original.payload["expires_at"]
    );
    let body = l.request(false, kedgeflow::clock::SystemClock.now_ms(), Some(&lease));
    let (code, out) = l.post(&leases, &body).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{out}");
    let certificate = out["certificate"].as_str().unwrap();
    let (code, out) = l
        .post(&issue, &l.h.issuance("shipping-lease", certificate))
        .await;
    assert_eq!(code, reqwest::StatusCode::OK, "{out}");
    assert_eq!(
        l.h.ledger
            .read_key(&l.h.counter_key())
            .await
            .unwrap()
            .unwrap(),
        b"1"
    );
    drop(process);
    assert!(
        command()
            .arg("--withdraw-lease-members")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !command()
            .args([
                "--replace-lease-members",
                "--expected-lease-generation",
                "1"
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        command()
            .args([
                "--replace-lease-members",
                "--expected-lease-generation",
                "2"
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let process = spawn();
    ready().await;
    let body = l.request(false, kedgeflow::clock::SystemClock.now_ms(), Some(&lease));
    assert_eq!(
        l.post(&leases, &body).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    drop(process);
}

#[test]
fn static_leases_examples_partition_roles_and_legacy_carriage_remains_closed() {
    let config = kedgeflow::control_config::ControlConfig::decode(include_bytes!(
        "../../../../config/control-leases.example.json"
    ))
    .unwrap();
    let (trust, _) = config.registration().unwrap();
    assert_eq!(trust.evidence["review"].obligation.stage, "static");
    assert_eq!(trust.evidence["capacity"].obligation.stage, "jit");
    assert_eq!(trust.leases.as_ref().unwrap().keys, keys(6));
    for change in [
        "jit_only",
        "static_only",
        "key_overlap",
        "invalid_lifetime",
        "invalid_jit_age",
    ] {
        let mut t = trust.clone();
        match change {
            "jit_only" => t
                .evidence
                .values_mut()
                .for_each(|r| r.obligation.stage = "jit".into()),
            "static_only" => t
                .evidence
                .values_mut()
                .for_each(|r| r.obligation.stage = "static".into()),
            "key_overlap" => t.leases.as_mut().unwrap().keys = keys(1),
            "invalid_lifetime" => t.leases.as_mut().unwrap().max_lifetime_ms = 0,
            "invalid_jit_age" => t.leases.as_mut().unwrap().jit_max_age_ms = 0,
            _ => unreachable!(),
        };
        assert!(t.validate_configuration().is_err(), "accepted {change}");
    }
    let old = json!({"proposal":"p","descriptor":"d","manifest":"m","witnesses":["w"]});
    let decoded: StoredAdmissionPacket = serde_json::from_value(old.clone()).unwrap();
    assert!(decoded.lease.is_none());
    assert_eq!(json!(decoded), old);
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../spec/drafts/admission-lineage-v0.1.schema.json"
    ))
    .unwrap();
    let schema = json!({"$defs":schema["$defs"],"$ref":"#/$defs/Packet"});
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&old));
    let mut leased = old;
    leased["lease"] = json!("signed-lease");
    assert!(!validator.is_valid(&leased));
}
