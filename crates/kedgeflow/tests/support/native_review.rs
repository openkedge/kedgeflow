//! Real native TLS/DPoP/etcd; authenticator and enrollment are synthetic.
use super::*;
use kedgeflow::{
    admission::{EvidencePredicate, EvidenceRequirement, RecordReference},
    clock::Clock,
    issuance::RequiredObligation,
    review::{Approval, ReviewAssertion, ReviewEnrollment},
    review_evidence::{PROFILE, ReviewRegistration, ReviewRule, result_schema, template_digest},
    review_service::ReviewService,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use std::collections::BTreeMap;

struct ReviewHarness {
    h: Harness,
    key: EcdsaKeyPair,
    enrollment: ReviewEnrollment,
    registration: ReviewRegistration,
    reviewer: support::Pki,
    credentials: Credentials,
}
struct ReviewRunning {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ReviewRunning {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ReviewHarness {
    async fn new() -> Option<Self> {
        let mut h = Harness::new().await?;
        h.ledger = h.ledger.clone().with_clock(Arc::new(Time(NOW)));
        h.f.sql();
        h.f.descriptor["rendering"]["template_digest"] = json!(template_digest().unwrap());
        h.f.descriptor["rendering"]["media_type"] = json!("text/plain");
        h.f.repin_descriptor();
        let rng = SystemRandom::new();
        let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der.as_ref(), &rng).unwrap();
        let enrollment = ReviewEnrollment {
            credential_id: URL_SAFE_NO_PAD.encode(b"native-credential"),
            reviewer: h.f.identity.subject.clone(),
            rp_id: "review.example".into(),
            origin: "https://review.example".into(),
            public_key_sec1: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
            user_handle: URL_SAFE_NO_PAD.encode(b"native-reviewer"),
            hardware_bound_required: false,
        };
        let rule = ReviewRule {
            credentials: BTreeMap::from([(enrollment.credential_id.clone(), enrollment.clone())]),
        };
        let schema = result_schema();
        let question = RecordReference {
            id: "question:canonical-review".into(),
            schema: "https://example.test/questions/review".into(),
            digest: "a".repeat(64),
        };
        let schema_ref = RecordReference {
            id: "schema:canonical-review".into(),
            schema: "https://kedgeflow.dev/spec/drafts/review-evidence-result-v0.1.schema.json"
                .into(),
            digest: digest("result-schema", &schema).unwrap(),
        };
        let predicates = vec![
            EvidencePredicate::BooleanEquals {
                field: "approved".into(),
                expected: true,
            },
            EvidencePredicate::BooleanEquals {
                field: "hardware_bound".into(),
                expected: false,
            },
        ];
        h.f.trust.evidence.insert(
            "review".into(),
            EvidenceRequirement {
                obligation: RequiredObligation {
                    predicate_digest: digest("evidence-predicate", &json!(predicates)).unwrap(),
                    stage: "jit".into(),
                    execution_relevant: true,
                },
                provider_id: "provider:canonical-review".into(),
                provider_version: "0.1".into(),
                keys: keys(28),
                question: question.clone(),
                result_schema_ref: schema_ref.clone(),
                result_schema: schema,
                max_age_ms: 60000,
                predicates,
                review: Some(rule.clone()),
            },
        );
        h.f.trust.obligation_manifest_digest = h.f.trust.registered_obligations_digest().unwrap();
        h.definition.obligation_manifest_digest = h.f.trust.obligation_manifest_digest.clone();
        h.f.trust.policy = h.definition.reference(7).unwrap();
        let encoded = |key: u8| {
            BTreeMap::from([(
                format!("key-{key}"),
                base64::engine::general_purpose::STANDARD.encode(
                    SigningKey::from_bytes(&[key; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
            )])
        };
        let registration = ReviewRegistration {
            tenant: h.f.trust.tenant.clone(),
            initiating_workload: h.f.identity.workload_id.clone(),
            initiating_subjects: vec![h.f.identity.subject.clone()],
            proposal_keys: encoded(1),
            registry_keys: encoded(2),
            descriptor_digest: h.f.trust.descriptor_digest.clone(),
            ownership_epoch: h.f.trust.ownership_epoch,
            policy: h.f.trust.policy.clone(),
            rule,
            provider_id: "provider:canonical-review".into(),
            provider_version: "0.1".into(),
            question,
            result_schema_ref: schema_ref,
            max_proposal_age_ms: 60000,
            lifetime_ms: 30000,
        };
        let mut pki =
            support::pki_for_workloads(&["spiffe://test/agent", "spiffe://test/reviewer"]);
        let reviewer = pki.pop().unwrap();
        h.pki = pki.pop().unwrap();
        let credentials = Credentials::new(&enrollment.reviewer, "kf.review");
        h.ledger.publish_policy(&h.bootstrap()).await.unwrap();
        h.ledger.enroll_review(enrollment.clone()).await.unwrap();
        Some(Self {
            h,
            key,
            enrollment,
            registration,
            reviewer,
            credentials,
        })
    }
    fn client(&self) -> reqwest::Client {
        kedgeflow::tls::pinned_http_client_pem(
            self.reviewer.ca.as_bytes(),
            self.reviewer.client.as_bytes(),
            self.reviewer.client_key.as_bytes(),
            Duration::from_secs(5),
        )
        .unwrap()
    }
    async fn start_with(
        &self,
        registration: ReviewRegistration,
        clock: Arc<dyn Clock>,
    ) -> ReviewRunning {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/review", listener.local_addr().unwrap());
        let service = Arc::new(
            ReviewService::new(
                registration,
                self.h.ledger.clone(),
                clock,
                self.credentials.auth(&url),
                "kf.review".into(),
                "spiffe://test/reviewer".into(),
                "key-28".into(),
                SigningKey::from_bytes(&[28; 32]),
            )
            .unwrap(),
        );
        let tls = kedgeflow::tls::server_config_pem(
            self.reviewer.server.as_bytes(),
            self.reviewer.server_key.as_bytes(),
            self.reviewer.ca.as_bytes(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, tls, service.router())
                .await
                .unwrap();
        });
        ReviewRunning { url, task }
    }
    async fn start(&self) -> ReviewRunning {
        self.start_with(self.registration.clone(), Arc::new(Time(NOW)))
            .await
    }
    fn begin(&self, verdict: &str) -> Value {
        let p = self.h.f.packet();
        verify_record(&p.proposal, "proposal", &keys(1)).unwrap();
        verify_record(&p.descriptor, "ctd", &keys(2)).unwrap();
        json!({"profile":PROFILE,"operation":"begin","request_id":"review-begin","credential_id":self.enrollment.credential_id,"proposal":String::from_utf8(p.proposal).unwrap(),"descriptor":String::from_utf8(p.descriptor).unwrap(),"verdict":verdict})
    }
    fn assertion(&self, approval: &Approval, count: u32, flags: u8) -> ReviewAssertion {
        let client=serde_json::to_vec(&json!({"type":"webauthn.get","challenge":approval.challenge().unwrap(),"origin":self.enrollment.origin,"crossOrigin":false})).unwrap();
        let mut auth = Sha256::digest(approval.rp_id.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&count.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        ReviewAssertion {
            credential_id: self.enrollment.credential_id.clone(),
            client_data_json: URL_SAFE_NO_PAD.encode(&client),
            authenticator_data: URL_SAFE_NO_PAD.encode(auth),
            signature: URL_SAFE_NO_PAD.encode(
                self.key
                    .sign(&SystemRandom::new(), &signed)
                    .unwrap()
                    .as_ref(),
            ),
            user_handle: Some(self.enrollment.user_handle.clone()),
        }
    }
    fn complete(&self, approval: &Approval, assertion: &ReviewAssertion) -> Value {
        let mut body = self.begin(&approval.verdict);
        body["operation"] = json!("complete");
        body.as_object_mut().unwrap().remove("credential_id");
        body.as_object_mut().unwrap().remove("verdict");
        body["approval"] = json!(approval);
        body["assertion"] = json!(assertion);
        body
    }
    async fn post(&self, url: &str, body: &Value) -> (reqwest::StatusCode, Value) {
        review_post(&self.client(), &self.credentials, url, body).await
    }
    async fn proof(
        &self,
        server: &ReviewRunning,
        verdict: &str,
        count: u32,
    ) -> (Approval, ReviewAssertion, Value) {
        let (code, body) = self.post(&server.url, &self.begin(verdict)).await;
        assert_eq!(code, reqwest::StatusCode::OK, "{body}");
        let approval: Approval = serde_json::from_value(body["approval"].clone()).unwrap();
        assert_eq!(body["challenge"], approval.challenge().unwrap());
        assert_eq!(
            approval.rendered_digest,
            hex::encode(Sha256::digest(
                body["rendered"].as_str().unwrap().as_bytes()
            ))
        );
        let assertion = self.assertion(&approval, count, 5);
        let body = self.complete(&approval, &assertion);
        (approval, assertion, body)
    }
    fn admission(&self, witness: &str) -> Value {
        let mut body = self.h.admission("reviewed-admit");
        let manifest: String = body["manifest"].as_str().unwrap().into();
        let mut m: Value = serde_json::from_str(&manifest).unwrap();
        let e: Value = serde_json::from_str(witness).unwrap();
        m["payload"]["witnesses"].as_array_mut().unwrap().push(json!({"witness":{"id":e["payload"]["wid"],"schema":e["schema"],"digest":record_hash(witness.as_bytes())},"obligation_id":"review","execution_relevant":true,"expires_at":e["payload"]["expires_at"]}));
        m["payload"]["assembled_at"] = json!(NOW);
        body["manifest"] =
            json!(String::from_utf8(signed("manifest", m["payload"].clone(), 3)).unwrap());
        body["witnesses"]
            .as_array_mut()
            .unwrap()
            .push(json!(witness));
        body
    }
}
async fn review_post(
    client: &reqwest::Client,
    credentials: &Credentials,
    url: &str,
    body: &Value,
) -> (reqwest::StatusCode, Value) {
    let response = client
        .post(url)
        .headers(credentials.headers(url))
        .json(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    let mut schema: Value = serde_json::from_str(include_str!(
        "../../../../spec/drafts/review-evidence-http-v0.1.schema.json"
    ))
    .unwrap();
    schema["oneOf"] = schema["$defs"]["Response"]["oneOf"].clone();
    assert!(
        jsonschema::validator_for(&schema).unwrap().is_valid(&value),
        "{value}"
    );
    (status, value)
}

#[tokio::test]
async fn native_review_retries_restart_admission_and_issuance_compare_consumption() {
    let Some(r) = ReviewHarness::new().await else {
        return;
    };
    let server = r.start().await;
    let (_, _, body) = r.proof(&server, "approve", 1).await;
    let (code, first) = r.post(&server.url, &body).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{first}");
    let witness = first["witness"].as_str().unwrap();
    verify_record(witness.as_bytes(), "evidence", &keys(28)).unwrap();
    let (_, retry) = r.post(&server.url, &body).await;
    assert_eq!(retry["witness"], witness);
    drop(server);
    let server = r.start().await;
    let (_, retry) = r.post(&server.url, &body).await;
    assert_eq!(retry["witness"], witness);
    let control = r.h.start().await;
    let (code, admitted) = r.h.post(&control.admit, &r.admission(witness)).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{admitted}");
    let certificate = admitted["certificate"].as_str().unwrap();
    let issue = r.h.issuance("reviewed-issue", certificate);
    let (code, issued) = r.h.post(&control.issue, &issue).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{issued}");
    let (_, retry) = r.h.post(&control.issue, &issue).await;
    assert_eq!(retry["grant"], issued["grant"]);
    assert_eq!(
        r.h.ledger
            .read_key(&r.h.counter_key())
            .await
            .unwrap()
            .unwrap(),
        b"1"
    );
    r.h.ledger
        .revoke_review(&r.enrollment.credential_id)
        .await
        .unwrap();
    assert_eq!(
        r.post(&server.url, &body).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        r.h.post(&control.admit, &r.admission(witness)).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        r.h.post(&control.issue, &issue).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        r.h.ledger
            .read_key(&r.h.counter_key())
            .await
            .unwrap()
            .unwrap(),
        b"1"
    );
}

#[tokio::test]
async fn native_review_revocation_between_admission_and_issuance_allocates_no_fence() {
    let Some(r) = ReviewHarness::new().await else {
        return;
    };
    let server = r.start().await;
    let (_, _, body) = r.proof(&server, "approve", 1).await;
    let (_, done) = r.post(&server.url, &body).await;
    let witness = done["witness"].as_str().unwrap();
    let control = r.h.start().await;
    let (code, admitted) = r.h.post(&control.admit, &r.admission(witness)).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{admitted}");
    r.h.ledger
        .revoke_review(&r.enrollment.credential_id)
        .await
        .unwrap();
    let issue =
        r.h.issuance("revoked", admitted["certificate"].as_str().unwrap());
    assert_eq!(
        r.h.post(&control.issue, &issue).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(
        r.h.ledger
            .read_key(&r.h.counter_key())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn native_review_consumed_unpublished_retry_retains_original_time_and_publisher() {
    let Some(r) = ReviewHarness::new().await else {
        return;
    };
    let server = r.start().await;
    let (approval, assertion, body) = r.proof(&server, "approve", 1).await;
    // Retain exactly the consumption transaction but no output, as after a death
    // before publication. The shipping-process fault test covers that crash below.
    r.h.ledger
        .consume_review(&approval, &assertion, &Time(NOW))
        .await
        .unwrap();
    drop(server);
    let server = r.start().await;
    let (code, done) = r.post(&server.url, &body).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{done}");
    let witness = done["witness"].as_str().unwrap();
    let e = verify_record(witness.as_bytes(), "evidence", &keys(28)).unwrap();
    assert_eq!(e.payload["observed_at"], NOW);
    assert_eq!(e.payload["result"]["sign_count"], 1);
    let mut registration = r.registration.clone();
    registration.provider_version = "0.2".into();
    drop(server);
    let server = r.start_with(registration, Arc::new(Time(NOW))).await;
    assert_eq!(
        r.post(&server.url, &body).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn native_review_fabricated_signed_facts_and_substitutions_refuse() {
    let Some(r) = ReviewHarness::new().await else {
        return;
    };
    let server = r.start().await;
    let (_, _, body) = r.proof(&server, "approve", 1).await;
    let (_, done) = r.post(&server.url, &body).await;
    let witness = done["witness"].as_str().unwrap();
    let good = verify_record(witness.as_bytes(), "evidence", &keys(28))
        .unwrap()
        .payload;
    let control = r.h.start().await;
    for field in [
        "nonce",
        "assertion_digest",
        "parameters_digest",
        "rendered_digest",
        "policy_epoch",
        "verified_at",
        "approved",
        "hardware_bound",
        "enrollment_digest",
        "sign_count",
        "extra",
    ] {
        let mut e = good.clone();
        let f = &mut e["result"];
        match field {
            "nonce" => f["approval"]["nonce"] = json!(URL_SAFE_NO_PAD.encode([99; 32])),
            "parameters_digest" | "rendered_digest" => f["approval"][field] = json!("e".repeat(64)),
            "policy_epoch" => f["approval"][field] = json!(8),
            "verified_at" => {
                f[field] = json!(NOW - 1);
                e["observed_at"] = json!(NOW - 1);
            }
            "approved" => f[field] = json!(false),
            "hardware_bound" => f[field] = json!(true),
            "sign_count" => f[field] = json!(2),
            "extra" => f["grant"] = json!(true),
            _ => f[field] = json!("e".repeat(64)),
        }
        let fake = String::from_utf8(signed("evidence", e, 28)).unwrap();
        let (code, out) = r.h.post(&control.admit, &r.admission(&fake)).await;
        assert!(!code.is_success(), "accepted {field}: {out}");
    }
    assert!(
        r.h.ledger
            .read_key(&r.h.counter_key())
            .await
            .unwrap()
            .is_none()
    );
    let (code, out) = r.h.post(&control.admit, &r.admission(witness)).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{out}");
}

#[tokio::test]
async fn native_review_native_permissions_proof_replay_closed_inputs_and_rejections() {
    let Some(r) = ReviewHarness::new().await else {
        return;
    };
    let server = r.start().await;
    let client = r.client();
    let begin = r.begin("approve");
    let headers = r.credentials.headers(&server.url);
    let response = client
        .post(&server.url)
        .headers(headers.clone())
        .json(&begin)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        client
            .post(&server.url)
            .headers(headers)
            .json(&begin)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        review_post(&r.h.client(), &r.credentials, &server.url, &begin)
            .await
            .0,
        reqwest::StatusCode::FORBIDDEN
    );
    let mut subject = r.enrollment.reviewer.clone();
    subject.sub = "wrong-reviewer".into();
    let wrong = Credentials::new(&subject, "kf.review");
    assert_eq!(
        review_post(&client, &wrong, &server.url, &begin).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    let wrong = Credentials::new(&r.enrollment.reviewer, "kf.admit");
    assert_eq!(
        review_post(&client, &wrong, &server.url, &begin).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    for field in ["nonce", "rendered", "reviewed_at", "grant"] {
        let mut wrong = begin.clone();
        wrong[field] = json!("caller");
        assert_eq!(
            r.post(&server.url, &wrong).await.0,
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    let mut wrong = begin.clone();
    wrong["profile"] = json!("KF-REVIEW-0");
    assert_eq!(
        r.post(&server.url, &wrong).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .post(&server.url)
            .headers(r.credentials.headers(&server.url))
            .header("origin", "https://review.example")
            .json(&begin)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .post(&server.url)
            .headers(r.credentials.headers(&server.url))
            .header("mcp-kedgeflow-grant", "bogus")
            .json(&begin)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let (approval, assertion, complete) = r.proof(&server, "approve", 1).await;
    let mut negatives = vec![r.assertion(&approval, 1, 1), r.assertion(&approval, 0, 5)];
    let mut wrong = assertion.clone();
    wrong.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    negatives.push(wrong);
    let mut wrong = assertion.clone();
    wrong.client_data_json=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"type":"webauthn.get","challenge":approval.challenge().unwrap(),"origin":"https://evil.example","crossOrigin":false})).unwrap());
    negatives.push(wrong);
    for negative in negatives {
        assert_eq!(
            r.post(&server.url, &r.complete(&approval, &negative))
                .await
                .0,
            reqwest::StatusCode::FORBIDDEN
        );
    }
    let mut changed = complete.clone();
    changed["approval"]["parameters_digest"] = json!("e".repeat(64));
    assert_eq!(
        r.post(&server.url, &changed).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        r.post(&server.url, &complete).await.0,
        reqwest::StatusCode::OK
    );
    let (_, _, reject) = r.proof(&server, "reject", 2).await;
    let (code, done) = r.post(&server.url, &reject).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{done}");
    let control = r.h.start().await;
    assert_eq!(
        r.h.post(
            &control.admit,
            &r.admission(done["witness"].as_str().unwrap())
        )
        .await
        .0,
        reqwest::StatusCode::FORBIDDEN
    );
    drop(server);
    let expired = r
        .start_with(r.registration.clone(), Arc::new(Time(NOW + 30001)))
        .await;
    assert_eq!(
        r.post(&expired.url, &complete).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    let mut changed = r.h.bootstrap();
    changed.policy.epoch += 1;
    r.h.ledger.publish_policy(&changed).await.unwrap();
    let server = r.start().await;
    assert_eq!(
        r.post(&server.url, &begin).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        r.post(&server.url, &complete).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
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
async fn native_review_shipping_process_crash_before_publication_and_custody_refusal() {
    use axum::{Extension, Json, Router, http::StatusCode, response::IntoResponse, routing::post};
    use base64::engine::general_purpose::STANDARD;
    use std::{
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        sync::atomic::AtomicBool,
    };
    let Some(mut r) = ReviewHarness::new().await else {
        return;
    };
    let now = kedgeflow::clock::SystemClock.now_ms();
    r.credentials = Credentials::new_at(&r.enrollment.reviewer, "kf.review", now);
    let agent = Credentials::new_at(
        &r.h.f.identity.subject,
        "capacity.reserve kf.admit kf.issue",
        now,
    );
    r.h.f.proposal["delegation"] = agent.delegation.clone();
    r.h.f.proposal["created_at"] = json!(now - 10);
    r.h.f.proposal["baseline_state"][0]["observed_at"] = json!(now - 12);
    r.h.f.proposal["baseline_state"][0]["expires_at"] = json!(now + 60000);
    let material = support::pki_for_workloads(&["spiffe://test/review-service"])
        .pop()
        .unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let block = Arc::new(AtomicBool::new(true));
    let prefix = r.h.prefix.clone();
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    let router = Router::new().route(
        "/v3/kv/txn",
        post({
            let entered = entered.clone();
            let release = release.clone();
            let block = block.clone();
            let prefix = prefix.clone();
            move |Extension(workload): Extension<WorkloadIdentity>,
                  headers: http::HeaderMap,
                  Json(value): Json<Value>| {
                let entered = entered.clone();
                let release = release.clone();
                let block = block.clone();
                let prefix = prefix.clone();
                let endpoint = endpoint.clone();
                async move {
                    if workload.as_str() != "spiffe://test/review-service"
                        || headers.get("authorization").and_then(|v| v.to_str().ok())
                            != Some("review-etcd-token")
                    {
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    let publication = value["success"].as_array().is_some_and(|ops| {
                        ops.iter().any(|v| {
                            v["request_put"]["key"]
                                .as_str()
                                .and_then(|s| STANDARD.decode(s).ok())
                                .is_some_and(|key| {
                                    String::from_utf8_lossy(&key)
                                        .starts_with(&format!("{prefix}/review/evidence/"))
                                })
                        })
                    });
                    if publication && block.swap(false, Ordering::SeqCst) {
                        entered.notify_one();
                        release.notified().await;
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    let response = reqwest::Client::new()
                        .post(format!("{endpoint}/v3/kv/txn"))
                        .json(&value)
                        .send()
                        .await
                        .unwrap();
                    let status = response.status();
                    let bytes = response.bytes().await.unwrap();
                    (status, [("content-type", "application/json")], bytes).into_response()
                }
            }
        }),
    );
    let proxy = support::serve_tls(&material, router).await;
    let dir = tempfile::Builder::new()
        .prefix("kf-review-process-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let root = dir.path();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let write = |name: &str, data: &[u8], mode: u32| {
        let path = root.join(name);
        std::fs::write(&path, data).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    };
    let certificate = write("server.pem", r.reviewer.server.as_bytes(), 0o644);
    let private_key = write("server-key.pem", r.reviewer.server_key.as_bytes(), 0o600);
    let workload_ca = write("workload-ca.pem", r.reviewer.ca.as_bytes(), 0o644);
    let etcd_ca = write("etcd-ca.pem", material.ca.as_bytes(), 0o644);
    let etcd_certificate = write("etcd-client.pem", material.client.as_bytes(), 0o644);
    let etcd_private_key = write("etcd-key.pem", material.client_key.as_bytes(), 0o600);
    let token = write("etcd-token", b"review-etcd-token", 0o600);
    let seed = write("provider-seed", STANDARD.encode([28; 32]).as_bytes(), 0o600);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("https://{listen}/review");
    let config = json!({"listen":listen.to_string(),"url":url,"certificate":certificate,"private_key":private_key,"workload_ca":workload_ca,"oidc_issuer":r.enrollment.reviewer.iss,"oidc_public_key_base64":STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),"audience":AUDIENCE,"scope":"kf.review","reviewer_workload":"spiffe://test/reviewer","etcd_endpoint":proxy.url,"etcd_prefix":prefix,"etcd_ca":etcd_ca,"etcd_certificate":etcd_certificate,"etcd_private_key":etcd_private_key,"etcd_token_file":token,"provider_key_id":"key-28","provider_signing_key_file":seed,"registration":r.registration});
    let path = write("review.json", &serde_json::to_vec(&config).unwrap(), 0o644);
    let command = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kf-review"));
        c.arg("--custody-root").arg(root).arg("--config").arg(&path);
        c
    };
    assert!(command().arg("--check").output().unwrap().status.success());
    // Offline check must not enroll or touch an unavailable remote endpoint.
    let mut offline = config.clone();
    offline["etcd_endpoint"] = json!("https://127.0.0.1:1");
    std::fs::write(&path, serde_json::to_vec(&offline).unwrap()).unwrap();
    assert!(command().arg("--check").output().unwrap().status.success());
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    for mode in [0o644, 0o620] {
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(!command().arg("--check").output().unwrap().status.success());
    }
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = root.join("linked-seed");
    std::os::unix::fs::symlink(&seed, &linked).unwrap();
    let mut changed = config.clone();
    changed["provider_signing_key_file"] = json!(linked);
    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(!command().arg("--check").output().unwrap().status.success());
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kf-review"))
        .arg("--print-template-digest")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        template_digest().unwrap()
    );
    // Existing create-only enrollment cannot silently reset the counter.
    assert!(!command().arg("--enroll").output().unwrap().status.success());
    let log = root.join("process.log");
    let spawn = || {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        Process(
            command()
                .stdout(Stdio::null())
                .stderr(file)
                .spawn()
                .unwrap(),
        )
    };
    let ready = || async {
        for _ in 0..100 {
            if let Ok(response) = r.client().get(&url).send().await
                && response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!(
            "shipping review startup failed: {}",
            std::fs::read_to_string(&log).unwrap()
        );
    };
    let process = spawn();
    ready().await;
    let (code, begin) = r.post(&url, &r.begin("approve")).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{begin}");
    let approval: Approval = serde_json::from_value(begin["approval"].clone()).unwrap();
    let assertion = r.assertion(&approval, 1, 5);
    let body = r.complete(&approval, &assertion);
    let client = r.client();
    let headers = r.credentials.headers(&url);
    let request_body = body.clone();
    let request_url = url.clone();
    let request = tokio::spawn(async move {
        client
            .post(&request_url)
            .headers(headers)
            .json(&request_body)
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    // The consumed record is independently visible before the SIGKILL; no
    // publication put reaches etcd while this barrier is held.
    let challenge_key = format!(
        "{}/review/challenges/{}",
        prefix,
        digest("review-nonce", &json!(approval.nonce)).unwrap()
    );
    // Key spelling is pinned by the core; query its complete review subtree.
    let response:Value=reqwest::Client::new().post(format!("{}/v3/kv/range",std::env::var("ETCD_ENDPOINT").unwrap())).json(&json!({"key":STANDARD.encode(format!("{prefix}/review/")),"range_end":STANDARD.encode(format!("{prefix}/review0"))})).send().await.unwrap().json().await.unwrap();
    let states = response["kvs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|kv| {
            (
                String::from_utf8(STANDARD.decode(kv["key"].as_str().unwrap()).unwrap()).unwrap(),
                serde_json::from_slice::<Value>(
                    &STANDARD.decode(kv["value"].as_str().unwrap()).unwrap(),
                )
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        states
            .iter()
            .any(|(_, v)| v["consumed"] == true && v["completion"]["sign_count"] == 1),
        "{challenge_key}: {states:?}"
    );
    assert!(states.iter().all(|(k, _)| !k.contains("/review/evidence/")));
    let verified_at = states
        .iter()
        .find(|(_, v)| v["consumed"] == true)
        .unwrap()
        .1["completion"]["verified_at"]
        .clone();
    drop(process);
    request.abort();
    release.notify_one();
    let process = spawn();
    ready().await;
    let (code, done) = r.post(&url, &body).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{done}");
    let witness = done["witness"].as_str().unwrap();
    let envelope = verify_record(witness.as_bytes(), "evidence", &keys(28)).unwrap();
    assert_eq!(envelope.payload["observed_at"], verified_at);
    assert_eq!(envelope.payload["result"]["sign_count"], 1);
    drop(process);
    let process = spawn();
    ready().await;
    let (code, retry) = r.post(&url, &body).await;
    assert_eq!(code, reqwest::StatusCode::OK, "{retry}");
    assert_eq!(retry["witness"], witness);
    drop(process);
    assert!(command().arg("--revoke").output().unwrap().status.success());
    let process = spawn();
    ready().await;
    assert_eq!(r.post(&url, &body).await.0, reqwest::StatusCode::FORBIDDEN);
    drop(process);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_review_revocation_races_admission_allocation_and_issuance_cas() {
    use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::post};
    use base64::engine::general_purpose::STANDARD;
    use std::sync::atomic::AtomicBool;
    for phase in ["admission", "fence-allocation", "issuance"] {
        let Some(mut r) = ReviewHarness::new().await else {
            return;
        };
        let review = r.start().await;
        let (_, _, body) = r.proof(&review, "approve", 1).await;
        let (_, done) = r.post(&review.url, &body).await;
        let witness = done["witness"].as_str().unwrap();
        let admission = r.admission(witness);
        let certificate = if phase != "admission" {
            let control = r.h.start().await;
            let (code, out) = r.h.post(&control.admit, &admission).await;
            assert_eq!(code, reqwest::StatusCode::OK, "{out}");
            Some(out["certificate"].as_str().unwrap().to_owned())
        } else {
            None
        };
        let direct = r.h.ledger.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let block = Arc::new(AtomicBool::new(true));
        let prefix = r.h.prefix.clone();
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
                            ops.iter().any(|v| {
                                v["request_put"]["key"]
                                    .as_str()
                                    .and_then(|s| STANDARD.decode(s).ok())
                                    .is_some_and(|key| {
                                        String::from_utf8_lossy(&key)
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
        r.h.ledger = EtcdLedger::new(
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            endpoint,
            &r.h.prefix,
        )
        .unwrap()
        .with_clock(Arc::new(Time(NOW)));
        let control = r.h.start().await;
        let (url, body) = if let Some(cert) = certificate {
            (control.issue.clone(), r.h.issuance("race", &cert))
        } else {
            (control.admit.clone(), admission)
        };
        let client = r.h.client();
        let credentials = r.h.credentials.clone();
        let request =
            tokio::spawn(async move { super::post(&client, &credentials, &url, &body).await });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        direct
            .revoke_review(&r.enrollment.credential_id)
            .await
            .unwrap();
        release.notify_one();
        let (code, out) = request.await.unwrap();
        assert_eq!(code, StatusCode::FORBIDDEN, "{phase}: {out}");
        if phase == "issuance" {
            assert_eq!(
                direct.read_key(&r.h.counter_key()).await.unwrap().unwrap(),
                b"1"
            );
        } else {
            assert!(direct.read_key(&r.h.counter_key()).await.unwrap().is_none());
        }
        let key =
            r.h.f
                .trust
                .operation_key(&r.h.f.identity, r.h.f.packet().proposal.as_slice())
                .unwrap();
        assert!(
            direct
                .read_key(&format!("{}/issuance/{key}", r.h.prefix))
                .await
                .unwrap()
                .is_none()
        );
        if phase == "admission" {
            assert!(
                direct
                    .read_key(&format!("{}/admission/{key}", r.h.prefix))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        proxy.abort();
    }
}

#[test]
fn native_review_example_registration_and_rule_pins_match() {
    let config: kedgeflow::review_config::ReviewConfig =
        serde_json::from_str(include_str!("../../../../config/review.example.json")).unwrap();
    config.registration.validate().unwrap();
    let evidence: BTreeMap<String, kedgeflow::control_config::EvidenceRegistration> =
        serde_json::from_str(include_str!(
            "../../../../config/review-evidence.example.json"
        ))
        .unwrap();
    let e = &evidence["review"];
    assert_eq!(e.result_schema, result_schema());
    assert_eq!(e.result_schema_ref, config.registration.result_schema_ref);
    assert_eq!(e.question, config.registration.question);
    assert_eq!(
        e.obligation.predicate_digest,
        digest("evidence-predicate", &json!(e.predicates)).unwrap()
    );
    assert_eq!(json!(e.review), json!(config.registration.rule));
    let mut value = json!(config.registration.rule);
    value["credentials"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap()["hardware_bound_required"] = json!(true);
    let rule: ReviewRule = serde_json::from_value(value).unwrap();
    assert!(rule.validate().is_err());
}
