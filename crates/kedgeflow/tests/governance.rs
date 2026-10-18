#[path = "support/a2a_root.rs"]
mod a2a_root;
#[path = "support/action_domain.rs"]
mod action_domain_tests;
#[path = "support/compensation.rs"]
mod compensation_tests;
#[path = "support/family_peer.rs"]
mod family_peer_tests;
#[path = "support/family.rs"]
mod family_tests;
#[allow(unused_imports, dead_code)]
#[path = "support/admission_fixture.rs"]
mod fixture;
#[path = "support/hierarchical_leaf.rs"]
mod hierarchical_leaf;
#[path = "support/live_agent.rs"]
mod live_agent;
#[path = "support/reserved_history.rs"]
mod reserved_history;
#[path = "support/reserved_leaf.rs"]
mod reserved_leaf;
#[path = "support/saga_forward.rs"]
mod saga_forward;
#[path = "support/saga.rs"]
mod saga_tests;
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use fixture::{Fixture, NOW, Time, keys};
use kedgeflow::{
    auth::DualAuthenticator,
    contracts::{Grant, GrantVerifier, canonical},
    gateway::ToolDescriptor,
    governance::*,
    governance_service::{AdministrativeRole, GovernanceService, GovernanceTrust},
    issuance::{GrantAuthority, IssuanceVerifier},
    ledger::{AuthorityLedger, EtcdLedger},
    policy::{AdmissionController, CedarAdmissionPolicy, CedarPolicyDefinition},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};
const POLICY: &str = r#"permit(principal, action == KedgeFlow::Action::"admit", resource);"#;
const AUD: &str = "urn:kedgeflow:administration-test";
struct TestClock(AtomicI64);
impl kedgeflow::clock::Clock for TestClock {
    fn now_ms(&self) -> i64 {
        let value = self.0.load(Ordering::SeqCst);
        if value == 0 {
            kedgeflow::clock::Clock::now_ms(&kedgeflow::clock::SystemClock)
        } else {
            value
        }
    }
}
fn jwt(header: Value, claims: Value, key: u8) -> String {
    let m = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    format!(
        "{m}.{}",
        URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[key; 32])
                .sign(m.as_bytes())
                .to_bytes()
        )
    )
}
struct Harness {
    f: Fixture,
    registration: ControlRegistration,
    definition: CedarPolicyDefinition,
    ledger: EtcdLedger,
    prefix: String,
    clock: Arc<TestClock>,
    url: String,
    token: String,
    jwk: Value,
    jti: AtomicU64,
    admin: reqwest::Client,
    gateway: reqwest::Client,
    gateway_pki: support::Pki,
    agent_pki: support::Pki,
    _task: tokio::task::JoinHandle<()>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self._task.abort();
    }
}
impl Harness {
    async fn new() -> Option<Self> {
        Self::with_gateway(None).await
    }
    async fn with_gateway(gateway_url: Option<&str>) -> Option<Self> {
        Self::with_setup(gateway_url, NOW, |_| {}).await
    }
    async fn with_setup(
        gateway_url: Option<&str>,
        now: i64,
        configure: impl FnOnce(&mut Fixture),
    ) -> Option<Self> {
        Self::with_environment(gateway_url, now, configure, None, None).await
    }
    async fn with_environment(
        gateway_url: Option<&str>,
        now: i64,
        configure: impl FnOnce(&mut Fixture),
        gate: Option<kedgeflow::restore::RestoreGate>,
        pkis: Option<Vec<support::Pki>>,
    ) -> Option<Self> {
        Self::with_environment_and_pair(gateway_url, now, configure, gate, pkis, None).await
    }
    async fn with_environment_and_pair(
        gateway_url: Option<&str>,
        now: i64,
        configure: impl FnOnce(&mut Fixture),
        gate: Option<kedgeflow::restore::RestoreGate>,
        pkis: Option<Vec<support::Pki>>,
        pair: Option<(kedgeflow::action_domain::Selection, Option<String>)>,
    ) -> Option<Self> {
        Self::with_native_options(gateway_url, now, configure, gate, pkis, pair, None).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn with_native_options(
        gateway_url: Option<&str>,
        now: i64,
        configure: impl FnOnce(&mut Fixture),
        gate: Option<kedgeflow::restore::RestoreGate>,
        pkis: Option<Vec<support::Pki>>,
        pair: Option<(kedgeflow::action_domain::Selection, Option<String>)>,
        inverse: Option<kedgeflow::compensation::Contract>,
    ) -> Option<Self> {
        Box::pin(Self::with_native_timing(
            gateway_url,
            now,
            configure,
            gate,
            pkis,
            pair,
            inverse,
            None,
        ))
        .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn with_native_timing(
        gateway_url: Option<&str>,
        now: i64,
        configure: impl FnOnce(&mut Fixture),
        gate: Option<kedgeflow::restore::RestoreGate>,
        pkis: Option<Vec<support::Pki>>,
        pair: Option<(kedgeflow::action_domain::Selection, Option<String>)>,
        inverse: Option<kedgeflow::compensation::Contract>,
        lifetime_ms: Option<i64>,
    ) -> Option<Self> {
        Box::pin(Self::with_family_options(
            gateway_url,
            now,
            configure,
            gate,
            pkis,
            pair,
            inverse,
            lifetime_ms,
            None,
        ))
        .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn with_family_options(
        gateway_url: Option<&str>,
        now: i64,
        configure: impl FnOnce(&mut Fixture),
        gate: Option<kedgeflow::restore::RestoreGate>,
        pkis: Option<Vec<support::Pki>>,
        pair: Option<(kedgeflow::action_domain::Selection, Option<String>)>,
        inverse: Option<kedgeflow::compensation::Contract>,
        lifetime_ms: Option<i64>,
        family: Option<(String, kedgeflow::family::Selection)>,
    ) -> Option<Self> {
        let combined = gate.is_some();
        let shared_prefix = pair.as_ref().is_some_and(|(_, p)| p.is_some());
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(v) => v,
            Err(_) => {
                assert_ne!(std::env::var("KF_REQUIRE_ETCD").as_deref(), Ok("1"));
                eprintln!("SKIP governance: ETCD_ENDPOINT absent");
                return None;
            }
        };
        let mut f = Fixture::new();
        configure(&mut f);
        f.trust.inverse_contract = inverse;
        if let Some(url) = gateway_url {
            f.descriptor["gateway_audience"] = json!(url);
            f.trust.descriptor_digest =
                fixture::record_hash(&fixture::signed("ctd", f.descriptor.clone(), 2));
            f.proposal["action"]["digest"] = json!(f.trust.descriptor_digest);
        }
        let delta = now - NOW;
        f.proposal["created_at"] = json!(f.proposal["created_at"].as_i64().unwrap() + delta);
        for field in ["observed_at", "expires_at"] {
            f.proposal["baseline_state"][0][field] =
                json!(f.proposal["baseline_state"][0][field].as_i64().unwrap() + delta);
            f.evidence[field] = json!(f.evidence[field].as_i64().unwrap() + delta);
        }
        f.proposal["delegation"]["expires_at"] =
            json!(f.proposal["delegation"]["expires_at"].as_i64().unwrap() + delta);
        if f.trust.inverse_contract.is_some() {
            f.identity.delegation_digest =
                kedgeflow::contracts::digest("delegation", &f.proposal["delegation"]).unwrap();
        }
        let definition = CedarPolicyDefinition {
            tenant: f.trust.tenant.clone(),
            policy_id: f.trust.policy.id.clone(),
            cedar: POLICY.into(),
            obligation_manifest_digest: f.trust.obligation_manifest_digest.clone(),
            max_certificate_lifetime_ms: lifetime_ms.unwrap_or(if combined && pair.is_none() {
                8000
            } else {
                5000
            }),
        };
        f.trust.policy = definition.reference(7).unwrap();
        let scope = EnforcementScope {
            conflict_domain: f.descriptor["concurrency"]["conflict_domain"]
                .as_str()
                .unwrap()
                .into(),
            action: serde_json::from_value(f.proposal["action"].clone()).unwrap(),
            resource: serde_json::from_value(f.proposal["resources"][0].clone()).unwrap(),
            audience: f.descriptor["gateway_audience"].as_str().unwrap().into(),
            adapter_contract: f.descriptor["adapter_contract"].clone(),
            predicate_descriptor: f.descriptor["concurrency"]["predicate_descriptor"].clone(),
        };
        let registration = ControlRegistration {
            tenant: f.trust.tenant.clone(),
            scope,
            policy: f.trust.policy.clone(),
            ownership_epoch: f.trust.ownership_epoch,
            obligation_manifest_digest: f.trust.obligation_manifest_digest.clone(),
            issuer_keys: keys(5)
                .iter()
                .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
                .collect(),
            trust_digest: trust_digest(&f.trust, &keys(6), &keys(5)).unwrap(),
            acknowledger: Acknowledger {
                component_id: "gateway-test".into(),
                workload_id: "spiffe://test/gateway".into(),
                key_id: "key-9".into(),
                public_key_hex: hex::encode(
                    SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes(),
                ),
                max_lifetime_ms: if lifetime_ms.is_some() || (combined && pair.is_none()) {
                    60000
                } else {
                    10000
                },
            },
        };
        let roles = [
            ("publish_policy", 10),
            ("register_descriptor", 11),
            ("install", 12),
            ("revoke", 13),
            ("query", 0),
        ]
        .into_iter()
        .map(|(kind, key)| {
            (
                kind.into(),
                AdministrativeRole {
                    subject: f.identity.subject.clone(),
                    workload_id: "spiffe://test/operator".into(),
                    scope: format!("kf.{kind}"),
                    keys: if key == 0 { BTreeMap::new() } else { keys(key) },
                },
            )
        })
        .collect();
        let trust = GovernanceTrust {
            registration: registration.clone(),
            admission: f.trust.clone(),
            definition: definition.clone(),
            admission_keys: keys(6),
            issuer_keys: keys(5),
            roles,
        };
        let clock = Arc::new(TestClock(AtomicI64::new(now)));
        let prefix = family
            .as_ref()
            .map(|(p, _)| p.clone())
            .or_else(|| pair.as_ref().and_then(|(_, p)| p.clone()))
            .unwrap_or_else(|| {
                format!(
                    "/kf-governance-tests/{}-{}",
                    std::process::id(),
                    rand::random::<u64>()
                )
            });
        let mut ledger = EtcdLedger::new(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            endpoint,
            &prefix,
        )
        .unwrap()
        .with_clock(clock.clone())
        .requiring_control(Some(registration.trust_digest.clone()));
        if let Some(gate) = gate {
            if shared_prefix {
                gate.check(&ledger).await.unwrap();
            } else {
                gate.enroll_empty(&ledger).await.unwrap();
            }
            ledger = ledger.with_restore_gate(gate).unwrap();
        }
        if let Some((s, _)) = pair {
            if family.is_none() {
                s.topology.enroll(&ledger).await.unwrap();
            }
            ledger = ledger.with_action_domain(s).unwrap();
        }
        if let Some((_, f)) = family {
            ledger = f.attach(ledger).unwrap();
        }
        let mut pkis = pkis.unwrap_or_else(|| {
            support::pki_for_workloads(&[
                "spiffe://test/operator",
                "spiffe://test/gateway",
                "spiffe://test/agent",
            ])
        });
        let agent_pki = pkis.pop().unwrap();
        let gateway_pki = pkis.pop().unwrap();
        let admin_pki = pkis.pop().unwrap();
        let client = |p: &support::Pki| {
            kedgeflow::tls::pinned_http_client_pem(
                p.ca.as_bytes(),
                p.client.as_bytes(),
                p.client_key.as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap()
        };
        let admin = client(&admin_pki);
        let gateway = client(&gateway_pki);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/control", listener.local_addr().unwrap());
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes())});
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()));
        let token = jwt(
            json!({"alg":"EdDSA","typ":"at+jwt"}),
            json!({"iss":f.identity.subject.iss,"sub":f.identity.subject.sub,"aud":AUD,"exp":now/1000+60,"iat":now/1000,"scope":"kf.publish_policy kf.register_descriptor kf.install kf.revoke kf.query","cnf":{"jkt":jkt}}),
            7,
        );
        let auth = DualAuthenticator::new(
            &f.identity.subject.iss,
            AUD,
            &url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let service =
            Arc::new(GovernanceService::new(trust, ledger.clone(), auth, clock.clone()).unwrap());
        let tls = kedgeflow::tls::server_config_pem(
            admin_pki.server.as_bytes(),
            admin_pki.server_key.as_bytes(),
            admin_pki.ca.as_bytes(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            kedgeflow::server::serve_router(listener, tls, service.router())
                .await
                .unwrap();
        });
        Some(Self {
            f,
            registration,
            definition,
            ledger,
            prefix,
            clock,
            url,
            token,
            jwk,
            jti: AtomicU64::new(1),
            admin,
            gateway,
            gateway_pki,
            agent_pki,
            _task: task,
        })
    }
    fn headers(&self) -> http::HeaderMap {
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":self.jwk}),
            json!({"jti":format!("gov-{}",self.jti.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":self.url,"iat":kedgeflow::clock::Clock::now_ms(self.clock.as_ref())/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(self.token.as_bytes()))}),
            8,
        );
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            format!("DPoP {}", self.token).parse().unwrap(),
        );
        h.insert("dpop", proof.parse().unwrap());
        h
    }
    async fn post(&self, record: &str, ack: bool) -> (reqwest::StatusCode, Value) {
        let c = if ack { &self.gateway } else { &self.admin };
        let mut request=c.post(&self.url).json(&json!({"profile":PROFILE,"operation":"apply","request_id":"gov-request","record":record}));
        if !ack {
            request = request.headers(self.headers());
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let status = response.status();
        let value = response.json::<Value>().await.unwrap();
        validate_control(&value).unwrap();
        (status, value)
    }
    async fn bootstrap(&self) -> StoredControl {
        let pp = sign_control(
            "publish_policy",
            &PolicyPublication {
                registration: self.registration.clone(),
                definition: self.definition.clone(),
            },
            "key-10",
            &SigningKey::from_bytes(&[10; 32]),
        )
        .unwrap();
        let rp = sign_control(
            "register_descriptor",
            &DescriptorPublication {
                registration: self.registration.clone(),
                descriptor: String::from_utf8(self.f.packet().descriptor).unwrap(),
            },
            "key-11",
            &SigningKey::from_bytes(&[11; 32]),
        )
        .unwrap();
        let (status, p) = self.post(&pp, false).await;
        assert!(status.is_success(), "{p}");
        let (status, r) = self.post(&rp, false).await;
        assert!(status.is_success(), "{r}");
        let i = Installation {
            registration: self.registration.clone(),
            revision: 1,
            expected_revision: 0,
            policy_publication_digest: p["digest"].as_str().unwrap().into(),
            descriptor_publication_digest: r["digest"].as_str().unwrap().into(),
        };
        let raw =
            sign_control("install", &i, "key-12", &SigningKey::from_bytes(&[12; 32])).unwrap();
        let (status, result) = self.post(&raw, false).await;
        assert!(status.is_success(), "{result}");
        StoredControl {
            digest: result["digest"].as_str().unwrap().into(),
            record: raw,
        }
    }
    fn tool(&self) -> ToolDescriptor {
        let s = &self.registration.scope;
        ToolDescriptor {
            inverse_contract: self.f.trust.inverse_contract.clone(),
            name: "node_drain".into(),
            read_only: false,
            required_scope: "capacity.reserve".into(),
            status_scope: "kf.status".into(),
            action: Some(s.action.clone()),
            resource: Some(s.resource.clone()),
            conflict_domain: s.conflict_domain.clone(),
            adapter_contract: s.adapter_contract.clone(),
            predicate_id: s.predicate_descriptor["id"].as_str().unwrap().into(),
            predicate_version: s.predicate_descriptor["version"].as_str().unwrap().into(),
            version_parameter: "expected_version".into(),
            fence_parameter: s.adapter_contract["fence_parameter"]
                .as_str()
                .unwrap()
                .into(),
            admission_endpoint: "https://control.test/admit".into(),
        }
    }
    fn ack(&self, installed: &StoredControl) -> String {
        acknowledge_gateway(
            &installed.payload("install").unwrap(),
            &installed.digest,
            &[self.tool()],
            &GrantVerifier {
                keys: keys(5),
                audience: self.registration.scope.audience.clone(),
            },
            &self.registration.acknowledger.workload_id,
            &SigningKey::from_bytes(&[9; 32]),
            kedgeflow::clock::Clock::now_ms(self.clock.as_ref()),
        )
        .unwrap()
    }
    async fn issue(&self) -> kedgeflow::error::Result<kedgeflow::ledger::IssuanceResult> {
        let packet = self.f.packet();
        let clock = Time(self.clock.0.load(Ordering::SeqCst));
        let inputs = self
            .f
            .trust
            .verify_inputs(&self.f.identity, packet.borrowed(), &clock)?;
        let controller = AdmissionController::new(
            CedarAdmissionPolicy::new(self.definition.clone(), self.f.trust.policy.clone())?,
            "key-6".into(),
            SigningKey::from_bytes(&[6; 32]),
        )?;
        let certificate = self
            .ledger
            .admit(&controller.prepare(&inputs, &clock)?, &clock)
            .await?
            .record
            .signed_certificate;
        GrantAuthority::new(
            IssuanceVerifier {
                tenant: self.f.trust.tenant.clone(),
                admission_keys: keys(6),
                grants: GrantVerifier {
                    keys: keys(5),
                    audience: self.registration.scope.audience.clone(),
                },
            },
            "key-5".into(),
            SigningKey::from_bytes(&[5; 32]),
        )?
        .issue(&self.ledger, &inputs, certificate.as_bytes(), &clock)
        .await
    }
    async fn revoke(&self, target: RevocationTarget) -> StoredControl {
        let raw = sign_control(
            "revoke",
            &Revocation {
                tenant: self.registration.tenant.clone(),
                conflict_domain: self.registration.scope.conflict_domain.clone(),
                target,
                revision: 1,
                reason_digest: "a".repeat(64),
            },
            "key-13",
            &SigningKey::from_bytes(&[13; 32]),
        )
        .unwrap();
        let (s, v) = self.post(&raw, false).await;
        assert!(s.is_success(), "{v}");
        StoredControl {
            record: raw,
            digest: v["digest"].as_str().unwrap().into(),
        }
    }
}
#[tokio::test]
async fn native_control_publication_install_ack_issue_claim_and_dispatch_revocation() {
    let Some(h) = Harness::new().await else {
        return;
    };
    assert!(h.issue().await.is_err());
    let installed = h.bootstrap().await;
    assert!(h.issue().await.is_err());
    // Repeating installation retains its original record and creates no ack.
    assert!(h.post(&installed.record, false).await.0.is_success());
    let ack = h.ack(&installed);
    assert_eq!(h.post(&ack, false).await.0, reqwest::StatusCode::FORBIDDEN);
    let (status, v) = h.post(&ack, true).await;
    assert!(status.is_success(), "{v}");
    let issued = h.issue().await.unwrap();
    let grant: Grant = serde_json::from_value(
        serde_json::from_str::<Value>(&issued.record.signed_grant).unwrap()["payload"].clone(),
    )
    .unwrap();
    let mut direct = grant.clone();
    direct.root_id = "legacy-extra-root".into();
    direct.gid = "legacy-extra-grant".into();
    direct.nonce = "legacy-extra-nonce".into();
    assert!(
        h.ledger
            .issue(&direct, "a".repeat(64).as_str())
            .await
            .is_err()
    );
    let mut replacement = grant.clone();
    replacement.root_generation += 1;
    replacement.fence += 1;
    replacement.gid = "legacy-replacement".into();
    replacement.nonce = "legacy-replacement-nonce".into();
    assert!(
        h.ledger
            .replace(&grant, &replacement, "b".repeat(64).as_str())
            .await
            .is_err()
    );
    let attempt = h
        .ledger
        .claim(&grant, &issued.record.grant_digest, "first")
        .await
        .unwrap();
    let revoke = h
        .revoke(RevocationTarget::Root {
            id: grant.root_id.clone(),
        })
        .await;
    assert!(
        h.ledger
            .authorize_dispatch(&grant, &issued.record.grant_digest, &attempt.id)
            .await
            .is_err()
    );
    assert!(h.issue().await.is_err());
    assert!(h.post(&revoke.record, false).await.0.is_success());
    assert_eq!(
        h.ledger.status(&grant, &attempt.id).await.unwrap().status,
        "claimed"
    );
    assert!(h.ledger.publish_policy(&grant).await.is_err());
}
#[tokio::test]
async fn acknowledgement_expiry_revision_change_and_publication_conflicts_fail_closed() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let installed = h.bootstrap().await;
    let ack = h.ack(&installed);
    assert!(h.post(&ack, true).await.0.is_success());
    let issued = h.issue().await.unwrap();
    let grant: Grant = serde_json::from_value(
        serde_json::from_str::<Value>(&issued.record.signed_grant).unwrap()["payload"].clone(),
    )
    .unwrap();
    h.clock.0.store(NOW + 10000, Ordering::SeqCst);
    assert!(
        h.ledger
            .claim(&grant, &issued.record.grant_digest, "expired-ack")
            .await
            .is_err()
    );
    h.clock.0.store(NOW + 100, Ordering::SeqCst);
    let mut i: Installation = installed.payload("install").unwrap();
    i.revision = 2;
    i.expected_revision = 1;
    let raw = sign_control("install", &i, "key-12", &SigningKey::from_bytes(&[12; 32])).unwrap();
    assert!(h.post(&raw, false).await.0.is_success());
    assert!(
        h.ledger
            .claim(&grant, &issued.record.grant_digest, "old-ack")
            .await
            .is_err()
    );
    assert!(!h.post(&ack, true).await.0.is_success());
    assert!(!h.post(&installed.record, false).await.0.is_success());
    let (_, current) = h
        .ledger
        .control_snapshot(&h.registration.scope.conflict_domain)
        .await
        .unwrap();
    assert!(current.is_some());
    let (installation, _) = h
        .ledger
        .control_snapshot(&h.registration.scope.conflict_domain)
        .await
        .unwrap();
    let latest = installation.unwrap();
    let new_ack = h.ack(&latest);
    assert!(h.post(&new_ack, true).await.0.is_success());
    h.ledger
        .claim(&grant, &issued.record.grant_digest, "fresh-ack")
        .await
        .unwrap();
    let mut bad_registration = h.registration.clone();
    bad_registration.policy.digest = "b".repeat(64);
    let bad = sign_control(
        "publish_policy",
        &PolicyPublication {
            registration: bad_registration,
            definition: h.definition.clone(),
        },
        "key-10",
        &SigningKey::from_bytes(&[10; 32]),
    )
    .unwrap();
    assert!(!h.post(&bad, false).await.0.is_success());
    let mut bad_tool = h.tool();
    bad_tool.action.as_mut().unwrap().digest = "c".repeat(64);
    assert!(
        acknowledge_gateway(
            &i,
            &latest.digest,
            &[bad_tool],
            &GrantVerifier {
                keys: keys(5),
                audience: i.registration.scope.audience.clone()
            },
            &i.registration.acknowledger.workload_id,
            &SigningKey::from_bytes(&[9; 32]),
            NOW + 100
        )
        .is_err()
    );
}
#[tokio::test]
async fn domain_revocation_prevents_creation_and_grant_revocation_races_claim() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let issued = h.issue().await.unwrap();
    let grant: Grant = serde_json::from_value(
        serde_json::from_str::<Value>(&issued.record.signed_grant).unwrap()["payload"].clone(),
    )
    .unwrap();
    let raw = sign_control(
        "revoke",
        &Revocation {
            tenant: h.registration.tenant.clone(),
            conflict_domain: grant.conflict_domain.clone(),
            target: RevocationTarget::Grant {
                id: grant.gid.clone(),
            },
            revision: 1,
            reason_digest: "a".repeat(64),
        },
        "key-13",
        &SigningKey::from_bytes(&[13; 32]),
    )
    .unwrap();
    let (claim, revoke) = tokio::join!(
        h.ledger
            .claim(&grant, &issued.record.grant_digest, "racing"),
        h.post(&raw, false)
    );
    assert!(revoke.0.is_success());
    assert!(
        h.ledger
            .claim(&grant, &issued.record.grant_digest, "after-revoke")
            .await
            .is_err()
    );
    if let Ok(a) = claim {
        assert!(
            h.ledger
                .authorize_dispatch(&grant, &issued.record.grant_digest, &a.id)
                .await
                .is_err()
        );
    }
    h.revoke(RevocationTarget::Domain).await;
    assert!(h.issue().await.is_err());
    assert!(!h.post(&installed.record, false).await.0.is_success() || h.issue().await.is_err());
}
#[tokio::test]
async fn wrong_record_role_tenant_unknown_fields_and_unregistered_admin_refuse() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let p = PolicyPublication {
        registration: h.registration.clone(),
        definition: h.definition.clone(),
    };
    let wrong = sign_control(
        "publish_policy",
        &p,
        "key-11",
        &SigningKey::from_bytes(&[11; 32]),
    )
    .unwrap();
    assert!(!h.post(&wrong, false).await.0.is_success());
    let mut other = p.clone();
    other.registration.tenant = "other".into();
    let wrong = sign_control(
        "publish_policy",
        &other,
        "key-10",
        &SigningKey::from_bytes(&[10; 32]),
    )
    .unwrap();
    assert!(!h.post(&wrong, false).await.0.is_success());
    let mut value = serde_json::to_value(&p).unwrap();
    value["grant_authority"] = json!(true);
    let wrong = sign_control(
        "publish_policy",
        &value,
        "key-10",
        &SigningKey::from_bytes(&[10; 32]),
    )
    .unwrap();
    assert_eq!(
        h.post(&wrong, false).await.0,
        reqwest::StatusCode::BAD_REQUEST
    );
    let good = sign_control(
        "publish_policy",
        &p,
        "key-10",
        &SigningKey::from_bytes(&[10; 32]),
    )
    .unwrap();
    let response=h.gateway.post(&h.url).headers(h.headers()).json(&json!({"profile":PROFILE,"operation":"apply","request_id":"wrong-workload","record":good})).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(
        h.ledger
            .control_snapshot(&h.registration.scope.conflict_domain)
            .await
            .unwrap()
            .0
            .is_none()
    );
}

#[tokio::test]
async fn native_gateway_configuration_verifies_and_renews_installed_acknowledgement() {
    let Some(h) = Harness::new().await else {
        return;
    };
    let installed = h.bootstrap().await;
    let endpoint = std::env::var("ETCD_ENDPOINT").unwrap();
    // TLS test intermediary preserves the actual etcd transaction response.
    // This checks token carriage, not production RBAC provisioning.
    let proxy = axum::Router::new().route(
        "/v3/kv/txn",
        axum::routing::post(move |headers: http::HeaderMap, body: axum::body::Bytes| {
            let endpoint = endpoint.clone();
            async move {
                use axum::response::IntoResponse;
                if headers.get("authorization").and_then(|h| h.to_str().ok())
                    != Some("test-etcd-role")
                {
                    return http::StatusCode::UNAUTHORIZED.into_response();
                }
                let response = reqwest::Client::new()
                    .post(format!("{endpoint}/v3/kv/txn"))
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await
                    .unwrap();
                (response.status(), response.bytes().await.unwrap()).into_response()
            }
        }),
    );
    let proxy = support::serve_tls(&h.gateway_pki, proxy).await;
    let dir = std::env::temp_dir().join(format!(
        "kf-gateway-control-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    for (name, value) in [
        ("ca.pem", h.gateway_pki.ca.clone()),
        ("client.pem", h.gateway_pki.client.clone()),
        ("key.pem", h.gateway_pki.client_key.clone()),
        ("etcd-token", "test-etcd-role".into()),
        (
            "ack-key",
            base64::engine::general_purpose::STANDARD.encode([9; 32]),
        ),
    ] {
        std::fs::write(dir.join(name), value).unwrap();
    }
    let (status, snapshot) = h
        .admin
        .post(&h.url)
        .headers(h.headers())
        .json(&json!({"profile":PROFILE,"operation":"query","request_id":"query"}))
        .send()
        .await
        .map(|r| {
            let status = r.status();
            (status, r)
        })
        .unwrap();
    assert!(status.is_success());
    validate_control(&snapshot.json::<Value>().await.unwrap()).unwrap();
    // Use the retained namespace without exposing it through agent HTTP.
    let prefix = h.ledger.namespace();
    let raw = json!({
        "require_control":true,"listen":"127.0.0.1:0","external_url":h.registration.scope.audience,
        "certificate":dir.join("client.pem"),"private_key":dir.join("key.pem"),"workload_ca":dir.join("ca.pem"),
        "grant_key_id":"key-5","grant_public_key_base64":base64::engine::general_purpose::STANDARD.encode(SigningKey::from_bytes(&[5;32]).verifying_key().as_bytes()),
        "oidc_issuer":h.f.identity.subject.iss,"oidc_public_key_base64":base64::engine::general_purpose::STANDARD.encode(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()),
        "etcd_endpoints":[proxy.url],"etcd_prefix":prefix,"etcd_ca":dir.join("ca.pem"),"etcd_token_file":dir.join("etcd-token"),
        "broker_endpoint":"https://broker.test/token","broker_ca":dir.join("ca.pem"),"target_audience":"https://target.test","target_scope":"resource:mutate","actor_workload":"spiffe://test/gateway","actor_token_file":dir.join("actor-token"),"target_url":"https://target.test/mcp","target_ca":dir.join("ca.pem"),"tools":[h.tool()],
        "enforcement":{"control_url":h.url,"control_ca":dir.join("ca.pem"),"installation_keys":{"key-12":base64::engine::general_purpose::STANDARD.encode(SigningKey::from_bytes(&[12;32]).verifying_key().as_bytes())},"component_id":"gateway-test","workload_id":"spiffe://test/gateway","acknowledgement_key_file":dir.join("ack-key")}
    });
    let mut config = kedgeflow::config::Config::decode(&serde_json::to_vec(&raw).unwrap()).unwrap();
    let interval = config.acknowledge_installation(&Time(NOW)).await.unwrap();
    assert_eq!(interval, Duration::from_millis(3333));
    let (_, ack) = h
        .ledger
        .control_snapshot(&h.registration.scope.conflict_domain)
        .await
        .unwrap();
    assert_eq!(
        ack.as_ref()
            .unwrap()
            .payload::<Acknowledgement>("acknowledge")
            .unwrap()
            .installation_digest,
        installed.digest
    );
    h.clock.0.store(NOW + 100, Ordering::SeqCst);
    config
        .acknowledge_installation(&Time(NOW + 100))
        .await
        .unwrap();
    let (_, latest) = h
        .ledger
        .control_snapshot(&h.registration.scope.conflict_domain)
        .await
        .unwrap();
    assert_ne!(latest.as_ref().unwrap().digest, ack.unwrap().digest);
    config.grant_public_key_base64 = base64::engine::general_purpose::STANDARD
        .encode(SigningKey::from_bytes(&[14; 32]).verifying_key().as_bytes());
    assert!(
        config
            .acknowledge_installation(&Time(NOW + 200))
            .await
            .is_err()
    );
    let (_, after) = h
        .ledger
        .control_snapshot(&h.registration.scope.conflict_domain)
        .await
        .unwrap();
    assert_eq!(after.unwrap().digest, latest.unwrap().digest);
}

#[tokio::test]
async fn revoke_races_issue_and_dispatch_without_reopening_authority() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let installed = h.bootstrap().await;
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let issued = h.issue().await.unwrap();
    let grant: Grant = serde_json::from_value(
        serde_json::from_str::<Value>(&issued.record.signed_grant).unwrap()["payload"].clone(),
    )
    .unwrap();
    let attempt = h
        .ledger
        .claim(&grant, &issued.record.grant_digest, "dispatch-race")
        .await
        .unwrap();
    let (dispatch, _revocation) = tokio::join!(
        h.ledger
            .authorize_dispatch(&grant, &issued.record.grant_digest, &attempt.id),
        h.revoke(RevocationTarget::Root {
            id: grant.root_id.clone()
        })
    );
    assert!(
        h.ledger
            .authorize_dispatch(&grant, &issued.record.grant_digest, &attempt.id)
            .await
            .is_err()
    );
    let part = |v: &str| URL_SAFE_NO_PAD.encode(v.as_bytes());
    let outbox = format!(
        "{}/domains/{}/roots/{}/outbox/{}",
        h.ledger.namespace(),
        part(&grant.conflict_domain),
        part(&grant.root_id),
        part(&attempt.id)
    );
    let retained = h.ledger.read_key(&outbox).await.unwrap().unwrap();
    assert_eq!(
        String::from_utf8(retained).unwrap(),
        if dispatch.is_ok() {
            "dispatch_authorized"
        } else {
            "claimed_not_dispatched"
        }
    );
    assert_eq!(
        h.ledger.status(&grant, &attempt.id).await.unwrap().status,
        "claimed"
    );
    h.f.proposal["qid"] = json!("new-operation-racing-domain-revocation");
    let (issue, _revoke) = tokio::join!(h.issue(), h.revoke(RevocationTarget::Domain));
    if let Ok(created) = issue {
        let g: Grant = serde_json::from_value(
            serde_json::from_str::<Value>(&created.record.signed_grant).unwrap()["payload"].clone(),
        )
        .unwrap();
        assert!(
            h.ledger
                .claim(&g, &created.record.grant_digest, "after-domain-revoke")
                .await
                .is_err()
        );
    }
    assert!(h.issue().await.is_err());
    let key =
        h.f.trust
            .operation_key(&h.f.identity, &h.f.packet().proposal)
            .unwrap();
    let before = h
        .ledger
        .read_key(&format!("{}/issuance/{key}", h.ledger.namespace()))
        .await
        .unwrap();
    h.f.proposal["qid"] = json!("another-operation-after-domain-revocation");
    assert!(h.issue().await.is_err());
    let after_key =
        h.f.trust
            .operation_key(&h.f.identity, &h.f.packet().proposal)
            .unwrap();
    assert!(
        h.ledger
            .read_key(&format!("{}/issuance/{after_key}", h.ledger.namespace()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.ledger
            .read_key(&format!("{}/issuance/{key}", h.ledger.namespace()))
            .await
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn native_admission_issuer_require_live_control_install_and_gateway_ack() {
    use kedgeflow::{
        auth::WorkloadIdentity,
        control::{ControlPermissions, ControlService},
    };
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let admit_url = format!("{origin}/admit");
    let issue_url = format!("{origin}/issue");
    let jwk = h.jwk.clone();
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(&jwk).unwrap()));
    let scope = "capacity.reserve kf.admit kf.issue";
    let token = jwt(
        json!({"alg":"EdDSA","typ":"at+jwt"}),
        json!({"iss":h.f.identity.subject.iss,"sub":h.f.identity.subject.sub,"aud":AUD,"exp":NOW/1000+60,"iat":NOW/1000,"scope":scope,"cnf":{"jkt":jkt}}),
        7,
    );
    let proof_counter = AtomicU64::new(1);
    let headers = |url: &str| {
        let proof = jwt(
            json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":jwk}),
            json!({"jti":format!("agent-{}",proof_counter.fetch_add(1,Ordering::SeqCst)),"htm":"POST","htu":url,"iat":NOW/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))}),
            8,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("DPoP {token}").parse().unwrap());
        headers.insert("dpop", proof.parse().unwrap());
        headers
    };
    let subject_issuer = h.f.identity.subject.iss.clone();
    let auth = |url: &str| {
        DualAuthenticator::new(
            &subject_issuer,
            AUD,
            url,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        )
        .unwrap()
    };
    let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(h.agent_pki.client.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    let identity = auth(&admit_url)
        .authenticate_at(
            &headers(&admit_url),
            &WorkloadIdentity::from_verified_cert_der(leaf.as_ref()).unwrap(),
            NOW / 1000,
        )
        .unwrap();
    h.f.proposal["delegation"] = json!({"access_token_digest":hex::encode(Sha256::digest(token.as_bytes())),"dpop_jkt":jkt,"authorization_server":h.f.identity.subject.iss,"token_audience":AUD,"scopes":scope.split_whitespace().collect::<Vec<_>>(),"expires_at":NOW+60000});
    h.f.identity = identity;
    let service = Arc::new(
        ControlService::new(
            Arc::new(h.f.trust.clone()),
            AdmissionController::new(
                CedarAdmissionPolicy::new(h.definition.clone(), h.f.trust.policy.clone()).unwrap(),
                "key-6".into(),
                SigningKey::from_bytes(&[6; 32]),
            )
            .unwrap(),
            GrantAuthority::new(
                IssuanceVerifier {
                    tenant: h.f.trust.tenant.clone(),
                    admission_keys: keys(6),
                    grants: GrantVerifier {
                        keys: keys(5),
                        audience: h.registration.scope.audience.clone(),
                    },
                },
                "key-5".into(),
                SigningKey::from_bytes(&[5; 32]),
            )
            .unwrap(),
            h.ledger.clone(),
            Arc::new(Time(NOW)),
            auth(&admit_url),
            auth(&issue_url),
            ControlPermissions {
                subjects: vec![h.f.identity.subject.clone()],
                admission_scope: "kf.admit".into(),
                issuance_scope: "kf.issue".into(),
            },
        )
        .unwrap(),
    );
    let tls = kedgeflow::tls::server_config_pem(
        h.agent_pki.server.as_bytes(),
        h.agent_pki.server_key.as_bytes(),
        h.agent_pki.ca.as_bytes(),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        kedgeflow::server::serve_router(listener, tls, service.router())
            .await
            .unwrap();
    });
    struct Running(tokio::task::JoinHandle<()>);
    impl Drop for Running {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _running = Running(task);
    let client = kedgeflow::tls::pinned_http_client_pem(
        h.agent_pki.ca.as_bytes(),
        h.agent_pki.client.as_bytes(),
        h.agent_pki.client_key.as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let p = h.f.packet();
    let body = json!({"profile":kedgeflow::control::PROFILE,"operation":"admit","request_id":"agent-admit","proposal":String::from_utf8(p.proposal.clone()).unwrap(),"descriptor":String::from_utf8(p.descriptor).unwrap(),"manifest":String::from_utf8(p.manifest).unwrap(),"witnesses":p.evidence.into_iter().map(|b|String::from_utf8(b).unwrap()).collect::<Vec<_>>()});
    assert_eq!(
        client
            .post(&admit_url)
            .headers(headers(&admit_url))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let installed = h.bootstrap().await;
    assert_eq!(
        client
            .post(&admit_url)
            .headers(headers(&admit_url))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(h.post(&h.ack(&installed), true).await.0.is_success());
    let response = client
        .post(&admit_url)
        .headers(headers(&admit_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let admission: Value = response.json().await.unwrap();
    let issue = json!({"profile":kedgeflow::control::PROFILE,"operation":"issue","request_id":"agent-issue","proposal":body["proposal"],"certificate":admission["certificate"]});
    let response = client
        .post(&issue_url)
        .headers(headers(&issue_url))
        .json(&issue)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let issued: Value = response.json().await.unwrap();
    let verified = GrantVerifier {
        keys: keys(5),
        audience: h.registration.scope.audience.clone(),
    }
    .verify(issued["grant"].as_str().unwrap().as_bytes(), NOW)
    .unwrap();
    h.ledger
        .claim(&verified.grant, &verified.digest, "native-control-claim")
        .await
        .unwrap();
    h.revoke(RevocationTarget::Domain).await;
    assert_eq!(
        client
            .post(&issue_url)
            .headers(headers(&issue_url))
            .json(&issue)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
}

#[test]
fn administrative_example_registration_is_public_only_and_closed() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/governance.example.json");
    let raw = std::fs::read(&path).unwrap();
    let config = kedgeflow::governance_config::GovernanceConfig::decode(&raw).unwrap();
    let trust = config.trust().unwrap();
    assert_eq!(
        trust.registration.scope.action.digest,
        Fixture::new().trust.descriptor_digest
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kf-governance"))
        .arg("--config")
        .arg(&path)
        .arg("--print-registration")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: ControlRegistration = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed, trust.registration);
    let mut unknown: Value = serde_json::from_slice(&raw).unwrap();
    unknown["allow_agent_publication"] = json!(true);
    assert!(
        kedgeflow::governance_config::GovernanceConfig::decode(
            &serde_json::to_vec(&unknown).unwrap()
        )
        .is_err()
    );
    let mut wrong: Value = serde_json::from_slice(&raw).unwrap();
    wrong["acknowledger"]["public_key_hex"] = json!(hex::encode(
        SigningKey::from_bytes(&[5; 32]).verifying_key().as_bytes()
    ));
    let wrong = kedgeflow::governance_config::GovernanceConfig::decode(
        &serde_json::to_vec(&wrong).unwrap(),
    )
    .unwrap();
    assert!(wrong.trust().is_err());
}

#[path = "support/control_history.rs"]
mod control_history_tests;

#[path = "support/sql_leaf.rs"]
mod sql_leaf;

#[path = "support/sql_failure.rs"]
mod sql_failure;

#[path = "support/exchange_identity.rs"]
mod exchange;
