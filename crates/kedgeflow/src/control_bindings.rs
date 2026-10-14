//! Observer-attested control snapshots retained in authority transactions.
use crate::{
    clock::Clock,
    contracts::{Grant, canonical, digest, strict_value},
    control_history::{ControlHistoryBundle, HistoryObserver},
    control_history_verify::{ControlHistoryTrust, ControlHistoryVerification, verify_history},
    error::{Error, Result},
    governance::{
        Acknowledgement, EnforcementScope, Installation, Revocation, RevocationTarget,
        trust_digest, validate_ack,
    },
    ledger::{EtcdLedger, get, put, range_kv, record, version_zero},
    recovery::Candidate,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const LEASE_PROFILE: &str = "KF-CONTROL-BINDINGS-0.2-draft";
pub const PROFILE: &str = "KF-CONTROL-BINDINGS-0.1-draft";
const MAX_BUNDLE: usize = 40 << 20;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlState {
    pub history_sequence: u64,
    pub history_digest: String,
    pub installation_digest: String,
    pub acknowledgement_digest: String,
    pub checked_at: i64,
    pub absent_revocations: Vec<RevocationTarget>,
}
pub(crate) struct ControlCheck {
    pub compare: Vec<Value>,
    pub state: Option<ControlState>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityControlBinding {
    pub phase: String,
    pub authority_digest: String,
    pub attempt_id: Option<String>,
    pub control: ControlState,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingCheckpointPayload {
    pub observer_id: String,
    pub namespace: String,
    pub tenant: String,
    pub operation_key: String,
    pub grant_digest: String,
    pub attempt_id: String,
    pub history_digest: String,
    pub bindings_digest: String,
    pub captured_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingCheckpoint {
    pub profile: String,
    pub kind: String,
    pub key_id: String,
    pub payload: BindingCheckpointPayload,
    pub signature: String,
}
impl BindingCheckpoint {
    fn message(&self) -> Result<Vec<u8>> {
        let mut raw = format!("KedgeFlow:{}\0", self.profile).into_bytes();
        raw.extend(canonical(&json!({"profile":self.profile,"kind":self.kind,"key_id":self.key_id,"payload":self.payload}))?);
        Ok(raw)
    }
    fn verify(&self, trust: &ControlHistoryTrust) -> Result<()> {
        let key = trust
            .observer_keys
            .get(&self.key_id)
            .ok_or_else(|| refuse("unregistered control binding observer"))?;
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| refuse("invalid binding signature encoding"))?;
        let sig =
            Signature::from_slice(&raw).map_err(|_| refuse("invalid binding signature length"))?;
        if ![PROFILE, LEASE_PROFILE].contains(&self.profile.as_str())
            || self.kind != "operation_bindings"
            || key.verify_strict(&self.message()?, &sig).is_err()
        {
            return Err(refuse("invalid binding checkpoint signature/profile"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBindingsBundle {
    pub profile: String,
    pub history: ControlHistoryBundle,
    pub bindings: Vec<AuthorityControlBinding>,
    pub checkpoint: BindingCheckpoint,
}
fn refuse(s: &str) -> Error {
    Error::Refused(s.into())
}
impl ControlBindingsBundle {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BUNDLE {
            return Err(refuse("control binding bundle exceeds bound"));
        }
        let b: Self = serde_json::from_value(strict_value(raw)?)?;
        b.bound()?;
        Ok(b)
    }
    fn bound(&self) -> Result<()> {
        if !(3..=4).contains(&self.bindings.len())
            || canonical(&serde_json::to_value(self)?)?.len() > MAX_BUNDLE
        {
            return Err(refuse("control binding carriage exceeds bound"));
        }
        static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
        static LEASE_SCHEMA: std::sync::OnceLock<jsonschema::Validator> =
            std::sync::OnceLock::new();
        let profile_value = serde_json::to_value(self)?;
        let (slot, raw) = match profile_value["profile"].as_str() {
            Some(PROFILE) => (
                &SCHEMA,
                include_str!("../../../spec/drafts/control-bindings-v0.1.schema.json"),
            ),
            Some(LEASE_PROFILE) => (
                &LEASE_SCHEMA,
                include_str!("../../../spec/drafts/control-bindings-v0.2.schema.json"),
            ),
            _ => return Err(Error::Invalid("unknown historical profile".into())),
        };
        let schema = slot.get_or_init(|| {
            crate::schema::compile(
                &serde_json::from_str(raw).expect("embedded control bindings schema"),
            )
            .expect("valid control bindings schema")
        });
        if !schema.is_valid(&serde_json::to_value(self)?) {
            return Err(refuse("closed control binding schema mismatch"));
        }
        self.history.bound()
    }
}
impl EtcdLedger {
    pub(crate) fn admission_control_key(&self, key: &str) -> String {
        format!("{}/admission-control/{key}", self.namespace())
    }
    pub(crate) fn issuance_control_key(&self, key: &str) -> String {
        format!("{}/issuance-control/{key}", self.namespace())
    }
    pub(crate) fn execution_control_key(&self, g: &Grant, attempt: &str, phase: &str) -> String {
        format!(
            "{}/control-bindings/{}/{phase}",
            self.root(g),
            crate::ledger::key_part(attempt)
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retain_control_binding(
        &self,
        compares: &mut Vec<Value>,
        writes: &mut Vec<Value>,
        key: &str,
        phase: &str,
        authority_digest: &str,
        attempt: Option<&str>,
        state: &Option<ControlState>,
    ) -> Result<()> {
        if let Some(control) = state {
            compares.push(version_zero(key));
            writes.push(put(
                key,
                &record(&AuthorityControlBinding {
                    phase: phase.into(),
                    authority_digest: authority_digest.into(),
                    attempt_id: attempt.map(String::from),
                    control: control.clone(),
                })?,
            ));
        }
        Ok(())
    }
    /// Authorized operator disclosure. Observer custody and correct ledger
    /// operation are trusted; the attestation is not an etcd consensus proof.
    pub async fn export_control_bindings(
        &self,
        c: &Candidate,
        operation_key: &str,
        observer: &HistoryObserver,
        clock: &dyn Clock,
    ) -> Result<ControlBindingsBundle> {
        let history = self
            .export_control_history(c, operation_key, observer, clock)
            .await?;
        let keys = [
            self.admission_control_key(operation_key),
            self.issuance_control_key(operation_key),
            self.execution_control_key(&c.grant, &c.attempt_id, "claim"),
            self.execution_control_key(&c.grant, &c.attempt_id, "dispatch"),
        ];
        let t = self
            .txn(vec![], keys.iter().map(|k| get(k)).collect(), vec![])
            .await?;
        if !t.succeeded || t.responses.len() != 4 {
            return Err(refuse("invalid control bindings read"));
        }
        let dispatched = history
            .lineage
            .outcomes
            .journal
            .iter()
            .any(|e| e["phase"] == "dispatch_authorized");
        let mut bindings = Vec::new();
        for (index, r) in t.responses.iter().enumerate() {
            let kv = range_kv(r)?;
            if index == 3 && !dispatched {
                if kv.is_some() {
                    return Err(refuse("unexpected retained dispatch binding"));
                }
            } else {
                let kv = kv.ok_or_else(|| {
                    refuse("missing retained authority control binding; no synthesis")
                })?;
                bindings.push(serde_json::from_value(strict_value(&kv.value)?)?);
            }
        }
        let profile = if history.profile == crate::control_history::LEASE_PROFILE {
            LEASE_PROFILE
        } else {
            PROFILE
        };
        let mut checkpoint = BindingCheckpoint {
            profile: profile.into(),
            kind: "operation_bindings".into(),
            key_id: observer.key_id.clone(),
            payload: BindingCheckpointPayload {
                observer_id: observer.id.clone(),
                namespace: self.namespace().into(),
                tenant: history.checkpoint.payload.tenant.clone(),
                operation_key: operation_key.into(),
                grant_digest: history.lineage.issuance.grant_digest.clone(),
                attempt_id: c.attempt_id.clone(),
                history_digest: digest(
                    "control-bindings-history",
                    &serde_json::to_value(&history)?,
                )?,
                bindings_digest: digest(
                    "control-bindings-records",
                    &serde_json::to_value(&bindings)?,
                )?,
                captured_at: clock.now_ms(),
            },
            signature: String::new(),
        };
        checkpoint.signature =
            URL_SAFE_NO_PAD.encode(observer.key.sign(&checkpoint.message()?).to_bytes());
        let bundle = ControlBindingsBundle {
            profile: profile.into(),
            history,
            bindings,
            checkpoint,
        };
        bundle.bound()?;
        Ok(bundle)
    }
}
#[derive(Debug, Serialize)]
pub struct ControlBindingsVerification {
    pub profile: String,
    pub phases_verified: Vec<String>,
    pub history_sequences: Vec<u64>,
    pub control_state: String,
    pub history: ControlHistoryVerification,
}
pub fn verify_control_bindings(
    b: &ControlBindingsBundle,
    trust: &ControlHistoryTrust,
) -> Result<ControlBindingsVerification> {
    b.bound()?;
    trust.validate()?;
    b.checkpoint.verify(trust)?;
    // Exact per-phase acknowledgement checks replace RFC 0013's weaker
    // single-acknowledgement clock-cover test; the public old verifier is unchanged.
    let mut history = verify_history(&b.history, trust, false)?;
    let l = &history.lineage;
    let cp = &b.checkpoint.payload;
    let g = trust
        .operation
        .grants
        .verify_retained(b.history.lineage.issuance.signed_grant.as_bytes())?
        .grant;
    if cp.observer_id != trust.observer_id
        || cp.namespace != trust.namespace
        || cp.tenant != l.tenant
        || cp.operation_key != l.operation_key
        || cp.grant_digest != l.grant_digest
        || cp.attempt_id != l.attempt_id
        || cp.captured_at < b.history.checkpoint.payload.captured_at
        || cp.history_digest
            != digest(
                "control-bindings-history",
                &serde_json::to_value(&b.history)?,
            )?
        || cp.bindings_digest
            != digest(
                "control-bindings-records",
                &serde_json::to_value(&b.bindings)?,
            )?
    {
        return Err(refuse("operation control checkpoint correlation mismatch"));
    }
    let dispatched = b
        .history
        .lineage
        .outcomes
        .journal
        .iter()
        .any(|e| e["phase"] == "dispatch_authorized");
    let phases: &[&str] = if dispatched {
        &["admission", "issuance", "claim", "dispatch"]
    } else {
        &["admission", "issuance", "claim"]
    };
    if b.bindings.len() != phases.len() {
        return Err(refuse("missing/unexpected authority control phase"));
    }
    let expected_scope = EnforcementScope::grant(&g)?;
    let pin = trust_digest(
        &trust.operation.admission,
        &trust.operation.admission_keys,
        &trust.operation.grants.keys,
    )?;
    let issuers: BTreeMap<_, _> = trust
        .operation
        .grants
        .keys
        .iter()
        .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
        .collect();
    let mut last_sequence = 0;
    let mut last_time = 0;
    for (binding, phase) in b.bindings.iter().zip(phases) {
        let s = &binding.control;
        let admission = *phase == "admission";
        let execution = matches!(*phase, "claim" | "dispatch");
        let expected_digest = if admission {
            &l.certificate_digest
        } else {
            &l.grant_digest
        };
        let expected_attempt = execution.then_some(l.attempt_id.as_str());
        let mut targets = vec![RevocationTarget::Domain];
        if !admission {
            targets.extend([
                RevocationTarget::Root {
                    id: g.root_id.clone(),
                },
                RevocationTarget::Grant { id: g.gid.clone() },
            ]);
        }
        let minimum = if admission {
            l.admitted_at
        } else {
            l.issued_at
        };
        let expiry = if admission {
            b.history.lineage.admission.expires_at
        } else {
            g.expires_at
        };
        if binding.phase != *phase
            || binding.authority_digest != *expected_digest
            || binding.attempt_id.as_deref() != expected_attempt
            || s.absent_revocations != targets
            || s.history_sequence < last_sequence
            || s.checked_at < last_time
            || s.checked_at < minimum
            || s.checked_at >= expiry
            || s.checked_at > cp.captured_at
            || s.checked_at > b.history.checkpoint.payload.captured_at
            || (!admission && s.checked_at < g.valid_from)
        {
            return Err(refuse(
                "control phase/authority/target/order/clock mismatch",
            ));
        }
        if execution {
            let journal_phase = if *phase == "claim" {
                "claimed"
            } else {
                "dispatch_authorized"
            };
            let time = b
                .history
                .lineage
                .outcomes
                .journal
                .iter()
                .find(|e| e["phase"] == journal_phase)
                .and_then(|e| e["event_time"].as_i64())
                .ok_or_else(|| refuse("missing control phase journal"))?;
            if s.checked_at > time {
                return Err(refuse("control observation follows phase journal"));
            }
        }
        let head = b
            .history
            .events
            .iter()
            .find(|e| e.sequence == s.history_sequence)
            .ok_or_else(|| refuse("control snapshot outside authenticated history"))?;
        if head.digest()? != s.history_digest || head.accepted_at > s.checked_at {
            return Err(refuse("control snapshot head/time mismatch"));
        }
        let mut installed = None;
        let mut ack = None;
        for event in b.history.events.iter().take(s.history_sequence as usize) {
            match event.kind.as_str() {
                "install" => {
                    installed = Some((
                        event.control.payload::<Installation>("install")?,
                        event.control.digest.clone(),
                    ))
                }
                "acknowledge" => {
                    ack = Some((
                        event.control.payload::<Acknowledgement>("acknowledge")?,
                        event.control.digest.clone(),
                    ))
                }
                "revoke" => {
                    let r: Revocation = event.control.payload("revoke")?;
                    if targets.contains(&r.target) {
                        return Err(refuse(
                            "applicable revocation precedes retained control CAS",
                        ));
                    }
                }
                _ => {}
            }
        }
        let (i, id) = installed.ok_or_else(|| refuse("control snapshot lacks installation"))?;
        let (a, ad) = ack.ok_or_else(|| refuse("control snapshot lacks acknowledgement"))?;
        if s.installation_digest != id
            || s.acknowledgement_digest != ad
            || i.registration.scope != expected_scope
            || i.registration.policy != g.policy
            || i.registration.ownership_epoch != g.ownership_epoch
            || i.registration.trust_digest != pin
            || i.registration.issuer_keys != issuers
        {
            return Err(refuse(
                "retained control installation/acknowledgement/membership mismatch",
            ));
        }
        validate_ack(&a, &i, &id, s.checked_at)?;
        last_sequence = s.history_sequence;
        last_time = s.checked_at;
    }
    history
        .lineage
        .missing_links
        .retain(|s| s != "operation-bound installation/revocation CAS sequence and clock trust");
    history
        .lineage
        .missing_links
        .push("observer custody/correct ledger operation and authority clock trust".into());
    history.operation_control_state =
        "observer_attested_per_phase_control_comparisons; no live permission".into();
    Ok(ControlBindingsVerification {
        profile: b.profile.clone(),
        phases_verified: phases.iter().map(|s| s.to_string()).collect(),
        history_sequences: b
            .bindings
            .iter()
            .map(|r| r.control.history_sequence)
            .collect(),
        control_state: "observer_attested_retained_CAS; not_consensus_proof".into(),
        history,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{
        ControlRegistration, DescriptorPublication, PolicyPublication, sign_control, verify_control,
    };
    use ed25519_dalek::SigningKey;
    struct Time;
    impl Clock for Time {
        fn now_ms(&self) -> i64 {
            1_800_000_000_001
        }
    }
    // A deterministic native CAS primitive test. Integration tests separately
    // qualify authenticated governance and complete authority transitions.
    #[tokio::test]
    async fn pending_control_compare_refuses_concurrent_governance_append_atomically() {
        let endpoint = match std::env::var("ETCD_ENDPOINT") {
            Ok(e) => e,
            Err(_) => {
                assert!(
                    std::env::var("KF_REQUIRE_ETCD").is_err(),
                    "required etcd endpoint absent"
                );
                eprintln!("SKIP native control CAS test: ETCD_ENDPOINT absent");
                return;
            }
        };
        let config: Value = serde_json::from_str(include_str!(
            "../../../config/control-history-trust.example.json"
        ))
        .unwrap();
        let registration: ControlRegistration =
            serde_json::from_value(config["historical"][0]["registration"].clone()).unwrap();
        let trust = crate::control_history_config::ControlHistoryTrustConfig::decode(
            &canonical(&config).unwrap(),
        )
        .unwrap()
        .registration()
        .unwrap();
        let ledger = EtcdLedger::new(
            reqwest::Client::builder().no_proxy().build().unwrap(),
            endpoint,
            format!("/kf-control-cas-tests/{}", rand::random::<u64>()),
        )
        .unwrap()
        .with_clock(std::sync::Arc::new(Time));
        let store = |kind: &str, payload: Value, seed: u8| {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let id = format!("key-{seed}");
            let raw = sign_control(kind, &payload, &id, &key).unwrap();
            verify_control::<Value>(&raw, kind, &BTreeMap::from([(id, key.verifying_key())]))
                .unwrap()
                .1
        };
        let policy = store(
            "publish_policy",
            json!(PolicyPublication {
                registration: registration.clone(),
                definition: trust.operation.policy.clone()
            }),
            10,
        );
        let descriptor = store(
            "register_descriptor",
            json!(DescriptorPublication {
                registration: registration.clone(),
                descriptor: "software-unit-fixture".into()
            }),
            11,
        );
        ledger
            .publish_control(&policy, "publish_policy")
            .await
            .unwrap();
        ledger
            .publish_control(&descriptor, "register_descriptor")
            .await
            .unwrap();
        let i = Installation {
            registration: registration.clone(),
            revision: 1,
            expected_revision: 0,
            policy_publication_digest: policy.digest,
            descriptor_publication_digest: descriptor.digest,
        };
        let installation = store("install", json!(i), 12);
        ledger.install_control(&installation).await.unwrap();
        let a = Acknowledgement {
            installation_digest: installation.digest,
            revision: 1,
            component_id: registration.acknowledger.component_id.clone(),
            workload_id: registration.acknowledger.workload_id.clone(),
            coverage: "gateway_control_checks".into(),
            installed_at: 1_800_000_000_000,
            expires_at: 1_800_000_010_000,
        };
        let ack = store("acknowledge", json!(a), 9);
        ledger
            .acknowledge_in_domain(&ack, &a, &registration.scope.conflict_domain)
            .await
            .unwrap();
        let pending = ledger
            .control_check(
                &registration.scope,
                &registration.policy,
                registration.ownership_epoch,
                Some("root"),
                Some("grant"),
            )
            .await
            .unwrap();
        let state = pending.state.unwrap();
        assert_eq!(state.history_sequence, 4);
        // Publication alone changes history while installation and ack remain
        // identical: the new head comparison is what refuses this pending CAS.
        let mut next = registration.clone();
        next.policy = trust
            .operation
            .policy
            .reference(next.policy.epoch + 1)
            .unwrap();
        let publication = store(
            "publish_policy",
            json!(PolicyPublication {
                registration: next,
                definition: trust.operation.policy
            }),
            10,
        );
        ledger
            .publish_control(&publication, "publish_policy")
            .await
            .unwrap();
        let authority_key = format!("{}/pending-authority", ledger.namespace());
        let binding_key = format!("{}/pending-binding", ledger.namespace());
        let mut compares = pending.compare;
        let mut writes = vec![put(&authority_key, "must-not-appear")];
        ledger
            .retain_control_binding(
                &mut compares,
                &mut writes,
                &binding_key,
                "claim",
                &"a".repeat(64),
                Some("attempt"),
                &Some(state),
            )
            .unwrap();
        assert!(
            !ledger
                .txn(compares, writes, vec![])
                .await
                .unwrap()
                .succeeded
        );
        assert!(ledger.read_key(&authority_key).await.unwrap().is_none());
        assert!(ledger.read_key(&binding_key).await.unwrap().is_none());
        let fresh = ledger
            .control_check(
                &registration.scope,
                &registration.policy,
                registration.ownership_epoch,
                Some("root"),
                Some("grant"),
            )
            .await
            .unwrap();
        assert_eq!(fresh.state.as_ref().unwrap().history_sequence, 5);
        assert!(
            ledger
                .txn(
                    fresh.compare,
                    vec![put(&authority_key, "fresh-observation")],
                    vec![]
                )
                .await
                .unwrap()
                .succeeded
        );
    }
}
