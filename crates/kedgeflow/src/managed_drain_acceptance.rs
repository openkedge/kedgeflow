//! Complete historical acceptance-prefix carriage for the named managed action.
//! A verifier checks signatures and correlation, not native consensus, current
//! authority or physical completion. Gateway integration must read actual storage.
use crate::{
    contracts::{canonical, strict_value},
    error::{Error, Result},
    lineage::AuthorizationBundle,
    managed_drain_capture::Sources,
    managed_drain_evidence::Acceptance,
    managed_drain_journal::Change,
    managed_drain_store::Context,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const PROFILE: &str = "KF-MANAGED-DRAIN-ACCEPTANCE-0.1-draft";
pub const MAX_BYTES: usize = 2 << 20;
fn refuse() -> Error {
    Error::Refused("complete managed acceptance prefix refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub profile: String,
    pub enrollment_digest: String,
    pub authorization: AuthorizationBundle,
    pub acceptance: Acceptance,
    pub sources: Sources,
}
impl Proof {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_BYTES {
            return Err(refuse());
        }
        let value = strict_value(raw)?;
        static SCHEMA: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
        let schema = SCHEMA.get_or_init(|| {
            crate::schema::compile(
                &serde_json::from_str(include_str!(
                    "../../../spec/drafts/managed-drain-acceptance-v0.1.schema.json"
                ))
                .expect("embedded managed acceptance schema"),
            )
            .expect("valid managed acceptance schema")
        });
        if !schema.is_valid(&value) {
            return Err(refuse());
        }
        let p: Self = serde_json::from_value(value)?;
        if p.profile != PROFILE {
            return Err(refuse());
        }
        Ok(p)
    }
    /// Select the exact accepted prefix from a complete independently read
    /// source snapshot. Later activity is outside this historical proof's scope.
    pub(crate) fn from_sources(
        context: &Context,
        acceptance: Acceptance,
        authorization: AuthorizationBundle,
        mut sources: Sources,
    ) -> Result<Self> {
        if sources.origin != acceptance.origin
            || sources.events.get(..acceptance.events.len()) != Some(&acceptance.events)
        {
            return Err(refuse());
        }
        sources.events = acceptance.events.clone();
        let heads = sources
            .events
            .iter()
            .map(|e| e.digest())
            .collect::<Result<BTreeSet<_>>>()?;
        sources
            .claims
            .retain(|_, claim| heads.contains(&claim.operating_head_digest));
        let accepted = acceptance.proof.digest()?;
        sources.controls.retain(|key, _| *key == accepted);
        let p = Self {
            profile: PROFILE.into(),
            enrollment_digest: context.enrollment.digest()?,
            authorization,
            acceptance,
            sources,
        };
        p.verify_historical_cached(context)?;
        Ok(p)
    }
    /// Only producer-side immutable historical replay can be reused. Standalone
    /// verification below always replays independently. No native read, current
    /// authority decision, clock result or final comparison is cached here.
    fn verify_historical_cached(&self, c: &Context) -> Result<()> {
        use crate::family_saga_cache::{ByteCache, key};
        use std::sync::{Mutex, OnceLock};
        static CACHE: OnceLock<Mutex<ByteCache<()>>> = OnceLock::new();
        // Exhaustive destructuring requires new protected pins to be included.
        let Context {
            selection,
            physical,
            enrollment,
        } = c;
        let pins =
            canonical(&json!({"selection":selection,"physical":physical,"enrollment":enrollment}))?;
        let raw = canonical(&json!(self))?;
        if raw.len() > MAX_BYTES {
            return Err(refuse());
        }
        let identity = key("complete-historical-managed-acceptance", &[&pins, &raw]);
        let cache = CACHE.get_or_init(|| Mutex::new(ByteCache::new(8)));
        if cache.lock().map_err(|_| refuse())?.get(&identity).is_some() {
            return Ok(());
        }
        self.verify(c)?;
        cache
            .lock()
            .map_err(|_| refuse())?
            .insert(identity, pins.len() + raw.len(), ());
        Ok(())
    }
    /// Protected context must be selected independently of this proof.
    pub fn verify(&self, c: &Context) -> Result<Value> {
        let a = &self.acceptance;
        let (grant, _) = c.validate_origin(&self.sources.origin)?;
        let node = c
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&c.selection.child_id)?;
        let authorization =
            crate::lineage::verify_authorization(&self.authorization, &node.forward()?.lineage)?;
        a.controller
            .verify("controller_state", &c.physical.controller)?;
        a.controller.body.validate(&c.physical.contract, &grant)?;
        let key = a.proof.digest()?;
        let last = self.sources.events.last().ok_or_else(refuse)?;
        if self.profile != PROFILE
            || self.enrollment_digest != c.enrollment.digest()?
            || a.profile != crate::managed_drain::PROFILE
            || a.enrollment_digest != self.enrollment_digest
            || a.origin != self.sources.origin
            || a.events != self.sources.events
            || !a.controller.body.steps.is_empty()
            || a.controller.body.closed.is_some()
            || authorization.operation_key != c.enrollment.operation_key
            || self.authorization.issuance.signed_grant != a.origin.signed_grant
            || self.authorization.issuance.grant_digest != a.origin.original.grant_digest
            || a.controller.body.accepted.signed_grant != a.origin.signed_grant
            || a.controller.body.accepted.grant_digest != a.origin.original.grant_digest
            || a.controller.body.accepted.attempt_id != a.origin.original.attempt_id
            || a.proof.body.mechanical_digest != a.controller.digest()?
            || a.proof.body.checked_at != a.controller.body.accepted.accepted_at
            || last.at != a.controller.body.accepted.accepted_at
            || !matches!(&last.change, Change::ControllerAccepted { proof_digest } if proof_digest == &key)
            || self.sources.controls.len() != 1
            || self
                .sources
                .controls
                .get(&key)
                .is_none_or(|proof| json!(proof) != json!(a.proof))
            || canonical(&json!(self))?.len() > MAX_BYTES
        {
            return Err(refuse());
        }
        let proposal =
            serde_json::from_value(strict_value(self.authorization.packet.proposal.as_bytes())?)?;
        c.admission_proposal(
            &crate::managed_drain_preflight::Request {
                profile: crate::current_reservation::PROFILE.into(),
                enrollment_digest: self.enrollment_digest.clone(),
                signed_proposal: self.authorization.packet.proposal.clone(),
                requested_at: self.sources.admission.statement.body.claim.requested_at,
            },
            grant.issued_at,
        )?;
        self.sources
            .admission
            .validate(c, &proposal, grant.issued_at)?;
        if !self.authorization.packet.witnesses.iter().any(|raw| {
            strict_value(raw.as_bytes()).ok() == Some(json!(self.sources.admission.evidence))
        }) {
            return Err(refuse());
        }
        let state = self
            .sources
            .verify_prefix(c, Some(&a.controller), None, last.at)?;
        if !state.accepted || state.closed || state.pending_steps != 0 || state.send_checks != 0 {
            return Err(refuse());
        }
        Ok(
            json!({"verified":"complete_signature_correlated_acceptance_prefix",
            "profile":PROFILE,"enrollment_digest":self.enrollment_digest,
            "grant_digest":a.origin.original.grant_digest,"attempt_id":a.origin.original.attempt_id,
            "accepted_at":last.at,"source_claims":self.sources.claims.len(),
            "complete_acceptance_sources":true,"native_history_verified":false,
            "physical_status":"unresolved","execution_authority":false}),
        )
    }
}

/// Native outcome reference. Every source byte remains in the complete member
/// capture and original authorization; independent audit must reconstruct the
/// exact full SDK proof and compare this digest. It is not a detached proof.
pub const REFERENCE_PROFILE: &str = "KF-MANAGED-DRAIN-ACCEPTANCE-REFERENCE-0.1-draft";
pub const REFERENCE_KIND: &str = "managed_drain_acceptance";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub profile: String,
    pub kind: String,
    pub enrollment_digest: String,
    pub proof_digest: String,
}
impl Reference {
    pub(crate) fn from_proof(proof: &Proof) -> Result<Self> {
        if proof.profile != PROFILE || canonical(&json!(proof))?.len() > MAX_BYTES {
            return Err(refuse());
        }
        Ok(Self {
            profile: REFERENCE_PROFILE.into(),
            kind: REFERENCE_KIND.into(),
            enrollment_digest: proof.enrollment_digest.clone(),
            proof_digest: crate::contracts::digest(
                "managed-drain-complete-acceptance-proof",
                &json!(proof),
            )?,
        })
    }
    fn verify(&self, c: &Context, proof: &Proof) -> Result<()> {
        proof.verify(c)?;
        if json!(self) != json!(Self::from_proof(proof)?) {
            return Err(refuse());
        }
        Ok(())
    }
}
/// Reconstruct using complete independently carried member sources, never an
/// HTTP fetch, an adapter assertion, a digest-only substitute or embedded trust.
fn reconstruct(
    c: &Context,
    member: &crate::family_saga::MemberSnapshot,
    sources: &Sources,
) -> Result<Proof> {
    use crate::{
        kube_drain_journal::State, kube_drain_proof::Signed, managed_drain_evidence::ControlKind,
    };
    let current = member
        .physical
        .as_ref()
        .and_then(|p| p.controller.as_ref())
        .ok_or_else(refuse)?;
    let mut controls = sources
        .controls
        .values()
        .filter(|p| p.body.kind == ControlKind::Accepted);
    let control = controls.next().ok_or_else(refuse)?.clone();
    if controls.next().is_some() {
        return Err(refuse());
    }
    let header = &control.body.mechanical_header;
    let controller = Signed {
        profile: header.profile.clone(),
        kind: header.kind.clone(),
        signer_id: header.signer_id.clone(),
        key_id: header.key_id.clone(),
        signature: header.signature.clone(),
        body: State {
            accepted: current.body.accepted.clone(),
            steps: vec![],
            closed: None,
        },
    };
    let key = control.digest()?;
    let end = sources
        .events
        .iter()
        .position(
            |e| matches!(&e.change,Change::ControllerAccepted {proof_digest} if proof_digest==&key),
        )
        .ok_or_else(refuse)?
        + 1;
    let acceptance = Acceptance {
        profile: crate::managed_drain::PROFILE.into(),
        enrollment_digest: c.enrollment.digest()?,
        origin: sources.origin.clone(),
        events: sources.events[..end].to_vec(),
        controller,
        proof: control,
    };
    let authorization = member
        .authorizations
        .get(&c.enrollment.operation_key)
        .ok_or_else(refuse)?
        .clone();
    Proof::from_sources(c, acceptance, authorization, sources.clone())
}
pub(crate) fn has_member_references(member: &crate::family_saga::MemberSnapshot) -> bool {
    member.executions.values().any(|execution| {
        execution
            .lineage
            .outcomes
            .evidence
            .values()
            .any(|value| value["kind"] == REFERENCE_KIND || value["profile"] == REFERENCE_PROFILE)
    })
}
pub(crate) fn verify_member_references(
    c: &Context,
    member: &crate::family_saga::MemberSnapshot,
    sources: &Sources,
) -> Result<()> {
    let execution = member
        .executions
        .get(&c.enrollment.operation_key)
        .ok_or_else(refuse)?;
    let references = execution
        .lineage
        .outcomes
        .evidence
        .values()
        .filter(|value| value["kind"] == REFERENCE_KIND || value["profile"] == REFERENCE_PROFILE)
        .collect::<Vec<_>>();
    if references.is_empty() {
        return Ok(());
    }
    let proof = reconstruct(c, member, sources)?;
    for value in references {
        let reference: Reference = serde_json::from_value(value.clone())?;
        reference.verify(c, &proof)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kube_drain_journal::State, kube_drain_proof::Signed, managed_drain_audit as audit,
        managed_drain_evidence::ControlKind, managed_drain_store::Material,
    };
    fn fixture() -> (Context, Proof, Sources) {
        let bundle: audit::Bundle = serde_json::from_str(include_str!("../../../results/verification/rfc-m8-managed-controller-2026-10-27/native-artifacts/managed-controller-completed/bundle.json")).unwrap();
        let trust: audit::Trust = serde_json::from_str(include_str!("../../../results/verification/rfc-m8-managed-controller-2026-10-27/native-artifacts/managed-controller-completed/trust.json")).unwrap();
        bundle.verify(&trust).unwrap();
        let context = Context::from_selection(trust.selection.clone()).unwrap();
        let Material::Aggregate(aggregate) =
            &bundle.evidence.materials[&bundle.evidence.current_aggregate_digest]
        else {
            panic!("aggregate")
        };
        let member = &aggregate.evidence.current.snapshot.members[&context.selection.child_id];
        let current = member
            .physical
            .as_ref()
            .unwrap()
            .controller
            .as_ref()
            .unwrap();
        let sources = bundle.evidence.source;
        let proof = sources
            .controls
            .values()
            .find(|p| p.body.kind == ControlKind::Accepted)
            .unwrap()
            .clone();
        let header = &proof.body.mechanical_header;
        let controller = Signed {
            profile: header.profile.clone(),
            kind: header.kind.clone(),
            signer_id: header.signer_id.clone(),
            key_id: header.key_id.clone(),
            signature: header.signature.clone(),
            body: State {
                accepted: current.body.accepted.clone(),
                steps: vec![],
                closed: None,
            },
        };
        let accepted_key = proof.digest().unwrap();
        let end = sources.events.iter().position(|event| matches!(&event.change,Change::ControllerAccepted {proof_digest} if proof_digest == &accepted_key)).unwrap()+1;
        let acceptance = Acceptance {
            profile: crate::managed_drain::PROFILE.into(),
            enrollment_digest: context.enrollment.digest().unwrap(),
            origin: sources.origin.clone(),
            events: sources.events[..end].to_vec(),
            controller,
            proof,
        };
        let authorization = member.authorizations[&context.enrollment.operation_key].clone();
        let p = Proof::from_sources(&context, acceptance, authorization, sources.clone()).unwrap();
        (context, p, sources)
    }
    #[test]
    fn complete_acceptance_prefix_replays_prior_actual_sources_without_claiming_physical_effect() {
        let (c, p, sources) = fixture();
        assert_eq!(sources.claims.len(), 4);
        assert_eq!(p.sources.claims.len(), 1);
        let raw = canonical(&json!(p)).unwrap();
        let verified = Proof::decode(&raw).unwrap().verify(&c).unwrap();
        assert_eq!(verified["complete_acceptance_sources"], true);
        assert_eq!(verified["native_history_verified"], false);
        assert_eq!(verified["execution_authority"], false);
        assert_eq!(verified["physical_status"], "unresolved");
    }
    #[test]
    fn acceptance_prefix_refuses_missing_sources_and_wrong_historical_scope() {
        let (c, p, sources) = fixture();
        for omission in [
            "claim",
            "control",
            "preflight",
            "source-signature",
            "authorization",
            "events",
            "later-claim",
            "profile",
        ] {
            let mut bad = p.clone();
            match omission {
                "claim" => bad.sources.claims.clear(),
                "control" => bad.sources.controls.clear(),
                "preflight" => bad.sources.preflight_claims.clear(),
                "source-signature" => bad.sources.admission.statement.signature = "invalid".into(),
                "authorization" => bad.authorization.packet.witnesses.clear(),
                "events" => {
                    bad.sources.events.remove(1);
                }
                "later-claim" => bad.sources.claims = sources.claims.clone(),
                _ => bad.profile = crate::managed_drain::PROFILE.into(),
            }
            assert!(bad.verify(&c).is_err(), "must refuse {omission}");
        }
        let mut bad = json!(p);
        bad["unknown"] = json!(true);
        assert!(Proof::decode(&canonical(&bad).unwrap()).is_err());
        assert!(Proof::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
    #[test]
    fn target_acceptance_cannot_select_its_own_prefix_or_enrollment() {
        let (c, p, sources) = fixture();
        let mut accepted = p.acceptance.clone();
        accepted.events.swap(0, 1);
        assert!(
            Proof::from_sources(&c, accepted, p.authorization.clone(), sources.clone()).is_err()
        );
        let mut accepted = p.acceptance.clone();
        accepted.origin.original.attempt_id = "other-attempt".into();
        assert!(Proof::from_sources(&c, accepted, p.authorization.clone(), sources).is_err());
        let mut bad = p;
        bad.enrollment_digest = "a".repeat(64);
        assert!(bad.verify(&c).is_err());
    }
    #[test]
    fn historical_replay_reuse_requires_every_proof_body_and_protected_pin() {
        let (c, p, _) = fixture();
        p.verify_historical_cached(&c).unwrap();
        p.verify_historical_cached(&c).unwrap();
        let mut forged = p.clone();
        forged.sources.admission.statement.signature = "invalid".into();
        assert!(forged.verify_historical_cached(&c).is_err());
        let mut missing = p.clone();
        missing.authorization.packet.witnesses.clear();
        assert!(missing.verify_historical_cached(&c).is_err());
        let mut wrong = c.clone();
        wrong.enrollment.target_scope = "other:scope".into();
        assert!(p.verify_historical_cached(&wrong).is_err());
        let mut wrong = c.clone();
        wrong.selection.child_id = "child-0".into();
        assert!(p.verify_historical_cached(&wrong).is_err());
        let mut wrong = c;
        wrong.physical.controller.keys.clear();
        assert!(p.verify_historical_cached(&wrong).is_err());
    }
    #[test]
    fn native_reference_requires_all_original_bodies_and_exact_complete_proof_digest() {
        let (c, p, sources) = fixture();
        let bundle: audit::Bundle=serde_json::from_str(include_str!("../../../results/verification/rfc-m8-managed-controller-2026-10-27/native-artifacts/managed-controller-completed/bundle.json")).unwrap();
        let Material::Aggregate(aggregate) =
            &bundle.evidence.materials[&bundle.evidence.current_aggregate_digest]
        else {
            panic!("aggregate")
        };
        let mut member = aggregate.evidence.current.snapshot.members[&c.selection.child_id].clone();
        let rebuilt = reconstruct(&c, &member, &sources).unwrap();
        assert_eq!(
            canonical(&json!(rebuilt)).unwrap(),
            canonical(&json!(p)).unwrap()
        );
        let reference = json!(Reference::from_proof(&p).unwrap());
        let key = crate::contracts::digest("outcome-evidence", &reference).unwrap();
        member
            .executions
            .get_mut(&c.enrollment.operation_key)
            .unwrap()
            .lineage
            .outcomes
            .evidence
            .insert(key.clone(), reference.clone());
        verify_member_references(&c, &member, &sources).unwrap();
        for case in [
            "missing-claim",
            "missing-control",
            "missing-authorization",
            "wrong-digest",
            "wrong-profile",
            "unknown-field",
        ] {
            let mut m = member.clone();
            let mut s = sources.clone();
            let value = m
                .executions
                .get_mut(&c.enrollment.operation_key)
                .unwrap()
                .lineage
                .outcomes
                .evidence
                .get_mut(&key)
                .unwrap();
            match case {
                "missing-claim" => s.claims.clear(),
                "missing-control" => s.controls.clear(),
                "missing-authorization" => m
                    .authorizations
                    .get_mut(&c.enrollment.operation_key)
                    .unwrap()
                    .packet
                    .witnesses
                    .clear(),
                "wrong-digest" => value["proof_digest"] = json!("a".repeat(64)),
                "wrong-profile" => value["profile"] = json!(PROFILE),
                "unknown-field" => value["omitted_body_is_trusted"] = json!(true),
                _ => unreachable!(),
            }
            assert!(verify_member_references(&c, &m, &s).is_err(), "{case}");
        }
    }
}
