//! Bounded memoization of verified historical bytes. Callers include all public
//! pins and actual stored bytes, and still retain current values in final CAS.
//! This never caches a live authority decision, clock result or absent record.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub(crate) struct ByteCache<T> {
    entries: BTreeMap<String, (usize, T)>,
    bytes: usize,
    max_entries: usize,
}
impl<T: Clone> ByteCache<T> {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            bytes: 0,
            max_entries,
        }
    }
    pub(crate) fn get(&self, key: &str) -> Option<T> {
        self.entries.get(key).map(|(_, v)| v.clone())
    }
    pub(crate) fn insert(&mut self, key: String, weight: usize, value: T) {
        const MAX_BYTES: usize = 16 << 20;
        if weight > MAX_BYTES || self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= self.max_entries
            || self.bytes.saturating_add(weight) > MAX_BYTES
        {
            if let Some((_, (n, _))) = self.entries.pop_first() {
                self.bytes -= n;
            } else {
                break;
            }
        }
        self.bytes += weight;
        self.entries.insert(key, (weight, value));
    }
}
pub(crate) fn key(domain: &str, parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in std::iter::once(domain.as_bytes()).chain(parts.iter().copied()) {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    hex::encode(h.finalize())
}

/// Complete public historical pins. Exhaustive destructuring makes a newly
/// added trust field a compile error here instead of silently omitting it from
/// the cache identity. This contains no live observation or private key.
pub(crate) fn trust_bytes(t: &crate::reserved_lineage::Trust) -> crate::error::Result<Vec<u8>> {
    use crate::{
        admission::{AdmissionTrust, EvidenceRequirement},
        contracts::{GrantVerifier, canonical},
        lineage::LineageTrust,
        reserved_lineage::Trust,
    };
    use serde_json::json;
    let Trust {
        registration,
        namespace,
        observer_id,
        observer_keys,
        lineage,
    } = t;
    let LineageTrust {
        admission,
        policy,
        subjects,
        delegation_audience,
        admission_keys,
        grants,
        outcome_keys,
        source_id,
    } = lineage;
    let AdmissionTrust {
        inverse_contract,
        leases,
        tenant,
        proposal_keys,
        proposal_workload_id,
        registry_keys,
        manifest_keys,
        descriptor_digest,
        ownership_epoch,
        policy: admission_policy,
        obligation_manifest_digest,
        required_scope,
        max_proposal_age_ms,
        evidence,
    } = admission;
    let GrantVerifier {
        keys: grant_keys,
        audience,
    } = grants;
    let keys = |m: &BTreeMap<String, ed25519_dalek::VerifyingKey>| {
        m.iter()
            .map(|(id, k)| (id.clone(), hex::encode(k.as_bytes())))
            .collect::<BTreeMap<_, _>>()
    };
    let evidence=evidence.iter().map(|(id,e)| {
        let EvidenceRequirement {review,obligation,provider_id,provider_version,keys:provider_keys,question,result_schema_ref,result_schema,max_age_ms,predicates}=e;
        (id.clone(),json!({"review":review,"obligation":obligation,"provider_id":provider_id,"provider_version":provider_version,"keys":keys(provider_keys),"question":question,"result_schema_ref":result_schema_ref,"result_schema":result_schema,"max_age_ms":max_age_ms,"predicates":predicates}))
    }).collect::<BTreeMap<_,_>>();
    canonical(
        &json!({"registration":registration,"namespace":namespace,"observer_id":observer_id,"observer_keys":keys(observer_keys),"lineage":{"policy":policy,"subjects":subjects,"delegation_audience":delegation_audience,"admission_keys":keys(admission_keys),"grant_keys":keys(grant_keys),"gateway_audience":audience,"outcome_keys":keys(outcome_keys),"source_id":source_id,"admission":{"inverse_contract":inverse_contract,"leases":leases.as_ref().map(crate::leases::LeaseTrust::binding),"tenant":tenant,"proposal_keys":keys(proposal_keys),"proposal_workload_id":proposal_workload_id,"registry_keys":keys(registry_keys),"manifest_keys":keys(manifest_keys),"descriptor_digest":descriptor_digest,"ownership_epoch":ownership_epoch,"policy":admission_policy,"obligation_manifest_digest":obligation_manifest_digest,"required_scope":required_scope,"max_proposal_age_ms":max_proposal_age_ms,"evidence":evidence}}}),
    )
}
