//! Operator-owned registration and key files for the bounded control service.
//! Loading a snapshot never publishes or acknowledges installed authority state.
use crate::{
    admission::{AdmissionTrust, EvidencePredicate, EvidenceRequirement, RecordReference},
    auth::DualAuthenticator,
    clock::SystemClock,
    config::{key, read_secret},
    contracts::{GrantVerifier, Subject, strict_value},
    control::{ControlPermissions, ControlService},
    endpoint::EndpointPolicy,
    error::{Error, Result},
    issuance::{GrantAuthority, IssuanceVerifier, RequiredObligation},
    ledger::EtcdLedger,
    policy::{AdmissionController, CedarAdmissionPolicy, CedarPolicyDefinition},
    schema::ClosedObjectSchema,
    tls,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRegistration {
    pub obligation: RequiredObligation,
    pub provider_id: String,
    pub provider_version: String,
    pub keys: BTreeMap<String, String>,
    pub question: RecordReference,
    pub result_schema_ref: RecordReference,
    pub result_schema: Value,
    pub max_age_ms: i64,
    pub predicates: Vec<EvidencePredicate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRegistration {
    pub id: String,
    pub epoch: u64,
    pub cedar: String,
    pub max_certificate_lifetime_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    #[serde(default)]
    pub shared_auth: Option<crate::shared_auth::SharedAuthConfig>,
    #[serde(default)]
    pub restore_gate: Option<crate::restore::RestoreGateConfig>,
    #[serde(default)]
    pub require_control: bool,
    pub listen: std::net::SocketAddr,
    pub admission_url: String,
    pub issuance_url: String,
    #[serde(default)]
    pub status_url: Option<String>,
    #[serde(default)]
    pub status_scope: Option<String>,
    pub delegation_audience: String,
    pub gateway_audience: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub workload_ca: PathBuf,
    pub oidc_issuer: String,
    pub oidc_public_key_base64: String,
    pub etcd_endpoint: String,
    pub etcd_prefix: String,
    pub etcd_ca: PathBuf,
    pub etcd_certificate: PathBuf,
    pub etcd_private_key: PathBuf,
    pub etcd_token_file: PathBuf,
    pub admission_key_id: String,
    pub admission_signing_key_file: PathBuf,
    pub issuer_key_id: String,
    pub issuer_signing_key_file: PathBuf,
    pub tenant: String,
    pub workload_id: String,
    pub subjects: Vec<Subject>,
    pub admission_scope: String,
    pub issuance_scope: String,
    pub action_scope: String,
    pub proposal_keys: BTreeMap<String, String>,
    pub registry_keys: BTreeMap<String, String>,
    pub manifest_keys: BTreeMap<String, String>,
    pub descriptor_digest: String,
    pub ownership_epoch: u64,
    pub max_proposal_age_ms: i64,
    pub policy: PolicyRegistration,
    pub evidence: BTreeMap<String, EvidenceRegistration>,
}

pub(crate) fn keys(raw: &BTreeMap<String, String>) -> Result<BTreeMap<String, VerifyingKey>> {
    if raw.is_empty() {
        return Err(Error::Invalid(
            "empty authority role key registration".into(),
        ));
    }
    raw.iter()
        .map(|(id, k)| {
            if id.is_empty() {
                return Err(Error::Invalid("empty authority key ID".into()));
            }
            Ok((
                id.clone(),
                VerifyingKey::from_bytes(&key(k)?)
                    .map_err(|_| Error::Invalid("invalid role public key".into()))?,
            ))
        })
        .collect()
}

impl ControlConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("control configuration exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }

    pub fn registration(&self) -> Result<(AdmissionTrust, CedarPolicyDefinition)> {
        if self.tenant.is_empty()
            || self.workload_id.is_empty()
            || self.action_scope.is_empty()
            || self.evidence.is_empty()
            || self.evidence.len() > 64
            || self.ownership_epoch == 0
            || self.max_proposal_age_ms <= 0
            || !crate::grant_reference::valid_reference(&self.descriptor_digest)
        {
            return Err(Error::Invalid("incomplete leaf registration".into()));
        }
        EndpointPolicy::new(&self.admission_url)?;
        EndpointPolicy::new(&self.issuance_url)?;
        EndpointPolicy::new(&self.gateway_audience)?;
        let endpoint = crate::grant_reference::fixed_https(&self.etcd_endpoint)?;
        if endpoint.path() != "/" {
            return Err(Error::Invalid("etcd must be a HTTPS origin".into()));
        }
        let evidence = self
            .evidence
            .iter()
            .map(|(id, r)| {
                ClosedObjectSchema::new(&r.result_schema)?;
                if r.predicates.is_empty()
                    || r.max_age_ms <= 0
                    || r.provider_id.is_empty()
                    || r.provider_version.is_empty()
                    || !matches!(r.obligation.stage.as_str(), "static" | "jit")
                {
                    return Err(Error::Invalid("invalid evidence registration".into()));
                }
                Ok((
                    id.clone(),
                    EvidenceRequirement {
                        obligation: r.obligation.clone(),
                        provider_id: r.provider_id.clone(),
                        provider_version: r.provider_version.clone(),
                        keys: keys(&r.keys)?,
                        question: r.question.clone(),
                        result_schema_ref: r.result_schema_ref.clone(),
                        result_schema: r.result_schema.clone(),
                        max_age_ms: r.max_age_ms,
                        predicates: r.predicates.clone(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut trust = AdmissionTrust {
            tenant: self.tenant.clone(),
            proposal_keys: keys(&self.proposal_keys)?,
            proposal_workload_id: self.workload_id.clone(),
            registry_keys: keys(&self.registry_keys)?,
            manifest_keys: keys(&self.manifest_keys)?,
            descriptor_digest: self.descriptor_digest.clone(),
            ownership_epoch: self.ownership_epoch,
            policy: crate::contracts::Policy {
                id: self.policy.id.clone(),
                epoch: self.policy.epoch,
                digest: String::new(),
            },
            obligation_manifest_digest: String::new(),
            required_scope: self.action_scope.clone(),
            max_proposal_age_ms: self.max_proposal_age_ms,
            evidence,
        };
        trust.obligation_manifest_digest = trust.registered_obligations_digest()?;
        trust.validate_configuration()?;
        let definition = CedarPolicyDefinition {
            tenant: self.tenant.clone(),
            policy_id: self.policy.id.clone(),
            cedar: self.policy.cedar.clone(),
            obligation_manifest_digest: trust.obligation_manifest_digest.clone(),
            max_certificate_lifetime_ms: self.policy.max_certificate_lifetime_ms,
        };
        trust.policy = definition.reference(self.policy.epoch)?;
        // Pin helpers never accept an invalid policy as installation material.
        CedarAdmissionPolicy::new(definition.clone(), trust.policy.clone())?;
        Ok((trust, definition))
    }

    pub async fn service(&self) -> Result<Arc<ControlService>> {
        let (trust, definition) = self.registration()?;
        let admission_key =
            SigningKey::from_bytes(&key(&read_secret(&self.admission_signing_key_file).await?)?);
        let issuer_key =
            SigningKey::from_bytes(&key(&read_secret(&self.issuer_signing_key_file).await?)?);
        let controller = AdmissionController::new(
            CedarAdmissionPolicy::new(definition, trust.policy.clone())?,
            self.admission_key_id.clone(),
            admission_key.clone(),
        )?;
        let trust_pin = crate::governance::trust_digest(
            &trust,
            &BTreeMap::from([(self.admission_key_id.clone(), admission_key.verifying_key())]),
            &BTreeMap::from([(self.issuer_key_id.clone(), issuer_key.verifying_key())]),
        )?;
        let issuer = GrantAuthority::new(
            IssuanceVerifier {
                tenant: trust.tenant.clone(),
                admission_keys: BTreeMap::from([(
                    self.admission_key_id.clone(),
                    admission_key.verifying_key(),
                )]),
                grants: GrantVerifier {
                    keys: BTreeMap::from([(
                        self.issuer_key_id.clone(),
                        issuer_key.verifying_key(),
                    )]),
                    audience: self.gateway_audience.clone(),
                },
            },
            self.issuer_key_id.clone(),
            issuer_key,
        )?;
        let client = tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            Duration::from_secs(5),
        )?;
        let mut ledger = EtcdLedger::new(client, &self.etcd_endpoint, &self.etcd_prefix)?
            .with_auth_token(&read_secret(&self.etcd_token_file).await?)?;
        if self.require_control {
            ledger = ledger.requiring_control(Some(trust_pin));
        }
        if let Some(gate) = &self.restore_gate {
            ledger = gate.attach(ledger).await?;
        }
        let auth = |url: &str| {
            let mut verifier = DualAuthenticator::new(
                &self.oidc_issuer,
                &self.delegation_audience,
                url,
                key(&self.oidc_public_key_base64)?,
            )?;
            if let Some(shared) = &self.shared_auth {
                verifier = verifier.with_shared_replay(ledger.clone(), shared.clone())?;
            }
            Ok::<_, Error>(verifier)
        };
        let mut service = ControlService::new(
            Arc::new(trust),
            controller,
            issuer,
            ledger.clone(),
            Arc::new(SystemClock),
            auth(&self.admission_url)?,
            auth(&self.issuance_url)?,
            ControlPermissions {
                subjects: self.subjects.clone(),
                admission_scope: self.admission_scope.clone(),
                issuance_scope: self.issuance_scope.clone(),
            },
        )?;
        match (&self.status_url, &self.status_scope) {
            (Some(url), Some(scope)) => service = service.with_status(auth(url)?, scope.clone())?,
            (None, None) => (),
            _ => return Err(Error::Invalid("status URL and scope must be paired".into())),
        }
        Ok(Arc::new(service))
    }
}
