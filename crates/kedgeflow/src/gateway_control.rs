//! Native gateway installation verification and acknowledgement renewal.
use crate::{
    clock::Clock,
    config::{Config, key, read_secret},
    contracts::GrantVerifier,
    control_config::keys,
    error::{Error, Result},
    governance::{Installation, PROFILE, acknowledge_gateway, verify_control},
    ledger::EtcdLedger,
    tls,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayControlConfig {
    pub control_url: String,
    pub control_ca: PathBuf,
    pub installation_keys: BTreeMap<String, String>,
    pub component_id: String,
    pub workload_id: String,
    pub acknowledgement_key_file: PathBuf,
}
impl Config {
    pub async fn acknowledge_installation(&self, clock: &dyn Clock) -> Result<Duration> {
        self.validate()?;
        let e = self
            .enforcement
            .as_ref()
            .ok_or_else(|| Error::Invalid("gateway acknowledgement is not configured".into()))?;
        let client = |ca: &PathBuf| {
            tls::pinned_http_client(
                ca,
                &self.certificate,
                &self.private_key,
                Duration::from_secs(5),
            )
        };
        let mut ledger = EtcdLedger::new(
            client(&self.etcd_ca)?,
            &self.etcd_endpoints[0],
            &self.etcd_prefix,
        )?;
        if !self.etcd_token_file.as_os_str().is_empty() {
            ledger = ledger.with_auth_token(&read_secret(&self.etcd_token_file).await?)?;
        }
        if let Some(gate) = &self.restore_gate {
            ledger = gate.attach(ledger).await?;
        }
        let domain = &self
            .tools
            .iter()
            .find(|t| !t.read_only)
            .ok_or_else(|| Error::Invalid("controlled tool required".into()))?
            .conflict_domain;
        let (stored, _) = ledger.control_snapshot(domain).await?;
        let stored =
            stored.ok_or_else(|| Error::Refused("gateway control not installed".into()))?;
        let (installation, verified): (Installation, _) =
            verify_control(&stored.record, "install", &keys(&e.installation_keys)?)?;
        let r = &installation.registration;
        if stored.digest != verified.digest
            || r.acknowledger.component_id != e.component_id
            || r.acknowledger.workload_id != e.workload_id
        {
            return Err(Error::Refused(
                "gateway installation enrollment mismatch".into(),
            ));
        }
        let signer =
            SigningKey::from_bytes(&key(&read_secret(&e.acknowledgement_key_file).await?)?);
        let verifier = GrantVerifier {
            keys: BTreeMap::from([(
                self.grant_key_id.clone(),
                VerifyingKey::from_bytes(&key(&self.grant_public_key_base64)?)
                    .map_err(|_| Error::Invalid("gateway issuer key".into()))?,
            )]),
            audience: self.external_url.clone(),
        };
        let record = acknowledge_gateway(
            &installation,
            &stored.digest,
            &self.tools,
            &verifier,
            &e.workload_id,
            &signer,
            clock.now_ms(),
        )?;
        let response=client(&e.control_ca)?.post(&e.control_url).json(&serde_json::json!({"profile":PROFILE,"operation":"apply","request_id":"gateway-installation-ack","record":record})).send().await?;
        if response.url().as_str() != e.control_url || !response.status().is_success() {
            return Err(Error::Unavailable(
                "gateway acknowledgement refused or unavailable".into(),
            ));
        }
        let raw = crate::grant_reference::bounded_response(response, 1 << 20).await?;
        let reply = crate::contracts::strict_value(&raw)?;
        crate::governance::validate_control(&reply)?;
        let (_, ack): (crate::governance::Acknowledgement, _) = verify_control(
            &record,
            "acknowledge",
            &crate::governance::acknowledgement_keys(&r.acknowledger)?,
        )?;
        if reply["profile"] != PROFILE
            || reply["operation"] != "applied"
            || reply["kind"] != "acknowledge"
            || reply["digest"] != ack.digest
            || reply["record"] != record
        {
            return Err(Error::Unavailable(
                "uncorrelated gateway acknowledgement".into(),
            ));
        }
        Ok(Duration::from_millis(
            (r.acknowledger.max_lifetime_ms / 3).clamp(100, 10000) as u64,
        ))
    }
}
