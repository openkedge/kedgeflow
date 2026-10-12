//! Fixed native collector client with fresh DPoP and exact signed-ack verification.
use crate::{
    clock::Clock,
    contracts::{canonical, digest},
    error::{Error, Result},
    grant_reference::{bounded_response, fixed_https},
    outcome_report::{Acknowledgement, PROFILE, validate, verify_ack},
    outcome_report_service::ReporterTrust,
    tls::PinnedClient,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub struct CollectorTrust {
    pub reporter: ReporterTrust,
    pub collector_id: String,
    pub collector_url: String,
    pub acknowledgement_keys: BTreeMap<String, VerifyingKey>,
}
#[derive(Clone, Serialize)]
pub struct DeliveryReceipt {
    pub signed_grant: String,
    pub signed_receipt: String,
    pub evidence: Value,
}
pub struct OutcomeReportClient {
    transport: PinnedClient,
    trust: CollectorTrust,
    token: String,
    proof_key: SigningKey,
    clock: Arc<dyn Clock>,
}
impl OutcomeReportClient {
    pub(crate) fn validate_worker(&self, worker: &crate::recovery::RecoveryWorker) -> Result<()> {
        worker.validate_reporter(&self.trust.reporter)
    }
    pub(crate) fn allows_candidate(&self, candidate: &crate::recovery::Candidate) -> bool {
        candidate.grant.conflict_domain == self.trust.reporter.conflict_domain
    }
    pub(crate) fn expected(&self, receipt: &DeliveryReceipt) -> Result<Acknowledgement> {
        let (_, envelope) = self
            .trust
            .reporter
            .receipt(&receipt.signed_grant, &receipt.signed_receipt)?;
        let expected = Acknowledgement::expected(
            &envelope,
            &self.trust.collector_id,
            &self.trust.collector_url,
            &self.trust.reporter.tenant,
        )?;
        if digest("outcome-evidence", &receipt.evidence)? != expected.evidence_digest {
            return Err(Error::Invalid("delivery evidence mismatch".into()));
        }
        Ok(expected)
    }
    pub(crate) fn verify_progress(&self, raw: &str, expected: &Acknowledgement) -> Result<()> {
        verify_ack(raw, &self.trust.acknowledgement_keys, expected)?;
        Ok(())
    }
    pub(crate) fn verify_bundle(&self, bundle: &crate::recovery::OutcomeBundle) -> Result<()> {
        if canonical(&serde_json::to_value(bundle)?)?.len() > 16 << 20 {
            return Err(Error::Invalid(
                "supervised outcome export exceeds bound".into(),
            ));
        }
        crate::recovery::verify_outcomes(
            bundle,
            &self.trust.reporter.grants,
            &self.trust.reporter.outcome_keys,
            &self.trust.reporter.source_id,
        )?;
        for raw in &bundle.receipts {
            self.trust
                .reporter
                .receipt(&bundle.execution.signed_grant, raw)?;
        }
        Ok(())
    }
    pub(crate) fn tenant(&self) -> &str {
        &self.trust.reporter.tenant
    }
    pub fn new(
        transport: PinnedClient,
        trust: CollectorTrust,
        token: String,
        proof_key: SigningKey,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        trust.reporter.validate()?;
        fixed_https(&trust.collector_url)?;
        if trust.collector_id.is_empty()
            || trust.collector_id.len() > 1024
            || trust.collector_url.len() > 1024
            || token.trim().is_empty()
            || trust.acknowledgement_keys.is_empty()
            || trust.acknowledgement_keys.values().any(|k| {
                trust
                    .reporter
                    .grants
                    .keys
                    .values()
                    .chain(trust.reporter.outcome_keys.values())
                    .any(|v| v == k)
            })
        {
            return Err(Error::Invalid("invalid collector trust".into()));
        }
        Ok(Self {
            transport,
            trust,
            token,
            proof_key,
            clock,
        })
    }
    async fn send(
        &self,
        id: &str,
        receipt: &DeliveryReceipt,
        query: bool,
    ) -> Result<Option<String>> {
        if id.is_empty()
            || id.len() > 1024
            || receipt.signed_grant.len() > 1 << 20
            || receipt.signed_receipt.len() > 1 << 20
        {
            return Err(Error::Invalid("delivery request bound".into()));
        }
        let (c, e) = self
            .trust
            .reporter
            .receipt(&receipt.signed_grant, &receipt.signed_receipt)?;
        let expected = Acknowledgement::expected(
            &e,
            &self.trust.collector_id,
            &self.trust.collector_url,
            &self.trust.reporter.tenant,
        )?;
        if digest("outcome-evidence", &receipt.evidence)? != expected.evidence_digest {
            return Err(Error::Invalid("delivery evidence mismatch".into()));
        }
        let command = if query {
            json!({"profile":PROFILE,"operation":"query","request_id":id,"signed_grant":receipt.signed_grant,"attempt_id":c.attempt_id,"receipt_digest":expected.receipt_digest})
        } else {
            json!({"profile":PROFILE,"operation":"report","request_id":id,"signed_grant":receipt.signed_grant,"signed_receipt":receipt.signed_receipt,"evidence":receipt.evidence})
        };
        validate(&command)?;
        let raw = canonical(&command)?;
        if raw.len() > 2 << 20 {
            return Err(Error::Invalid("delivery body exceeds bound".into()));
        }
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(self.proof_key.verifying_key().as_bytes())});
        let header = json!({"alg":"EdDSA","typ":"dpop+jwt","jwk":jwk});
        let claims = json!({"jti":hex::encode(rand::random::<[u8;32]>()),"htm":"POST","htu":self.trust.collector_url,"iat":self.clock.now_ms()/1000,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(self.token.as_bytes()))});
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(canonical(&header)?),
            URL_SAFE_NO_PAD.encode(canonical(&claims)?)
        );
        let proof = format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(self.proof_key.sign(message.as_bytes()).to_bytes())
        );
        let response = self
            .transport
            .client()
            .post(&self.trust.collector_url)
            .header("authorization", format!("DPoP {}", self.token))
            .header("dpop", proof)
            .header("content-type", "application/json")
            .body(raw)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if response.url().as_str() != self.trust.collector_url || !response.status().is_success() {
            return Err(Error::Unavailable(
                "outcome delivery refused or unavailable; query exact receipt".into(),
            ));
        }
        let raw = bounded_response(response, 1 << 20).await?;
        let reply = crate::contracts::strict_value(&raw)?;
        validate(&reply)?;
        if reply["request_id"] != id {
            return Err(Error::Unavailable(
                "uncorrelated outcome delivery reply".into(),
            ));
        }
        if query
            && reply["operation"] == "missing"
            && reply["receipt_digest"] == expected.receipt_digest
        {
            return Ok(None);
        }
        if reply["operation"] != "acknowledgement" {
            return Err(Error::Unavailable("invalid outcome delivery reply".into()));
        }
        let raw = reply["acknowledgement"]
            .as_str()
            .ok_or_else(|| Error::Invalid("acknowledgement required".into()))?;
        verify_ack(raw, &self.trust.acknowledgement_keys, &expected)?;
        Ok(Some(raw.into()))
    }
    pub async fn deliver(&self, id: &str, receipt: &DeliveryReceipt) -> Result<String> {
        self.send(id, receipt, false)
            .await?
            .ok_or_else(|| Error::Unavailable("missing delivery acknowledgement".into()))
    }
    pub async fn lookup(&self, id: &str, receipt: &DeliveryReceipt) -> Result<Option<String>> {
        self.send(id, receipt, true).await
    }
}
