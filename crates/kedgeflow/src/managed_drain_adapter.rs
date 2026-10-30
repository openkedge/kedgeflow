//! Named managed adapter with independently selected native acceptance sources.
use crate::{
    adapter::{AdapterResult, ResourceAdapter},
    auth::Identity,
    broker::TargetCredential,
    clock::Clock,
    contracts::{GrantVerifier, strict_value},
    error::{Error, Result},
    gateway::{Request, VerifiedCall},
    grant_reference::{bounded_response, fixed_https},
    managed_drain::{ACTION, PROFILE, VERSION},
    managed_drain_acceptance::Proof,
    managed_drain_evidence::Acceptance,
    managed_drain_store::{Context, Store},
    target_token::{TargetTokenVerifier, TokenBinding},
    tls::PinnedClient,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

fn refuse() -> Error {
    Error::Refused("explicit managed drain adapter refused".into())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub selection: crate::family::Selection,
    pub token_issuer: String,
    pub target_keys: BTreeMap<String, String>,
    pub gateway_workload: String,
}
impl Config {
    pub fn validate(&self, grants: &GrantVerifier) -> Result<()> {
        let c = Context::from_selection(self.selection.clone())?;
        let e = &c.enrollment;
        let native = self
            .selection
            .registration
            .composition
            .as_ref()
            .ok_or_else(refuse)?
            .node(&self.selection.child_id)?
            .forward()?;
        if self.profile != PROFILE
            || native.lineage.grants.keys != grants.keys
            || native.lineage.grants.audience != grants.audience
            || !crate::auth::valid_spiffe_id(&self.gateway_workload)
            || [
                &e.controller_workload,
                &e.supervisor_workload,
                &e.evidence_workload,
            ]
            .contains(&&self.gateway_workload)
            || !c.physical.control()?.historical.iter().any(|h| {
                h.registration.scope == native.registration.scope
                    && h.registration.acknowledger.workload_id == self.gateway_workload
            })
        {
            return Err(refuse());
        }
        let target = crate::control_config::keys(&self.target_keys)?;
        TargetTokenVerifier::new(self.token_issuer.clone(), target.clone())?;
        for keys in [
            &c.physical.controller.keys,
            &c.physical.observer.keys,
            &e.operating_observer.keys,
            &e.policy.incident_sink.acknowledgement_keys,
            &e.current_sql.provider.keys,
            &e.current_sql.storage.owner.keys,
        ] {
            if crate::control_config::keys(keys)?
                .values()
                .any(|key| target.values().any(|k| k == key))
            {
                return Err(refuse());
            }
        }
        if target
            .values()
            .any(|key| grants.keys.values().any(|k| k == key))
        {
            return Err(refuse());
        }
        Ok(())
    }
}
pub struct Adapter {
    config: Config,
    grants: GrantVerifier,
    tokens: TargetTokenVerifier,
    endpoint: reqwest::Url,
    client: PinnedClient,
    store: Store,
    clock: Arc<dyn Clock>,
}
impl Adapter {
    pub fn new(
        endpoint: &str,
        client: PinnedClient,
        config: Config,
        grants: GrantVerifier,
        ledger: crate::ledger::EtcdLedger,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        config.validate(&grants)?;
        let store = Store::new(ledger)?;
        if store.context.selection != config.selection
            || endpoint != store.context.enrollment.target_audience
        {
            return Err(refuse());
        }
        let tokens = TargetTokenVerifier::new(
            config.token_issuer.clone(),
            crate::control_config::keys(&config.target_keys)?,
        )?;
        Ok(Self {
            config,
            grants,
            tokens,
            endpoint: fixed_https(endpoint)?,
            client,
            store,
            clock,
        })
    }
    async fn proof(&self, acceptance: Acceptance, expires_at: i64) -> Result<Proof> {
        let remaining = expires_at
            .checked_sub(self.clock.now_ms())
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::Unknown("original managed proof budget exhausted".into()))?;
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(remaining as u64)
                .min(std::time::Duration::from_secs(5));
        for read in 0..2 {
            match tokio::time::timeout_at(deadline, self.proof_snapshot(acceptance.clone())).await {
                Ok(Err(Error::Unavailable(message)))
                    if read == 0
                        && [
                            "managed acceptance native read comparison raced",
                            "invalid guarded proof read",
                            "reservation read epoch raced",
                            "managed read epoch raced",
                            "preflight history read epoch raced",
                            "native guarded read epoch raced",
                        ]
                        .contains(&message.as_str())
                        && self.clock.now_ms() < expires_at =>
                {
                    eprintln!(
                        "managed original acceptance proof read raced: {message}; recapturing once without another execution request"
                    );
                }
                Ok(result) => return result,
                Err(_) => {
                    return Err(Error::Unknown(
                        "original managed proof budget exhausted".into(),
                    ));
                }
            }
        }
        Err(Error::Unknown(
            "original managed proof read did not settle".into(),
        ))
    }
    async fn proof_snapshot(&self, acceptance: Acceptance) -> Result<Proof> {
        // Independent read-only captures; full correlation verification and the
        // combined final native CAS still precede every accepted proof reply.
        let (authorization, (sources, mut compare)) = tokio::try_join!(
            self.store
                .ledger
                .export_authorization(&self.store.context.enrollment.operation_key),
            self.store.control_capture(),
        )?;
        compare.extend(self.store.ledger.authorization_comparisons(
            &self.store.context.enrollment.operation_key,
            &authorization,
        )?);
        let context = self.store.context.clone();
        let sources = sources.ok_or_else(refuse)?;
        let base = self.store.context.base();
        let last = sources.preflight_claims.last().ok_or_else(refuse)?;
        compare.push(crate::ledger::value_eq(
            &format!("{base}/preflight/head"),
            &crate::ledger::record(last)?,
        ));
        for claim in &sources.preflight_claims {
            compare.push(crate::ledger::value_eq(
                &format!("{base}/preflight/events/{:04}", claim.sequence),
                &crate::ledger::record(claim)?,
            ));
        }
        let proof = tokio::task::spawn_blocking(move || {
            Proof::from_sources(&context, acceptance, authorization, sources)
        })
        .await
        .map_err(|_| {
            Error::Unavailable("managed acceptance verification worker failed".into())
        })??;
        if !self
            .store
            .ledger
            .txn(compare, vec![], vec![])
            .await?
            .succeeded
        {
            return Err(Error::Unavailable(
                "managed acceptance native read comparison raced".into(),
            ));
        }
        Ok(proof)
    }
}
#[async_trait]
impl ResourceAdapter for Adapter {
    async fn prepare(&self) -> Result<()> {
        // Replay the installed complete historical inventory before short-lived
        // execution begins. Existing memoization keys every public pin and all
        // actual source bytes. Every execution still rereads the sources and
        // carries its fresh authority/epoch comparisons into the final CAS.
        crate::family_saga_runtime::prepare_history(
            &self.store.ledger,
            &self.store.context.selection.registration,
        )
        .await
    }
    fn managed_drain_context(&self) -> Option<&Context> {
        Some(&self.store.context)
    }
    fn outcome_evidence(&self, result: &AdapterResult) -> Result<Value> {
        let proof: Proof = serde_json::from_value(
            result.result["structuredContent"]["kedgeflow_managed_drain_acceptance"].clone(),
        )?;
        if result.status != "committed"
            || proof.enrollment_digest != self.store.context.enrollment.digest()?
        {
            return Err(refuse());
        }
        Ok(json!(
            crate::managed_drain_acceptance::Reference::from_proof(&proof)?
        ))
    }
    async fn dispatch(
        &self,
        call: &VerifiedCall,
        credential: &TargetCredential,
    ) -> Result<AdapterResult> {
        let now = self.clock.now_ms();
        let v = self.grants.verify(&call.signed_grant, now)?;
        let c = &self.store.context;
        let e = &c.enrollment;
        let contract = &c.physical.contract;
        if v.grant != call.grant
            || v.digest != call.grant_digest
            || credential.audience != e.target_audience
            || now >= credential.expires_at_ms
            || call.grant.resources != [contract.resource()?]
            || call.grant.action.id != ACTION
            || call.grant.action.version != VERSION
            || call.grant.adapter_contract != crate::managed_drain::adapter_contract()
            || call.request.params.arguments
                != json!({"node":contract.node.name,"expected_version":contract.generation})
        {
            return Err(refuse());
        }
        self.tokens.verify(
            &credential.token,
            &TokenBinding {
                grant_digest: call.grant_digest.clone(),
                root_id: call.grant.root_id.clone(),
                attempt_id: call.attempt_id.clone(),
                gateway_workload: self.config.gateway_workload.clone(),
                audience: e.target_audience.clone(),
                scope: e.target_scope.clone(),
                max_expires_at: call.grant.expires_at,
            },
            now,
        )?;
        let response = self
            .client
            .client()
            .post(self.endpoint.clone())
            .bearer_auth(&credential.token)
            .json(&crate::kube_drain_http::Accept {
                profile: PROFILE.into(),
                operation: "accept".into(),
                signed_grant: URL_SAFE_NO_PAD.encode(&call.signed_grant),
                attempt_id: call.attempt_id.clone(),
                parameters: call.request.params.arguments.clone(),
            })
            .send()
            .await
            .map_err(|_| Error::Unknown("original managed acceptance reply unavailable".into()))?;
        if response.status() != reqwest::StatusCode::OK || response.url() != &self.endpoint {
            return Err(Error::Unknown(format!(
                "original managed acceptance ambiguous (HTTP {})",
                response.status()
            )));
        }
        let a: Acceptance = serde_json::from_value(strict_value(
            &bounded_response(response, crate::managed_drain_acceptance::MAX_BYTES).await?,
        )?)?;
        if a.origin.original.grant_digest != call.grant_digest
            || a.origin.original.attempt_id != call.attempt_id
            || a.origin.signed_grant.as_bytes() != call.signed_grant.as_slice()
        {
            return Err(refuse());
        }
        let proof = self.proof(a, call.grant.expires_at).await?;
        Ok(AdapterResult {
            status: "committed".into(),
            result: json!({"resultType":"complete","isError":false,"content":[],"structuredContent":{
                "kedgeflow_terminal_receipt":{"attempt_id":call.attempt_id,"grant_digest":call.grant_digest,
                    "resource":call.grant.resources[0],"fence":call.grant.fence,"status":"committed","post_version":contract.generation},
                "kedgeflow_drain_acceptance":proof.acceptance.controller,
                "kedgeflow_managed_drain_acceptance":proof,
                "physical_status":"unresolved","commit_point":"controller_acceptance"}}),
        })
    }
    async fn read(&self, _: &Request, _: &Identity) -> Result<Value> {
        Err(refuse())
    }
}
