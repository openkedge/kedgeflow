//! Read-only physical observer. It holds no Kubernetes mutation credential and
//! does not submit, repeat or renew a controller operation.
use crate::{
    clock::Clock,
    contracts::{GrantVerifier, strict_value},
    error::{Error, Result},
    kube_drain::PROFILE,
    kube_drain_api::Api,
    kube_drain_journal::State,
    kube_drain_proof::{Capture, NoDispatch, Observation, Signed, Trust},
    ledger::{EtcdLedger, get, range_kv, record, value_eq, version_zero},
};
use ed25519_dalek::SigningKey;
use std::sync::Arc;
fn refuse() -> Error {
    Error::Refused("complete original physical observation refused".into())
}
pub struct Observer {
    trust: Trust,
    api: Arc<Api>,
    key_id: String,
    key: SigningKey,
    clock: Arc<dyn Clock>,
}
impl Observer {
    pub fn new(
        trust: Trust,
        api: Arc<Api>,
        key_id: String,
        key: SigningKey,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        trust.validate()?;
        if crate::control_config::keys(&trust.observer.keys)?.get(&key_id)
            != Some(&key.verifying_key())
        {
            return Err(refuse());
        }
        Ok(Self {
            trust,
            api,
            key_id,
            key,
            clock,
        })
    }
    pub fn trust(&self) -> &Trust {
        &self.trust
    }
    pub async fn collect(
        &self,
        l: &EtcdLedger,
        operation: &str,
        epoch: &str,
        grants: &GrantVerifier,
        previous: Option<&Capture>,
    ) -> Result<Capture> {
        if self.trust.operating.is_none() {
            return self
                .collect_inner(l, operation, epoch, grants, previous)
                .await;
        }
        let from = self.clock.now_ms();
        let capture = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.collect_inner(l, operation, epoch, grants, previous),
        )
        .await
        .map_err(|_| refuse())??;
        let until = self.clock.now_ms();
        if until < from || until - from > 10000 {
            return Err(refuse());
        }
        Ok(capture)
    }
    async fn collect_inner(
        &self,
        l: &EtcdLedger,
        operation: &str,
        epoch: &str,
        grants: &GrantVerifier,
        previous: Option<&Capture>,
    ) -> Result<Capture> {
        let base = crate::kube_drain_runtime::base(l, operation);
        let keys = [
            format!("{base}/contract"),
            format!("{base}/state"),
            format!("{base}/gate"),
        ];
        let t = l
            .txn(vec![], keys.iter().map(|k| get(k)).collect(), vec![])
            .await?;
        if !t.succeeded || t.responses.len() != 3 {
            return Err(refuse());
        }
        let values = t
            .responses
            .iter()
            .map(range_kv)
            .collect::<Result<Vec<_>>>()?;
        let expected = record(&self.trust)?;
        if values[0]
            .as_ref()
            .is_none_or(|v| v.value != expected.as_bytes())
        {
            return Err(refuse());
        }
        let mut compare = Vec::new();
        for (k, v) in keys.iter().zip(&values) {
            compare.push(match v {
                Some(v) => value_eq(k, std::str::from_utf8(&v.value).map_err(|_| refuse())?),
                None => version_zero(k),
            });
        }
        let controller = values[1]
            .as_ref()
            .map(|v| -> Result<Signed<State>> {
                if v.value.len() > crate::kube_drain_journal::MAX_STATE {
                    return Err(refuse());
                }
                let s: Signed<State> = serde_json::from_value(strict_value(&v.value)?)?;
                s.verify("controller_state", &self.trust.controller)?;
                let g = grants.verify_retained(s.body.accepted.signed_grant.as_bytes())?;
                if g.digest != s.body.accepted.grant_digest {
                    return Err(refuse());
                }
                s.body.validate(&self.trust.contract, &g.grant)?;
                Ok(s)
            })
            .transpose()?;
        let closed_absence = values[2]
            .as_ref()
            .map(|v| -> Result<Signed<NoDispatch>> {
                if v.value.len() > 16384 {
                    return Err(refuse());
                }
                let g: Signed<NoDispatch> = serde_json::from_value(strict_value(&v.value)?)?;
                g.verify("closed_no_dispatch", &self.trust.controller)?;
                Ok(g)
            })
            .transpose()?;
        let managed = if self.trust.operating.is_some() {
            let store = crate::managed_drain_store::Store::new(l.clone())?;
            let (sources, comparisons) = store.control_capture().await?;
            compare.extend(comparisons);
            Some((store, sources))
        } else {
            None
        };
        if controller.is_some() && closed_absence.is_some() {
            return Err(refuse());
        }
        let control_history = if let Some(state) = &controller {
            let grant = grants
                .verify_retained(state.body.accepted.signed_grant.as_bytes())?
                .grant;
            let observer = crate::control_history::HistoryObserver {
                id: self.trust.observer.id.clone(),
                key_id: self.key_id.clone(),
                key: self.key.clone(),
            };
            Some(Box::new(
                l.export_physical_control_history(
                    &crate::recovery::Candidate {
                        grant,
                        attempt_id: state.body.accepted.attempt_id.clone(),
                    },
                    operation,
                    &observer,
                    self.clock.as_ref(),
                )
                .await?,
            ))
        } else {
            None
        };
        let retained_completion = match previous {
            Some(p) if p.retained_completion.is_some() => p.retained_completion.clone(),
            Some(p) if p.controller.is_some() && p.observation.body.inventory.is_some() => {
                let controller = p.controller.as_ref().ok_or_else(refuse)?;
                if controller.body.physical_status(
                    &self.trust.contract,
                    p.observation.body.inventory.as_ref().ok_or_else(refuse)?,
                )? == "observed_completed"
                {
                    Some(Box::new(crate::kube_drain_proof::Completion {
                        controller: controller.clone(),
                        observation: p.observation.clone(),
                    }))
                } else {
                    None
                }
            }
            _ => None,
        };
        let inventory = if closed_absence.is_some()
            || controller.as_ref().is_some_and(|s| s.body.closed.is_some())
        {
            None
        } else {
            Some(self.api.inventory(&self.trust.contract).await?)
        };
        let observed_at = self.clock.now_ms();
        if !l.txn(compare, vec![], vec![]).await?.succeeded {
            return Err(refuse());
        }
        let managed = match managed {
            Some((store, Some(sources))) => {
                Some(Box::new(crate::managed_drain_capture::NativeCapture::sign(
                    sources,
                    &store.context,
                    controller.as_ref(),
                    closed_absence.as_ref(),
                    epoch,
                    observed_at,
                    &self.key_id,
                    &self.key,
                )?))
            }
            _ => None,
        };
        let observation = Signed::sign(
            "physical_observation",
            Observation {
                profile: PROFILE.into(),
                contract_digest: self.trust.contract.digest()?,
                operation_key: operation.into(),
                controller_digest: controller.as_ref().map(Signed::digest).transpose()?,
                gate_digest: closed_absence.as_ref().map(Signed::digest).transpose()?,
                observed_at,
                native_epoch: epoch.into(),
                inventory,
            },
            &self.trust.observer,
            &self.key_id,
            &self.key,
        )?;
        let capture = Capture {
            controller,
            closed_absence,
            observation,
            control_history,
            retained_completion,
            managed,
        };
        capture.verify_sources(&self.trust, operation, observed_at)?;
        Ok(capture)
    }
}
