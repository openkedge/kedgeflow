//! Write-ahead restore quarantine. The witness MUST survive authority restores.
//! No automatic pending-reservation repair, rollback, or live migration exists.
use crate::{
    contracts::{digest, strict_value},
    error::{Error, Result},
    ledger::{EtcdLedger, Txn, get, put, range_kv, record, value_eq, version_zero, wire},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub const PROFILE: &str = "KF-RESTORE-GATE-0.1-draft";
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreHead {
    pub profile: String,
    pub namespace: String,
    pub witness: String,
    pub enrollment: String,
    pub sequence: u64,
    pub digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessRecord {
    pub head: RestoreHead,
    pub state: WitnessState,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WitnessState {
    Ready,
    Pending,
}

#[derive(Clone)]
pub struct RestoreGate {
    witness: Arc<EtcdLedger>,
}
pub(crate) fn marker_key(ledger: &EtcdLedger) -> String {
    format!("{}/restore-gate", ledger.prefix)
}
fn quarantine() -> Error {
    Error::Refused("restore quarantine: missing, pending or mismatched witness/head".into())
}
impl RestoreGate {
    /// The caller supplies separately administered storage and credentials.
    /// A different URL does not establish independent backup/failure domains.
    pub fn new(witness: EtcdLedger) -> Result<Self> {
        if witness.restore_gate.is_some() {
            return Err(Error::Invalid(
                "a restore witness cannot itself use this gate".into(),
            ));
        }
        Ok(Self {
            witness: Arc::new(witness),
        })
    }
    fn key(&self) -> String {
        format!("{}/head", self.witness.prefix)
    }
    fn binding(&self) -> String {
        format!("{}{}", self.witness.endpoint, self.witness.prefix)
    }
    async fn read(&self) -> Result<Option<WitnessRecord>> {
        let t = self
            .witness
            .raw_txn(Vec::new(), vec![get(&self.key())], Vec::new())
            .await?;
        range_kv(t.responses.first().ok_or_else(quarantine)?)?
            .map(|kv| {
                if kv.value.len() > 4096 {
                    return Err(quarantine());
                }
                serde_json::from_value(strict_value(&kv.value).map_err(|_| quarantine())?)
                    .map_err(|_| quarantine())
            })
            .transpose()
    }
    async fn change(&self, expected: Option<&WitnessRecord>, next: &WitnessRecord) -> Result<()> {
        let compare = match expected {
            Some(old) => value_eq(&self.key(), &record(old)?),
            None => version_zero(&self.key()),
        };
        let t = self
            .witness
            .raw_txn(
                vec![compare],
                vec![put(&self.key(), &record(next)?)],
                Vec::new(),
            )
            .await?;
        if !t.succeeded {
            return Err(quarantine());
        }
        Ok(())
    }
    fn validate(&self, ledger: &EtcdLedger, head: &RestoreHead) -> Result<()> {
        if head.profile != PROFILE
            || head.namespace != ledger.prefix
            || head.witness != self.binding()
            || head.namespace.len() > 1024
            || head.witness.len() > 2048
            || head.sequence > MAX_SEQUENCE
            || head.enrollment.len() != 64
            || head.digest.len() != 64
            || !head
                .enrollment
                .bytes()
                .chain(head.digest.bytes())
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(quarantine());
        }
        Ok(())
    }
    /// Privileged bootstrap, only for an entirely empty local namespace and an
    /// absent witness. An ambiguous bootstrap leaves pending state quarantined.
    pub async fn enroll_empty(&self, ledger: &EtcdLedger) -> Result<RestoreHead> {
        if ledger.endpoint == self.witness.endpoint {
            return Err(Error::Invalid(
                "witness must use a separate etcd origin".into(),
            ));
        }
        let head = RestoreHead {
            profile: PROFILE.into(),
            namespace: ledger.prefix.clone(),
            witness: self.binding(),
            enrollment: hex::encode(rand::random::<[u8; 32]>()),
            sequence: 0,
            digest: digest(
                "restore-genesis",
                &json!({"namespace":ledger.prefix,"witness":self.binding()}),
            )?,
        };
        self.validate(ledger, &head)?;
        // First reserve remotely; there is no automatic abort, even on failure.
        let pending = WitnessRecord {
            head: head.clone(),
            state: WitnessState::Pending,
        };
        self.change(None, &pending).await?;
        let start = format!("{}/", ledger.prefix);
        let end = format!("{}0", ledger.prefix);
        let t = ledger.raw_txn(vec![json!({"key":wire(&start),"range_end":wire(&end),"target":"VERSION","result":"EQUAL","version":"0"})],
            vec![put(&marker_key(ledger), &record(&head)?)], Vec::new()).await?;
        if !t.succeeded {
            return Err(quarantine());
        }
        self.change(
            Some(&pending),
            &WitnessRecord {
                head: head.clone(),
                state: WitnessState::Ready,
            },
        )
        .await?;
        Ok(head)
    }
    async fn checked(&self, ledger: &EtcdLedger) -> Result<(RestoreHead, WitnessRecord)> {
        let local = ledger
            .raw_txn(Vec::new(), vec![get(&marker_key(ledger))], Vec::new())
            .await?;
        let kv =
            range_kv(local.responses.first().ok_or_else(quarantine)?)?.ok_or_else(quarantine)?;
        if kv.value.len() > 4096 {
            return Err(quarantine());
        }
        let head: RestoreHead =
            serde_json::from_value(strict_value(&kv.value).map_err(|_| quarantine())?)
                .map_err(|_| quarantine())?;
        self.validate(ledger, &head)?;
        let witness = self.read().await?.ok_or_else(quarantine)?;
        if witness.state != WitnessState::Ready || witness.head != head {
            return Err(quarantine());
        }
        Ok((head, witness))
    }
    pub async fn check(&self, ledger: &EtcdLedger) -> Result<RestoreHead> {
        Ok(self.checked(ledger).await?.0)
    }
    pub(crate) async fn transaction(
        &self,
        ledger: &EtcdLedger,
        compare: Vec<Value>,
        success: Vec<Value>,
        failure: Vec<Value>,
    ) -> Result<Txn> {
        let (old, witness) = self.checked(ledger).await?;
        let writes = success
            .iter()
            .chain(&failure)
            .any(|v| v.get("request_range").is_none());
        let request = json!({"compare":compare,"success":success,"failure":failure});
        let mut next = old.clone();
        let pending = if writes {
            next.sequence = old
                .sequence
                .checked_add(1)
                .filter(|s| *s <= MAX_SEQUENCE)
                .ok_or_else(quarantine)?;
            next.digest = digest(
                "restore-transition",
                &json!({"previous":old,"transaction":request,"salt":hex::encode(rand::random::<[u8;32]>())}),
            )?;
            let pending = WitnessRecord {
                head: next.clone(),
                state: WitnessState::Pending,
            };
            self.change(Some(&witness), &pending).await?;
            Some(pending)
        } else {
            None
        };
        let mut ops = vec![json!({"request_txn":request})];
        if writes {
            ops.push(put(&marker_key(ledger), &record(&next)?));
        }
        // Outer CAS guards BOTH branches of the original transaction. A false
        // application comparison still stamps the sequence; a false guard CAS
        // runs no application branch and leaves the remote reservation pending.
        let outer = ledger
            .raw_txn(
                vec![value_eq(&marker_key(ledger), &record(&old)?)],
                ops,
                Vec::new(),
            )
            .await?;
        if !outer.succeeded {
            return Err(quarantine());
        }
        if outer.responses.len() != if writes { 2 } else { 1 }
            || (writes && !outer.responses[1]["response_put"].is_object())
        {
            return Err(quarantine());
        }
        let inner = outer
            .responses
            .first()
            .and_then(|v| v.get("response_txn"))
            .ok_or_else(quarantine)?;
        let succeeded = match inner.get("succeeded") {
            Some(Value::Bool(b)) => *b,
            None => false,
            _ => return Err(quarantine()),
        };
        let responses = match inner.get("responses") {
            Some(Value::Array(a)) => a.clone(),
            None => Vec::new(),
            _ => return Err(quarantine()),
        };
        if let Some(pending) = pending {
            self.change(
                Some(&pending),
                &WitnessRecord {
                    head: next,
                    state: WitnessState::Ready,
                },
            )
            .await?;
        }
        Ok(Txn {
            succeeded,
            responses,
        })
    }
}
impl EtcdLedger {
    pub fn with_restore_gate(mut self, gate: RestoreGate) -> Result<Self> {
        if self.endpoint == gate.witness.endpoint {
            return Err(Error::Invalid(
                "witness must use a separate etcd origin".into(),
            ));
        }
        self.restore_gate = Some(gate);
        Ok(self)
    }
}

/// Optional for legacy fixtures. Once enrolled, omitting this configuration
/// refuses access because the local marker requires the independent witness.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreGateConfig {
    pub endpoint: String,
    pub prefix: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub token_file: PathBuf,
}
impl RestoreGateConfig {
    pub async fn gate(&self) -> Result<RestoreGate> {
        crate::endpoint::EndpointPolicy::new(&format!("{}/", self.endpoint.trim_end_matches('/')))?;
        let client = crate::tls::pinned_http_client(
            &self.ca,
            &self.certificate,
            &self.private_key,
            Duration::from_secs(5),
        )?;
        RestoreGate::new(
            EtcdLedger::new(client, &self.endpoint, &self.prefix)?
                .with_auth_token(&crate::config::read_secret(&self.token_file).await?)?,
        )
    }
    pub async fn attach(&self, ledger: EtcdLedger) -> Result<EtcdLedger> {
        ledger.with_restore_gate(self.gate().await?)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreOperatorConfig {
    etcd_endpoint: String,
    etcd_prefix: String,
    etcd_ca: PathBuf,
    etcd_certificate: PathBuf,
    etcd_private_key: PathBuf,
    etcd_token_file: PathBuf,
    pub restore_gate: RestoreGateConfig,
}
impl RestoreOperatorConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1 << 20 {
            return Err(Error::Invalid("restore configuration exceeds bound".into()));
        }
        Ok(serde_json::from_value(strict_value(raw)?)?)
    }
    pub async fn ledger(&self) -> Result<EtcdLedger> {
        crate::endpoint::EndpointPolicy::new(&format!(
            "{}/",
            self.etcd_endpoint.trim_end_matches('/')
        ))?;
        let client = crate::tls::pinned_http_client(
            &self.etcd_ca,
            &self.etcd_certificate,
            &self.etcd_private_key,
            Duration::from_secs(5),
        )?;
        EtcdLedger::new(client, &self.etcd_endpoint, &self.etcd_prefix)?
            .with_auth_token(&crate::config::read_secret(&self.etcd_token_file).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn draft_witness_schema_is_closed_and_sequence_bounded() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../spec/drafts/restore-gate-v0.1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let h = RestoreHead {
            profile: PROFILE.into(),
            namespace: "/authority".into(),
            witness: "https://witness.example:2379/witness".into(),
            enrollment: "a".repeat(64),
            sequence: MAX_SEQUENCE,
            digest: "b".repeat(64),
        };
        let mut v = serde_json::to_value(WitnessRecord {
            head: h,
            state: WitnessState::Pending,
        })
        .unwrap();
        assert!(validator.is_valid(&v));
        v["head"]["sequence"] = json!(MAX_SEQUENCE + 1);
        assert!(!validator.is_valid(&v));
        v["head"]["sequence"] = json!(0);
        v["head"]["force"] = json!(true);
        assert!(!validator.is_valid(&v));
        v["head"].as_object_mut().unwrap().remove("force");
        v["state"] = json!("released");
        assert!(!validator.is_valid(&v));
        assert!(serde_json::from_value::<WitnessRecord>(v).is_err());
    }
}
