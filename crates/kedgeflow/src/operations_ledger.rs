//! Read-only, live prerequisites. Never use a mutation to test write permission.
use crate::{
    contracts::Policy,
    error::{Error, Result},
    governance::EnforcementScope,
    ledger::{EtcdLedger, get, range_kv},
};
impl EtcdLedger {
    pub(crate) async fn readiness_reads(&self) -> Result<()> {
        let result = self
            .guarded_ranges(vec![get(&crate::restore::marker_key(self))])
            .await?;
        range_kv(&result[0])?;
        Ok(())
    }
    pub(crate) async fn readiness_control(
        &self,
        scope: &EnforcementScope,
        policy: &Policy,
        ownership: u64,
    ) -> Result<()> {
        let check = self
            .control_check(scope, policy, ownership, None, None)
            .await?;
        if check.state.is_none() {
            return Err(Error::Refused("managed control not installed".into()));
        }
        let mut compare = check.compare;
        if let Some(gate) = self
            .reservation_gate_for(&scope.conflict_domain, true)
            .await?
        {
            compare.extend(gate.compare)
        }
        let txn = self
            .txn(
                compare,
                vec![get(&crate::restore::marker_key(self))],
                vec![],
            )
            .await?;
        if !txn.succeeded || txn.responses.len() != 1 {
            return Err(Error::Unavailable("readiness snapshot changed".into()));
        }
        range_kv(&txn.responses[0])?;
        Ok(())
    }
}
