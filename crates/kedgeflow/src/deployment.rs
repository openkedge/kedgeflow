//! Launch-time requirements for the managed service package.
//! Passing these checks is not production deployment certification.
use crate::{
    broker_config::BrokerConfig,
    config::Config,
    control_config::ControlConfig,
    error::{Error, Result},
};

pub fn gateway(config: &Config) -> Result<()> {
    if !config.require_control
        || config.shared_auth.is_none()
        || config.restore_gate.is_none()
        || config.enforcement.is_none()
        || config.etcd_token_file.as_os_str().is_empty()
    {
        return Err(Error::Refused(
            "managed gateway requires control, shared proof consumption, witness, acknowledgement and ledger authentication".into(),
        ));
    }
    Ok(())
}

pub fn control(config: &ControlConfig) -> Result<()> {
    if !config.require_control || config.shared_auth.is_none() || config.restore_gate.is_none() {
        return Err(Error::Refused(
            "managed control requires control, shared proof consumption and witness".into(),
        ));
    }
    Ok(())
}

pub fn broker(config: &BrokerConfig) -> Result<()> {
    if config.allow_unmanaged_fixture
        || config.restore_gate.is_none()
        || config.identity_refresh.is_none()
    {
        return Err(Error::Refused(
            "managed broker requires managed authority, witness and signed identity refresh".into(),
        ));
    }
    Ok(())
}

pub fn recovery(config: &crate::recovery_config::RecoveryConfig) -> Result<()> {
    // Recovery remains query-only after expiry/withdrawal. Do not require live
    // execution control to resolve an already-consumed original attempt.
    if config.restore_gate.is_none() {
        return Err(Error::Refused(
            "managed recovery requires a restore witness".into(),
        ));
    }
    Ok(())
}

pub fn supervisor(config: &crate::supervision_config::SupervisionConfig) -> Result<()> {
    recovery(&config.recovery)
}

pub fn collector(config: &crate::outcome_report_config::OutcomeReportConfig) -> Result<()> {
    if config.shared_auth.is_none() || config.restore_gate.is_none() {
        return Err(Error::Refused(
            "managed collector requires shared proof consumption and a restore witness".into(),
        ));
    }
    Ok(())
}

pub fn governance(config: &crate::governance_config::GovernanceConfig) -> Result<()> {
    // This checks public enrollment requirements, not admission/issuer private
    // material. Governance must never load the signers of those other roles.
    control(&config.control)
}
