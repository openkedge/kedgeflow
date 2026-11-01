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
