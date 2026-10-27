//! Protected file snapshots shared by explicit managed processes. Local SAN
//! inspection only rejects role mixups; remote authentication still needs mTLS.
use crate::{
    error::{Error, Result},
    postgres_custody::{Material, Root},
    tls::PinnedClient,
};
use std::{path::Path, time::Duration};
pub(crate) fn refuse() -> Error {
    Error::Refused("protected managed process material/role refused".into())
}
pub(crate) fn secret(root: &Root, path: &Path) -> Result<String> {
    String::from_utf8(root.read(path, Material::Secret, 16384)?)
        .map(|v| v.trim().to_owned())
        .map_err(|_| refuse())
}
pub(crate) fn local_role(pem: &[u8], expected: &str) -> Result<()> {
    use x509_parser::{
        extensions::GeneralName,
        prelude::{FromDer, X509Certificate},
    };
    let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .next()
        .ok_or_else(refuse)?
        .map_err(|_| refuse())?;
    let (_, cert) = X509Certificate::from_der(&leaf).map_err(|_| refuse())?;
    let san = cert
        .subject_alternative_name()
        .map_err(|_| refuse())?
        .ok_or_else(refuse)?;
    let mut ids = san.value.general_names.iter().filter_map(|n| match n {
        GeneralName::URI(v)
            if v.split(':')
                .next()
                .is_some_and(|v| v.eq_ignore_ascii_case("spiffe")) =>
        {
            Some(*v)
        }
        _ => None,
    });
    if !crate::auth::valid_spiffe_id(expected)
        || ids.next() != Some(expected)
        || ids.next().is_some()
    {
        return Err(refuse());
    }
    Ok(())
}
pub(crate) fn transport(
    root: &Root,
    ca: &Path,
    certificate: &Path,
    key: &Path,
    workload: &str,
) -> Result<PinnedClient> {
    let ca = root.read(ca, Material::Public, 1 << 20)?;
    let certificate = root.read(certificate, Material::Public, 1 << 20)?;
    let key = root.read(key, Material::Secret, 1 << 20)?;
    local_role(&certificate, workload)?;
    crate::tls::pinned_client_pem(&ca, &certificate, &key, Duration::from_secs(5))
}
pub(crate) async fn family(
    root: &Root,
    config: &crate::family::Config,
    workload: &str,
) -> Result<crate::family::Family> {
    crate::grant_reference::fixed_https(&config.etcd_endpoint)?;
    let client = transport(
        root,
        &config.etcd_ca,
        &config.etcd_certificate,
        &config.etcd_private_key,
        workload,
    )?;
    let mut ledger = crate::ledger::EtcdLedger::new(
        client.client().clone(),
        &config.etcd_endpoint,
        &config.etcd_prefix,
    )?
    .with_auth_token(&secret(root, &config.etcd_token_file)?)?;
    if let Some(gate) = &config.restore_gate {
        crate::grant_reference::fixed_https(&gate.endpoint)?;
        let client = transport(
            root,
            &gate.ca,
            &gate.certificate,
            &gate.private_key,
            workload,
        )?;
        let guard = crate::restore::RestoreGate::new(
            crate::ledger::EtcdLedger::new(client.client().clone(), &gate.endpoint, &gate.prefix)?
                .with_auth_token(&secret(root, &gate.token_file)?)?,
        )?;
        ledger = ledger.with_restore_gate(guard)?;
    }
    crate::family::Family::new(ledger, config.registration.clone())
}
