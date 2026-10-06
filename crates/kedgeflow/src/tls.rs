//! Required verified mTLS for inbound workloads; pinned, authenticated outbound
//! clients. These helpers do not provision trust or make a same-privilege daemon
//! independent of an agent.
use crate::error::{Error, Result};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use std::{
    fs,
    io::{BufReader, Cursor},
    path::Path,
    sync::Arc,
    time::Duration,
};

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path)
        .map_err(|_| Error::Invalid(format!("cannot read TLS material: {}", path.display())))
}

fn certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(bytes)))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| Error::Invalid("invalid certificate PEM".to_owned()))?;
    if certs.is_empty() {
        return Err(Error::Invalid("empty certificate PEM".to_owned()));
    }
    Ok(certs)
}

fn private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(Cursor::new(bytes));
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|_| Error::Invalid("invalid private-key PEM".to_owned()))?
        .ok_or_else(|| Error::Invalid("missing private key".to_owned()))?;
    // Refuse multiple private keys rather than selecting an ambiguous identity.
    if rustls_pemfile::private_key(&mut reader)
        .map_err(|_| Error::Invalid("invalid trailing private-key PEM".to_owned()))?
        .is_some()
    {
        return Err(Error::Invalid("multiple private keys".to_owned()));
    }
    Ok(key)
}

pub fn server_config(
    certificate_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
    workload_ca_path: impl AsRef<Path>,
) -> Result<Arc<ServerConfig>> {
    let certificate = read(certificate_path.as_ref())?;
    let key = read(private_key_path.as_ref())?;
    let roots = read(workload_ca_path.as_ref())?;
    server_config_pem(&certificate, &key, &roots)
}

pub fn server_config_pem(
    certificate: &[u8],
    key: &[u8],
    workload_ca: &[u8],
) -> Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(workload_ca)? {
        roots
            .add(cert)
            .map_err(|_| Error::Invalid("invalid workload CA".to_owned()))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| Error::Invalid("invalid workload client verifier".to_owned()))?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Invalid("TLS 1.3 unavailable".to_owned()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(certificate)?, private_key(key)?)
        .map_err(|_| Error::Invalid("invalid gateway certificate/key".to_owned()))?;
    // EndpointPolicy's native binding intentionally accepts HTTP/1.1
    // origin-form requests; no browser or HTTP/2 authority alias profile.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn pinned_http_client(
    ca_path: impl AsRef<Path>,
    certificate_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
    timeout: Duration,
) -> Result<reqwest::Client> {
    let ca = read(ca_path.as_ref())?;
    let certificate = read(certificate_path.as_ref())?;
    let key = read(private_key_path.as_ref())?;
    pinned_http_client_pem(&ca, &certificate, &key, timeout)
}

pub fn pinned_http_client_pem(
    ca: &[u8],
    certificate: &[u8],
    key: &[u8],
    timeout: Duration,
) -> Result<reqwest::Client> {
    if timeout.is_zero() {
        return Err(Error::Invalid("HTTP timeout must be positive".to_owned()));
    }
    // Ensure CA and identity material is actually present before client build.
    certificates(ca)?;
    certificates(certificate)?;
    private_key(key)?;
    let roots = reqwest::Certificate::from_pem_bundle(ca)
        .map_err(|_| Error::Invalid("invalid pinned HTTP CA".to_owned()))?;
    let mut identity_pem = certificate.to_vec();
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(key);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|_| Error::Invalid("invalid HTTP client identity".to_owned()))?;
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .identity(identity)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .http1_only()
        .connect_timeout(timeout.min(Duration::from_secs(5)))
        .timeout(timeout);
    for root in roots {
        builder = builder.add_root_certificate(root);
    }
    builder
        .build()
        .map_err(|_| Error::Invalid("cannot construct pinned HTTP client".to_owned()))
}

/// Only enforcing constructors can produce this type. Privileged HTTP clients
/// cannot accidentally accept caller-chosen roots, proxies or redirect policy.
#[derive(Clone, Debug)]
pub struct PinnedClient(reqwest::Client);

impl PinnedClient {
    pub fn client(&self) -> &reqwest::Client {
        &self.0
    }
}

pub fn pinned_client(
    ca_path: impl AsRef<Path>,
    certificate_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
    timeout: Duration,
) -> Result<PinnedClient> {
    Ok(PinnedClient(pinned_http_client(
        ca_path,
        certificate_path,
        private_key_path,
        timeout,
    )?))
}

pub fn pinned_client_pem(
    ca: &[u8],
    certificate: &[u8],
    key: &[u8],
    timeout: Duration,
) -> Result<PinnedClient> {
    Ok(PinnedClient(pinned_http_client_pem(
        ca,
        certificate,
        key,
        timeout,
    )?))
}
