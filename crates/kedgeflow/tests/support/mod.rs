//! Software-generated certificate fixtures and a real verified-mTLS HTTP test
//! server. These tests establish transport mechanics, not production enrollment.
#![allow(dead_code)]
use axum::{Extension, Router};
use kedgeflow::{auth::WorkloadIdentity, tls::server_config_pem};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct Pki {
    pub ca: String,
    pub server: String,
    pub server_key: String,
    pub client: String,
    pub client_key: String,
}

pub fn pki() -> Pki {
    pki_with_workload("spiffe://test/agent")
}

pub fn pki_with_workload(workload: &str) -> Pki {
    pki_for_workloads(&[workload]).pop().unwrap()
}

pub fn pki_for_workloads(workloads: &[&str]) -> Vec<Pki> {
    pki_with_usage(workloads, false)
}
pub fn dual_pki_for_workloads(workloads: &[&str]) -> Vec<Pki> {
    pki_with_usage(workloads, true)
}
fn pki_with_usage(workloads: &[&str], dual: bool) -> Vec<Pki> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "KedgeFlow software test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let server_key = KeyPair::generate().unwrap();
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params.signed_by(&server_key, &issuer).unwrap();
    workloads
        .iter()
        .map(|workload| {
            let client_key = KeyPair::generate().unwrap();
            let names = if dual {
                vec!["localhost".into(), "127.0.0.1".into()]
            } else {
                Vec::new()
            };
            let mut client_params = CertificateParams::new(names).unwrap();
            client_params
                .subject_alt_names
                .push(SanType::URI((*workload).try_into().unwrap()));
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            if dual {
                client_params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ServerAuth);
            }
            let client = client_params.signed_by(&client_key, &issuer).unwrap();
            Pki {
                ca: ca_cert.pem(),
                server: if dual { client.pem() } else { server.pem() },
                server_key: if dual {
                    client_key.serialize_pem()
                } else {
                    server_key.serialize_pem()
                },
                client: client.pem(),
                client_key: client_key.serialize_pem(),
            }
        })
        .collect()
}

pub struct HttpsServer {
    pub url: String,
    task: JoinHandle<()>,
}
impl Drop for HttpsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The Router only receives a workload extension after rustls validates an
/// enrolled client certificate and the leaf supplies exactly one valid SPIFFE ID.
pub async fn serve_tls(pki: &Pki, router: Router) -> HttpsServer {
    let config = server_config_pem(
        pki.server.as_bytes(),
        pki.server_key.as_bytes(),
        pki.ca.as_bytes(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else {
                    return;
                };
                let Some(peer) = tls.get_ref().1.peer_certificates().and_then(|c| c.first()) else {
                    return;
                };
                let Ok(workload) = WorkloadIdentity::from_verified_cert_der(peer.as_ref()) else {
                    return;
                };
                let service = hyper_util::service::TowerToHyperService::new(
                    router.layer(Extension(workload)),
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    HttpsServer {
        url: format!("https://{address}"),
        task,
    }
}

pub mod witness;
