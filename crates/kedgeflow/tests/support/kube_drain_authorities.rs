//! Actual protected control/broker processes; the parent remains a same-UID fixture.
use super::*;

pub(crate) struct Material {
    pub native_endpoint: String,
    pub control: support::Pki,
    pub control_credential: String,
    pub broker: support::Pki,
    pub broker_credential: String,
}
pub(super) struct Endpoints<'a> {
    pub control_listen: std::net::SocketAddr,
    pub broker_listen: std::net::SocketAddr,
    pub admit: &'a str,
    pub issue: &'a str,
    pub status: &'a str,
    pub gateway: &'a str,
    pub broker: &'a str,
    pub target: &'a str,
}
struct Root(PathBuf);
impl Root {
    fn new(parent: &std::path::Path, name: &str) -> Self {
        let path = parent.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn transport(&self, pki: &support::Pki, incoming_ca: &str, credential: &str) -> Value {
        json!({"certificate":self.write("identity.pem", pki.client.as_bytes()),
            "private_key":self.write("identity.key", pki.client_key.as_bytes()),
            "workload_ca":self.write("incoming-ca.pem", incoming_ca.as_bytes()),
            "etcd_ca":self.write("native-ca.pem", pki.ca.as_bytes()),
            "etcd_certificate":self.0.join("identity.pem"),"etcd_private_key":self.0.join("identity.key"),
            "etcd_token_file":self.write("native.token", credential.as_bytes())})
    }
    async fn start(
        &self,
        binary: &str,
        config: &Value,
        listen: std::net::SocketAddr,
    ) -> tokio::process::Child {
        let file = self.write("config.json", &canonical(config).unwrap());
        let checked = tokio::process::Command::new(binary)
            .arg("--config")
            .arg(&file)
            .arg("--check")
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            checked.status.success(),
            "protected authority config refused: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        let path = self.0.join("service.log");
        let log = std::fs::File::create(&path).unwrap();
        let mut child = tokio::process::Command::new(binary)
            .arg("--config")
            .arg(&file)
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let until = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "authority exited: {}",
                std::fs::read_to_string(&path).unwrap()
            );
            // Only TCP readiness: no admission, issue, exchange or native request.
            if tokio::net::TcpStream::connect(listen).await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "authority listener unavailable: {}",
                std::fs::read_to_string(&path).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        child
    }
}
fn encoded(keys: &BTreeMap<String, ed25519_dalek::VerifyingKey>) -> Value {
    json!(
        keys.iter()
            .map(|(id, key)| (id.clone(), STANDARD.encode(key.as_bytes())))
            .collect::<BTreeMap<_, _>>()
    )
}
pub(super) async fn start(
    r: &Ready,
    material: &Material,
    endpoints: Endpoints<'_>,
    tool: &kedgeflow::gateway::ToolDescriptor,
    snapshot: &kedgeflow::exchange_identity::TrustSnapshot,
    parent: &std::path::Path,
) -> Vec<tokio::process::Child> {
    let h = &r.physical;
    let trust = &h.f.trust;
    let pin = kedgeflow::governance::trust_digest(trust, &keys(6), &keys(5)).unwrap();
    let selection = json!({"registration":r.r,"child_id":"child-1"});
    let control = Root::new(parent, "control");
    let mut config = control.transport(
        &material.control,
        &h.agent_pki.ca,
        &material.control_credential,
    );
    let evidence: BTreeMap<_,_> = trust.evidence.iter().map(|(id,e)| (id.clone(),json!({
        "review":e.review,"obligation":e.obligation,"provider_id":e.provider_id,"provider_version":e.provider_version,
        "keys":encoded(&e.keys),"question":e.question,"result_schema_ref":e.result_schema_ref,
        "result_schema":e.result_schema,"max_age_ms":e.max_age_ms,"predicates":e.predicates}))).collect();
    config.as_object_mut().unwrap().extend(json!({"listen":endpoints.control_listen,
        "admission_url":endpoints.admit,"issuance_url":endpoints.issue,"status_url":endpoints.status,"status_scope":"kf.status",
        "delegation_audience":crate::AUD,"gateway_audience":endpoints.gateway,
        "oidc_issuer":h.f.identity.subject.iss,"oidc_public_key_base64":public(7)["key-7"],
        "etcd_endpoint":material.native_endpoint,"etcd_prefix":r.r.namespace,"require_control":true,
        "family":selection,"reservation":r.r.child("child-1").unwrap().reservation,
        "admission_key_id":"key-6","admission_signing_key_file":control.write("admission.seed",STANDARD.encode([6;32]).as_bytes()),
        "issuer_key_id":"key-5","issuer_signing_key_file":control.write("issuer.seed",STANDARD.encode([5;32]).as_bytes()),
        "tenant":trust.tenant,"workload_id":trust.proposal_workload_id,"subjects":[h.f.identity.subject],
        "admission_scope":"kf.admit","issuance_scope":"kf.issue","action_scope":trust.required_scope,
        "proposal_keys":encoded(&trust.proposal_keys),"registry_keys":encoded(&trust.registry_keys),"manifest_keys":encoded(&trust.manifest_keys),
        "descriptor_digest":trust.descriptor_digest,"ownership_epoch":trust.ownership_epoch,"max_proposal_age_ms":trust.max_proposal_age_ms,
        "policy":{"id":trust.policy.id,"epoch":trust.policy.epoch,"cedar":h.definition.cedar,
            "max_certificate_lifetime_ms":h.definition.max_certificate_lifetime_ms},"evidence":evidence}).as_object().unwrap().clone());
    let loaded =
        kedgeflow::control_config::ControlConfig::decode(&canonical(&config).unwrap()).unwrap();
    let (actual, definition) = loaded.registration().unwrap();
    assert_eq!(
        kedgeflow::governance::trust_digest(&actual, &keys(6), &keys(5)).unwrap(),
        pin
    );
    assert_eq!(actual.policy, trust.policy);
    assert_eq!(
        actual.obligation_manifest_digest,
        trust.obligation_manifest_digest
    );
    assert_eq!(
        canonical(&json!(definition)).unwrap(),
        canonical(&json!(h.definition)).unwrap()
    );
    let control_child = control
        .start(
            env!("CARGO_BIN_EXE_kf-control"),
            &config,
            endpoints.control_listen,
        )
        .await;
    let broker = Root::new(parent, "broker");
    let mut config = broker.transport(
        &material.broker,
        &material.broker.ca,
        &material.broker_credential,
    );
    config.as_object_mut().unwrap().extend(json!({"listen":endpoints.broker_listen,"external_url":endpoints.broker,
        "etcd_endpoint":material.native_endpoint,"etcd_prefix":r.r.namespace,"family":selection,
        "gateway_audience":endpoints.gateway,"delegation_audience":crate::AUD,"grant_keys":public(5),
        "registration":{"gateway_workload":"spiffe://test/gateway","target_audience":endpoints.target,
            "target_scope":"node:drain","max_lifetime_ms":5000,"tool":tool},
        "identity_snapshot_file":broker.write("identity.json",&canonical(&json!(snapshot)).unwrap()),
        "identity_epoch_floor_file":broker.write("identity.floor",snapshot.epoch.to_string().as_bytes()),
        "target_key_id":"key-29","target_signing_key_file":broker.write("target.seed",STANDARD.encode([29;32]).as_bytes()),
        "target_verification_keys":public(29),"allow_unmanaged_fixture":false,"installed_trust_digest":pin}).as_object().unwrap().clone());
    let broker_child = broker
        .start(
            env!("CARGO_BIN_EXE_kf-broker"),
            &config,
            endpoints.broker_listen,
        )
        .await;
    vec![control_child, broker_child]
}
