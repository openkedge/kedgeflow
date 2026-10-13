//! Separate disposable witness process shared by restore/SQL qualification.
use reqwest::Client;
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tempfile::TempDir;
// Hold startup until health is ready so another fixture cannot select ports
// released by this fixture before its child has bound them.
static WITNESS_STARTUP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub struct WitnessProcess {
    pub child: Child,
    _dir: TempDir,
    pub endpoint: String,
}
impl Drop for WitnessProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl WitnessProcess {
    pub async fn start() -> Self {
        let _startup = WITNESS_STARTUP.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let client = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", client.local_addr().unwrap());
        let peer_url = format!("http://{}", peer.local_addr().unwrap());
        let binary = std::env::var("ETCD_BINARY").unwrap_or_else(|_| "etcd".into());
        let log = std::fs::File::create(dir.path().join("witness.log")).unwrap();
        drop(client);
        drop(peer);
        let child = Command::new(binary)
            .args([
                "--name=witness",
                &format!("--data-dir={}", dir.path().join("data").display()),
                &format!("--listen-client-urls={endpoint}"),
                &format!("--advertise-client-urls={endpoint}"),
                &format!("--listen-peer-urls={peer_url}"),
                &format!("--initial-advertise-peer-urls={peer_url}"),
                &format!("--initial-cluster=witness={peer_url}"),
                "--initial-cluster-state=new",
                "--log-level=error",
            ])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut p = Self {
            child,
            _dir: dir,
            endpoint,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                p.child.try_wait().unwrap().is_none(),
                "witness exited during startup: {}",
                std::fs::read_to_string(p._dir.path().join("witness.log")).unwrap_or_default()
            );
            if Client::new()
                .get(format!("{}/health", p.endpoint))
                .timeout(Duration::from_millis(200))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return p;
            }
            assert!(
                Instant::now() < deadline,
                "witness readiness timeout: {}",
                std::fs::read_to_string(p._dir.path().join("witness.log")).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
