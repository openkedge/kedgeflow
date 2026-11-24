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
    arguments: Vec<String>,
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
        let arguments = vec![
            "--name=witness".into(),
            format!("--data-dir={}", dir.path().join("data").display()),
            format!("--listen-client-urls={endpoint}"),
            format!("--advertise-client-urls={endpoint}"),
            format!("--listen-peer-urls={peer_url}"),
            format!("--initial-advertise-peer-urls={peer_url}"),
            format!("--initial-cluster=witness={peer_url}"),
            "--initial-cluster-state=new".into(),
            "--log-level=error".into(),
        ];
        let child = Command::new(binary)
            .args(&arguments)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut p = Self {
            child,
            _dir: dir,
            endpoint,
            arguments,
        };
        p.ready().await;
        p
    }
    async fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "witness exited during startup: {}",
                std::fs::read_to_string(self._dir.path().join("witness.log")).unwrap_or_default()
            );
            if Client::new()
                .get(format!("{}/health", self.endpoint))
                .timeout(Duration::from_millis(200))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "witness readiness timeout: {}",
                std::fs::read_to_string(self._dir.path().join("witness.log")).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    /// Copy only this stopped fixture member's physical WAL/backend files.
    #[allow(dead_code)]
    pub fn cold_copy(&mut self, destination: &std::path::Path) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        copy_tree(&self._dir.path().join("data"), destination);
    }
    /// Replace only this fixture member, preserving the separate witness process.
    #[allow(dead_code)]
    pub async fn restore_cold(&mut self, snapshot: &std::path::Path) {
        let _startup = WITNESS_STARTUP.lock().await;
        assert!(self.child.try_wait().unwrap().is_some());
        std::fs::remove_dir_all(self._dir.path().join("data")).unwrap();
        copy_tree(snapshot, &self._dir.path().join("data"));
        let log = std::fs::File::create(self._dir.path().join("witness.log")).unwrap();
        self.child = Command::new(std::env::var("ETCD_BINARY").unwrap_or_else(|_| "etcd".into()))
            .args(&self.arguments)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.ready().await;
    }
}

#[allow(dead_code)]
fn copy_tree(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            assert!(kind.is_file(), "no links or special files in cold backup");
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}
