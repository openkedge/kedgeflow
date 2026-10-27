#[tokio::main]
async fn main() {
    if let Err(e) = kedgeflow::kube_drain_cli::run(true).await {
        eprintln!("kf-managed-kube-drain: {e}");
        std::process::exit(1);
    }
}
