#[tokio::main]
async fn main() {
    if let Err(e) = kedgeflow::kube_drain_cli::run(false).await {
        eprintln!("kf-kube-drain: {e}");
        std::process::exit(1);
    }
}
