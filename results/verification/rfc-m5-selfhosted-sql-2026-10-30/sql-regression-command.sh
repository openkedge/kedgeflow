set -eu
cargo test --locked --offline --test governance sql_leaf:: -- --nocapture --test-threads=1
cargo test --locked --offline --test governance sql_failure:: -- --nocapture --test-threads=1
cargo test --locked --offline --test governance live_agent:: -- --nocapture --test-threads=1
