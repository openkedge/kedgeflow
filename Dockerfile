FROM rust:1.98-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release --bin kf-proxy

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home kedgeflow
COPY --from=builder /build/target/release/kf-proxy /usr/local/bin/kf-proxy
USER 10001
ENTRYPOINT ["kf-proxy"]
