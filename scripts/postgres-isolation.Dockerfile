# A disposable Linux fixture, never a deployment image. The build records its
# exact base image digest; the fixture itself runs without external networking.
FROM rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157

RUN apt-get update && apt-get install -y --no-install-recommends \
    bison bzip2 ca-certificates curl flex gcc libc6-dev make openssl passwd perl python3 util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kf
RUN curl --fail --location --retry 3 \
      https://ftp.postgresql.org/pub/source/v18.3/postgresql-18.3.tar.bz2 \
      -o postgres.tar.bz2 \
    && echo 'd95663fbbf3a80f81a9d98d895266bdcb74ba274bcc04ef6d76630a72dee016f  postgres.tar.bz2' \
      | sha256sum --check \
    && tar -xjf postgres.tar.bz2 \
    && cd postgresql-18.3 \
    && ./configure --prefix=/opt/kf/postgres --without-icu --without-readline --without-zlib \
    && make -j2 && make install \
    && cd /opt/kf && rm -rf postgresql-18.3 postgres.tar.bz2

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY spec ./spec
COPY migrations ./migrations
RUN cargo build --locked --bin kf-postgres-target --jobs 2 \
    && install -D target/debug/kf-postgres-target /opt/kf/bin/kf-postgres-target \
    && rm -rf target /usr/local/cargo/registry

COPY config/postgres-target.example.json ./config/postgres-target.example.json
COPY scripts/qualify-postgres-isolation.py ./scripts/qualify-postgres-isolation.py
COPY scripts/postgres-isolation.Dockerfile scripts/postgres-isolation.Dockerfile.dockerignore ./scripts/
RUN find Cargo.toml Cargo.lock crates spec migrations config scripts -type f -print0 \
      | sort -z | xargs -0 sha256sum > /opt/kf/source-sha256.txt \
    && tar -czf /opt/kf/source.tar.gz Cargo.toml Cargo.lock crates spec migrations config scripts \
    && dpkg-query -W > /opt/kf/packages.txt \
    && rustc --version > /opt/kf/tools.txt && cargo --version >> /opt/kf/tools.txt \
    && /opt/kf/postgres/bin/postgres --version >> /opt/kf/tools.txt \
    && python3 --version >> /opt/kf/tools.txt && openssl version >> /opt/kf/tools.txt

ENTRYPOINT ["python3", "/source/scripts/qualify-postgres-isolation.py", "--ephemeral-host", "--bindir", "/opt/kf/postgres/bin", "--target", "/opt/kf/bin/kf-postgres-target"]
