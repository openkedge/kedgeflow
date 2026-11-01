FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl openssl passwd python3 python3-cryptography util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; case "$TARGETARCH" in \
      arm64) checksum=451baba77cba6a0b2cdd3ca8b589589418b88673867d2da7f8dac9099252b372 ;; \
      amd64) checksum=f0d1740504fc95e49860ea22dcbe878ebbfee4c9bb077c6a586ed66b9c82a62e ;; \
      *) exit 1 ;; esac; \
    curl --fail --location --retry 3 \
      "https://github.com/spiffe/spire/releases/download/v1.15.5/spire-1.15.5-linux-${TARGETARCH}-musl.tar.gz" \
      -o /tmp/spire.tar.gz; \
    echo "$checksum  /tmp/spire.tar.gz" | sha256sum --check; \
    mkdir /opt/spire; tar -xzf /tmp/spire.tar.gz -C /opt/spire --strip-components=1; \
    rm /tmp/spire.tar.gz
RUN useradd --uid 1002 --no-create-home --shell /bin/false pilot-agent \
    && useradd --uid 1003 --no-create-home --shell /bin/false unregistered-agent \
    && mkdir -p /run/kf-spire/private /var/lib/spire/server /var/lib/spire/agent /run/pilot \
    && chmod 700 /run/kf-spire/private /var/lib/spire/server /var/lib/spire/agent /run/pilot
COPY . /opt/pilot
CMD ["sleep", "infinity"]
