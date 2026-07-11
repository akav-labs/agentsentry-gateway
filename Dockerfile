# Build a static-ish, self-contained gateway binary. Uses rustls (no OpenSSL),
# so the build and runtime images stay tiny with no system TLS dependencies.
FROM rust:1.96-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release && cp target/release/agentsentry-gateway /tmp/agentsentry-gateway

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1001 -g nogroup appuser
COPY --from=builder /tmp/agentsentry-gateway /usr/local/bin/agentsentry-gateway
USER appuser
EXPOSE 9003
ENTRYPOINT ["agentsentry-gateway"]
