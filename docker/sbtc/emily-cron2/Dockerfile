FROM rust:1.98.1-slim-trixie AS builder
WORKDIR /code/sbtc
COPY . .
RUN cargo build --locked -p emily-cron2

FROM debian:trixie-slim AS emily-cron2
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /code/sbtc/target/debug/emily-cron2 /usr/local/bin/emily-cron2
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/emily-cron2"]
