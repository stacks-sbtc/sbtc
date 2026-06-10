# syntax=docker/dockerfile:1.7

# Build stage. We need rust to compile the devenv-setup binary, plus npm/pnpm
# to run the Emily CDK synth that produces the CloudFormation template the
# binary consumes at runtime.
FROM rust:1.94.1-slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    make \
    npm \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN npm install -g pnpm@10

WORKDIR /code/sbtc
COPY . /code/sbtc/

# Build the devenv-setup binary (debug, matching the rest of the devenv).
RUN cargo build --locked --bin devenv-setup

# Synthesise the Emily CDK template so the aws-setup phase has tables to read.
ARG AWS_STAGE=local
ARG TABLES_ONLY=true
RUN make install-pnpm && make emily-cdk-synth

# Runtime stage.
FROM debian:trixie-slim AS devenv-setup
WORKDIR /code
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /code/sbtc/target/debug/devenv-setup /usr/local/bin/devenv-setup
COPY --from=builder /code/sbtc/emily/cdk/cdk.out /code/cdk.out

# AWS / DynamoDB defaults. Local DynamoDB ignores the credentials but the SDK
# refuses to start without them; override at runtime if pointing at real AWS.
ENV AWS_ACCESS_KEY_ID=xxxxxxxxxxxx
ENV AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxx
ENV AWS_REGION=us-west-2
ENV INPUT_CDK_TEMPLATE_PATH=/code/cdk.out/EmilyStack.template.json
ENV READY_FILE_PATH=/tmp/aws-setup-ready

ENTRYPOINT ["/usr/local/bin/devenv-setup", "run"]
