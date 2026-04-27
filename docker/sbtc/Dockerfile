FROM rust:1.94.1-slim-trixie AS builder

# Install dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    make \
    npm \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN npm install -g pnpm@10

# Build the codebase from the local sources.
# -------------------------------------------
WORKDIR /code/sbtc
COPY . /code/sbtc/

# Build signer and blocklist client.
# -------------------------------------
RUN cargo build --locked --bin signer --bin blocklist-client

# Build Emily Server.
# --------------------
ARG EMILY_SERVER_BUILD_ARGS=""
RUN cargo build --locked --bin emily-server $EMILY_SERVER_BUILD_ARGS

# Build Emily AWS setup.
# -----------------------
ARG AWS_STAGE=local
ARG TABLES_ONLY=true
RUN make install-pnpm && make emily-cdk-synth

# Create Docker image to run the signer.
# ---------------------------------------
FROM debian:trixie-slim AS signer
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /code/sbtc/target/debug/signer /usr/local/bin/signer
ENTRYPOINT ["/usr/local/bin/signer", "--config", "/signer-config.toml", "--migrate-db"]

# Create Docker image for the blocklist client.
# ----------------------------------------------
FROM debian:trixie-slim AS blocklist-client
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /code/sbtc/target/debug/blocklist-client /usr/local/bin/blocklist-client
ENTRYPOINT ["/usr/local/bin/blocklist-client"]

# Create Docker image to setup the AWS resources for Emily.
# ----------------------------------------------------------
FROM python:3.12-slim AS emily-aws-setup
WORKDIR /code
COPY --from=builder /code/sbtc/docker/sbtc/emily-aws-setup/initialize.py /code/initialize.py
COPY --from=builder /code/sbtc/emily/cdk/cdk.out /code/cdk.out
RUN pip3 install boto3
# The local lambda path is not used here because we're only deploying with the
# dynamodb tables. This will need to point to the local lambda zip file
# that was compiled to be deployed.
ENV LOCAL_LAMBDA_PATH=/code/your-compiled-aws-lambda-here.zip
ENV DYNAMODB_ENDPOINT=http://dynamodb:8000
ENV INPUT_CDK_TEMPLATE=/code/cdk.out/EmilyStack.template.json
ENV OUTPUT_CDK_TEMPLATE=/code/cdk.out/EmilyStack.devenv.template.json
ENTRYPOINT ["python3", "/code/initialize.py"]

# Create Docker image to run the emily server.
# ---------------------------------------------
FROM debian:trixie-slim AS emily-server
WORKDIR /code
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /code/sbtc/target/debug/emily-server /usr/local/bin/emily-server
# Server configuration.
ENV HOST=0.0.0.0
ENV PORT=3030
# AWS configuration.
ENV AWS_ACCESS_KEY_ID=xxxxxxxxxxxx
ENV AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxx
ENV AWS_REGION=us-west-2
ENV DYNAMODB_ENDPOINT=http://dynamodb:8000
ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/emily-server --host $HOST --port $PORT --dynamodb-endpoint $DYNAMODB_ENDPOINT"]
