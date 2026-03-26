FROM rust:1.94.0-slim-trixie AS builder

# Install host build dependencies.
# Build scripts run on the glibc host, so dlopen (needed by bindgen) works.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    git \
    make \
    protobuf-compiler \
    npm \
    default-jre \
    wget \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN npm install -g pnpm@9

# Install the musl cross-toolchain from musl.cc.
# This provides a complete musl-native gcc/g++/ar/libstdc++ for the target,
# avoiding the glibc libstdc++ mismatch that occurs with Debian's g++.
RUN ARCH="$(uname -m)" && \
    wget -qO- "https://musl.cc/${ARCH}-linux-musl-cross.tgz" | tar xz -C /opt && \
    ln -s "/opt/${ARCH}-linux-musl-cross/bin/${ARCH}-linux-musl-gcc" /usr/local/bin/ && \
    ln -s "/opt/${ARCH}-linux-musl-cross/bin/${ARCH}-linux-musl-g++" /usr/local/bin/ && \
    ln -s "/opt/${ARCH}-linux-musl-cross/bin/${ARCH}-linux-musl-ar" /usr/local/bin/

# Add the musl Rust target.
RUN rustup target add "$(uname -m)-unknown-linux-musl"

# Download the sbtc code base so that the initial build is done with
# an appropriate version of the code and the result can be cached.
WORKDIR /code
RUN git clone https://github.com/stacks-sbtc/sbtc.git
WORKDIR /code/sbtc

# Build the codebase from the local sources.
# -------------------------------------------
COPY . /code/sbtc/

# Build statically-linked musl binaries.
# .cargo/config.toml is in .dockerignore so the macOS defaults don't interfere.
# The musl.cc toolchain provides the correct CC/CXX/AR/linker.
RUN MUSL_TARGET="$(uname -m)-unknown-linux-musl" && \
    ARCH="$(uname -m)" && \
    export "CC_${ARCH}_unknown_linux_musl=${ARCH}-linux-musl-gcc" && \
    export "CXX_${ARCH}_unknown_linux_musl=${ARCH}-linux-musl-g++" && \
    export "AR_${ARCH}_unknown_linux_musl=${ARCH}-linux-musl-ar" && \
    export "CARGO_TARGET_$(echo "$MUSL_TARGET" | tr '[:lower:]-' '[:upper:]_')_LINKER=${ARCH}-linux-musl-gcc" && \
    cargo build --target "$MUSL_TARGET" --bin signer --bin blocklist-client --bin emily-server && \
    mkdir -p /output && \
    cp "target/$MUSL_TARGET/debug/signer" /output/signer && \
    cp "target/$MUSL_TARGET/debug/blocklist-client" /output/blocklist-client && \
    cp "target/$MUSL_TARGET/debug/emily-server" /output/emily-server

# Build Emily AWS setup.
# -----------------------
ARG AWS_STAGE=local
ARG TABLES_ONLY=true
RUN make emily-cdk-synth

# Create Docker image to run the signer.
# ---------------------------------------
# distroless/static includes ca-certificates at /etc/ssl/certs/ca-certificates.crt.
FROM gcr.io/distroless/static-debian13 AS signer
COPY --from=builder /output/signer /usr/local/bin/signer
ENTRYPOINT ["/usr/local/bin/signer", "--config", "/signer-config.toml", "--migrate-db"]

# Create Docker image for the blocklist client.
# ----------------------------------------------
# distroless/static includes ca-certificates at /etc/ssl/certs/ca-certificates.crt.
FROM gcr.io/distroless/static-debian13 AS blocklist-client
COPY --from=builder /output/blocklist-client /usr/local/bin/blocklist-client
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
COPY --from=builder /output/emily-server /usr/local/bin/emily-server
# Server configuration.
ENV HOST=0.0.0.0
ENV PORT=3030
# AWS configuration.
ENV AWS_ACCESS_KEY_ID=xxxxxxxxxxxx
ENV AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxx
ENV AWS_REGION=us-west-2
ENV DYNAMODB_ENDPOINT=http://dynamodb:8000
ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/emily-server --host $HOST --port $PORT --dynamodb-endpoint $DYNAMODB_ENDPOINT"]
