# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

# Build context must be the repo root (Cargo workspace spans all members).
# docker build -f worker-components/network-node/Dockerfile -t network-node .

FROM rust:1.87-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p network-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/network-node /usr/local/bin/network-node
ENTRYPOINT ["network-node"]
