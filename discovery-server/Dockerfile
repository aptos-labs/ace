# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

# Build context must be the repo root (pnpm workspace: discovery-server depends on the
# @aptos-labs/ace-sdk workspace package for the DiscoveryViewV0 decoder).
# docker build -f discovery-server/Dockerfile -t ace-discovery .

FROM node:20-slim AS builder
RUN corepack enable
WORKDIR /repo
COPY . .
# Install only the discovery-server + ace-sdk projects (and their deps), not the whole workspace.
RUN pnpm install --frozen-lockfile \
      --filter "@aptos-labs/ace-sdk" \
      --filter "@aptos-labs/ace-discovery-server"
RUN pnpm --filter @aptos-labs/ace-sdk build
RUN pnpm --filter @aptos-labs/ace-discovery-server build

# tsup bundles ace-sdk + ts-sdk into dist/index.js, so the runtime image is just node + one file.
FROM node:20-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /repo/discovery-server/dist ./dist
EXPOSE 8080
ENTRYPOINT ["node", "dist/index.js"]
