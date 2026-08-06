# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

# Build context must be the repo root (discovery-server/tsconfig.json extends ../tsconfig.json).
# docker build -f discovery-server/Dockerfile -t ace-discovery .

FROM node:20-slim AS builder
WORKDIR /repo
COPY tsconfig.json ./tsconfig.json
COPY discovery-server ./discovery-server
WORKDIR /repo/discovery-server
RUN npm install --no-audit --no-fund
RUN npm run build

FROM node:20-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY discovery-server/package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=builder /repo/discovery-server/dist ./dist
EXPOSE 8080
ENTRYPOINT ["node", "dist/index.js"]
