// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import { SnapshotCache, type SnapshotConfig } from "./snapshot";

const DEFAULT_PORT = 8080;
const DEFAULT_CACHE_TTL_MS = 1500;

function required(name: string): string {
    const v = process.env[name];
    if (!v) throw new Error(`${name} is required`);
    return v;
}

function loadConfig(): SnapshotConfig & { port: number } {
    return {
        // The deployer picks the fullnode explicitly — no baked-in network default.
        fullnode: required("ACE_DISCOVERY_FULLNODE"),
        contractAddr: required("ACE_DISCOVERY_CONTRACT_ADDR"),
        apiKey: process.env.ACE_DISCOVERY_API_KEY || undefined,
        cacheTtlMs: process.env.ACE_DISCOVERY_CACHE_TTL_MS
            ? Number(process.env.ACE_DISCOVERY_CACHE_TTL_MS)
            : DEFAULT_CACHE_TTL_MS,
        port: process.env.ACE_DISCOVERY_PORT ? Number(process.env.ACE_DISCOVERY_PORT) : DEFAULT_PORT,
    };
}

function main() {
    const cfg = loadConfig();
    const cache = new SnapshotCache(cfg);

    const server = http.createServer(async (req, res) => {
        // Public, read-only, no API key required. Discovery data is the same for everyone.
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");

        const url = (req.url ?? "/").split("?")[0];

        if (req.method === "OPTIONS") {
            res.writeHead(204).end();
            return;
        }
        if (req.method !== "GET") {
            res.writeHead(405, { "Content-Type": "text/plain" }).end("method not allowed");
            return;
        }
        if (url === "/healthz") {
            res.writeHead(200, { "Content-Type": "text/plain" }).end("ok");
            return;
        }
        if (url === "/") {
            try {
                // Body is just the `0x`-prefixed BCS hex of DiscoveryViewV0 — no JSON envelope.
                const hex = await cache.get();
                // Clients should not cache the snapshot — they fetch fresh per operation. The
                // upstream fullnode is shielded by this server's own short-TTL singleflight, not by
                // client-side caching.
                res.writeHead(200, {
                    "Content-Type": "text/plain; charset=utf-8",
                    "Cache-Control": "no-store",
                }).end(hex);
            } catch (err) {
                res.writeHead(502, { "Content-Type": "text/plain" })
                    .end(`upstream discovery view failed: ${err instanceof Error ? err.message : String(err)}`);
            }
            return;
        }
        res.writeHead(404, { "Content-Type": "text/plain" }).end("not found");
    });

    server.listen(cfg.port, () => {
        // eslint-disable-next-line no-console
        console.log(
            `ace-discovery-server listening on :${cfg.port} — fullnode=${cfg.fullnode} ` +
            `contract=${cfg.contractAddr} ttl=${cfg.cacheTtlMs}ms`,
        );
    });
}

main();
