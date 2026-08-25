// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import { DiscoveryViewV0 } from "@aptos-labs/ace-sdk";
import { SnapshotCache, type SnapshotConfig } from "./snapshot";

function hexToBytes(hex: string): Uint8Array {
    const clean = hex.replace(/^0x/, "");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
}

const DEFAULT_PORT = 8080;
const DEFAULT_CACHE_TTL_MS = 1500;
// Latest-mode by default (lag disabled) so behavior is unchanged unless explicitly opted in.
const DEFAULT_LAG_MS = 0;
const DEFAULT_SAMPLE_INTERVAL_MS = 1000;

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
        // Serve state ~lagMs behind latest to dodge the epoch-boundary share-registration race.
        // 0 = disabled (serve latest). sampleIntervalMs is the age granularity and must be ≪ lagMs.
        lagMs: process.env.ACE_DISCOVERY_LAG_MS ? Number(process.env.ACE_DISCOVERY_LAG_MS) : DEFAULT_LAG_MS,
        sampleIntervalMs: process.env.ACE_DISCOVERY_SAMPLE_INTERVAL_MS
            ? Number(process.env.ACE_DISCOVERY_SAMPLE_INTERVAL_MS)
            : DEFAULT_SAMPLE_INTERVAL_MS,
        port: process.env.ACE_DISCOVERY_PORT ? Number(process.env.ACE_DISCOVERY_PORT) : DEFAULT_PORT,
    };
}

function main() {
    const cfg = loadConfig();
    if (cfg.lagMs > 0 && cfg.sampleIntervalMs * 2 > cfg.lagMs) {
        // eslint-disable-next-line no-console
        console.warn(
            `ace-discovery: sampleIntervalMs=${cfg.sampleIntervalMs} is not ≪ lagMs=${cfg.lagMs}; ` +
            `served-view age granularity will be coarse. Prefer sampleIntervalMs ≤ lagMs/4.`,
        );
    }
    const cache = new SnapshotCache(cfg);
    cache.start(); // no-op unless lagMs>0

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

        // Clients should not cache the snapshot — they fetch fresh per operation. The upstream
        // fullnode is shielded by this server's own short-TTL singleflight, not by client caching.
        const noStore = { "Cache-Control": "no-store" };

        // `/bcs` (and `/` for convenience) → the raw 0x-hex BCS of DiscoveryViewV0. This is what the
        // SDK consumes (authoritative; decoded byte-for-byte). Pure pass-through, no decode.
        if (url === "/" || url === "/bcs") {
            try {
                const hex = await cache.get();
                res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", ...noStore }).end(hex);
            } catch (err) {
                res.writeHead(502, { "Content-Type": "text/plain" })
                    .end(`upstream discovery view failed: ${err instanceof Error ? err.message : String(err)}`);
            }
            return;
        }

        // `/json` → human-readable decoded view (all crypto material hex-encoded). For eyeballing /
        // debugging; decoded via the SDK's DiscoveryViewV0 so it can't drift from the SDK's decoder.
        if (url === "/json") {
            try {
                const hex = await cache.get();
                const readable = DiscoveryViewV0.fromBytes(hexToBytes(hex)).toReadable();
                res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", ...noStore })
                    .end(JSON.stringify(readable, null, 2));
            } catch (err) {
                res.writeHead(502, { "Content-Type": "text/plain" })
                    .end(`upstream discovery view failed: ${err instanceof Error ? err.message : String(err)}`);
            }
            return;
        }

        res.writeHead(404, { "Content-Type": "text/plain" }).end("not found");
    });

    server.listen(cfg.port, () => {
        const mode = cfg.lagMs > 0
            ? `lag=${cfg.lagMs}ms sample=${cfg.sampleIntervalMs}ms`
            : `ttl=${cfg.cacheTtlMs}ms`;
        // eslint-disable-next-line no-console
        console.log(
            `ace-discovery-server listening on :${cfg.port} — fullnode=${cfg.fullnode} ` +
            `contract=${cfg.contractAddr} ${mode}`,
        );
    });

    for (const sig of ["SIGTERM", "SIGINT"] as const) {
        process.on(sig, () => {
            cache.stop();
            server.close(() => process.exit(0));
        });
    }
}

main();
