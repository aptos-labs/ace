// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Constant-rate load probe. For each target QPS in a ramp, drives POSTs at a
 * fixed inter-arrival (1/QPS s) for `durationSec` wall seconds, no concurrency
 * cap. Records per-request latency; errors / timeouts collapse to a 999_000ms
 * sentinel so "what a client sees" plots without special-casing.
 *
 * Reads the current request body from a `Minter` (in-process), so epoch
 * transitions are handled transparently.
 */

import { appendFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { dirname } from 'path';
import { Agent, setGlobalDispatcher } from 'undici';

import type { Minter, Pool } from './mint.js';

// Replace Node's default undici dispatcher with a 256-connection HTTP/1.1 pool.
// Node's `fetch` would otherwise multiplex all requests on a single HTTP/2
// connection per origin, which throttles at the server's MAX_CONCURRENT_STREAMS
// and Cloud Run's per-connection backend-routing — the driver-side bottleneck
// we saw in the 5×400 test (server fleet was idle at 14ms mean; drivers saw
// multi-second p99). 256 sockets × keepalive lets the driver spread requests
// across many TCP connections so no single connection becomes the choke point.
// (Sized for ~5k qps per driver at ~30ms RTT, with headroom for tail latency.)
setGlobalDispatcher(new Agent({
    connections: 256,
    pipelining: 1,
    keepAliveTimeout: 30_000,
    keepAliveMaxTimeout: 600_000,
}));

export interface ProbeConfig {
    minter: { current(): Pool };
    ramp: number[];
    durationSec: number;
    cooldownSec: number;
    timeoutMs: number;
    resultsPath: string;
    /** Stop-condition thresholds. */
    stopErrorRate: number;       // default 0.05
    stopP99Ms: number;            // default 10_000
}

interface LevelResult {
    qps: number;
    n: number;
    errorRate: number;
    p50: number; p75: number; p90: number; p95: number; p99: number;
    mean: number;
    inflightPeak: number;
    statusCounts: Map<string, number>;
}

const ERROR_LATENCY_MS = 999_000;

function quantile(sortedAsc: number[], q: number): number {
    if (sortedAsc.length === 0) return NaN;
    const idx = (sortedAsc.length - 1) * q;
    const lo = Math.floor(idx), hi = Math.ceil(idx);
    if (lo === hi) return sortedAsc[lo]!;
    return sortedAsc[lo]! + (sortedAsc[hi]! - sortedAsc[lo]!) * (idx - lo);
}

async function fireOne(
    endpoint: string, body: string, timeoutMs: number, statusCounts: Map<string, number>,
): Promise<number> {
    const t0 = performance.now();
    try {
        const resp = await fetch(endpoint, {
            method: 'POST',
            body: Buffer.from(body, 'hex'),
            signal: AbortSignal.timeout(timeoutMs),
        });
        const responseBytes = new Uint8Array(await resp.arrayBuffer());
        const key = `${resp.status}${responseBytes.length === 0 ? ':empty' : ''}`;
        statusCounts.set(key, (statusCounts.get(key) ?? 0) + 1);
        if (!resp.ok || responseBytes.length === 0) return ERROR_LATENCY_MS;
        return performance.now() - t0;
    } catch (e: any) {
        const key = `exc:${e?.name ?? 'unknown'}`;
        statusCounts.set(key, (statusCounts.get(key) ?? 0) + 1);
        return ERROR_LATENCY_MS;
    }
}

async function runLevel(cfg: ProbeConfig, qps: number): Promise<LevelResult> {
    const interArrivalMs = 1000 / qps;
    const deadline = performance.now() + cfg.durationSec * 1000;
    const latencies: number[] = [];
    const statusCounts = new Map<string, number>();
    let inflight = 0;
    let inflightPeak = 0;

    let nextFire = performance.now();
    while (performance.now() < deadline) {
        const now = performance.now();
        const sleepFor = nextFire - now;
        if (sleepFor > 0) await new Promise(r => setTimeout(r, Math.min(sleepFor, 50)));
        if (performance.now() < nextFire) continue;

        inflight++;
        if (inflight > inflightPeak) inflightPeak = inflight;
        const pool = cfg.minter.current();
        // Fire-and-forget: each Promise releases its closure once it resolves.
        // Tracking via a counter (not array) keeps memory bounded by in-flight.
        void (async () => {
            const dt = await fireOne(pool.endpoint, pool.encReqHex, cfg.timeoutMs, statusCounts);
            latencies.push(dt);
            inflight--;
        })();
        nextFire += interArrivalMs;
    }
    // Drain outstanding requests (bounded by timeoutMs).
    while (inflight > 0) await new Promise(r => setTimeout(r, 100));

    const sorted = [...latencies].sort((a, b) => a - b);
    const errors = sorted.filter(x => x === ERROR_LATENCY_MS).length;
    const mean = sorted.reduce((a, b) => a + b, 0) / Math.max(sorted.length, 1);
    return {
        qps, n: sorted.length,
        errorRate: errors / Math.max(sorted.length, 1),
        p50: quantile(sorted, 0.50),
        p75: quantile(sorted, 0.75),
        p90: quantile(sorted, 0.90),
        p95: quantile(sorted, 0.95),
        p99: quantile(sorted, 0.99),
        mean,
        inflightPeak,
        statusCounts,
    };
}

/** Run the configured ramp end-to-end. Returns the results CSV path. */
export async function runProbe(cfg: ProbeConfig): Promise<string> {
    mkdirSync(dirname(cfg.resultsPath), { recursive: true });
    if (!existsSync(cfg.resultsPath)) {
        writeFileSync(cfg.resultsPath, 'qps,n,error_rate,p50,p75,p90,p95,p99,mean,inflight_peak,started_at,duration_s\n');
    }

    const initial = cfg.minter.current();
    console.log(`endpoint: ${initial.endpoint}`);
    console.log(`ramp: ${cfg.ramp.join(', ')} QPS, each ${cfg.durationSec}s, cooldown ${cfg.cooldownSec}s`);
    console.log(`results → ${cfg.resultsPath}`);

    for (const qps of cfg.ramp) {
        const startedAt = new Date().toISOString();
        console.log(`\n[${startedAt}] qps=${qps} starting (epoch=${cfg.minter.current().epoch})...`);
        const r = await runLevel(cfg, qps);
        appendFileSync(cfg.resultsPath, [
            r.qps, r.n, r.errorRate.toFixed(4),
            r.p50.toFixed(1), r.p75.toFixed(1), r.p90.toFixed(1), r.p95.toFixed(1), r.p99.toFixed(1),
            r.mean.toFixed(1), r.inflightPeak,
            startedAt, cfg.durationSec,
        ].join(',') + '\n');
        const statusStr = [...r.statusCounts.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(' ');
        console.log(`  n=${r.n} err=${(r.errorRate * 100).toFixed(2)}% p50=${r.p50.toFixed(0)}ms p95=${r.p95.toFixed(0)}ms p99=${r.p99.toFixed(0)}ms peak-inflight=${r.inflightPeak}`);
        console.log(`  status: ${statusStr}`);

        if (r.errorRate > cfg.stopErrorRate || r.p99 > cfg.stopP99Ms) {
            console.log(`\nstopping: error_rate=${r.errorRate.toFixed(4)} or p99=${r.p99.toFixed(0)}ms past threshold`);
            break;
        }
        if (qps !== cfg.ramp[cfg.ramp.length - 1]) {
            console.log(`  cooldown ${cfg.cooldownSec}s...`);
            await new Promise(r => setTimeout(r, cfg.cooldownSec * 1000));
        }
    }
    return cfg.resultsPath;
}
