// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";

export interface SnapshotConfig {
    /** Aptos fullnode REST base URL (…/v1). */
    fullnode: string;
    /** Optional node API key (attached as `Authorization: Bearer`). Held server-side only. */
    apiKey?: string;
    /** ACE contract address. */
    contractAddr: string;
    /** lag=0 path only: how long a fetched snapshot is served before a refresh is triggered. */
    cacheTtlMs: number;
    /**
     * Serve on-chain state as-of ~`lagMs` ago instead of latest. `0` (default) keeps the original
     * behavior (serve latest via the lazy TTL cache below).
     *
     * Why lag: at an epoch boundary the on-chain epoch advances a beat before the workers finish
     * registering the new epoch's shares, so a client that reads the freshly-advanced epoch and
     * immediately asks the workers for it gets a 404 (`no share for … epoch=N`). Serving a view that
     * trails real time by `lagMs` hands clients an epoch the workers have already registered, closing
     * that leading-edge race. Safe because the workers keep the previous epoch for a grace window and
     * the derived secret is epoch-invariant — so a slightly-old epoch is equally serveable and gives
     * the same result.
     */
    lagMs: number;
    /**
     * Sampler cadence when `lagMs>0`. This is the *age granularity* of the served view, NOT the lag —
     * it must be ≪ `lagMs`. The served snapshot's age is `lagMs .. lagMs + sampleIntervalMs`, so a
     * small interval (e.g. 1s) with a larger lag (e.g. 5s) gives a tight, consistent trail.
     */
    sampleIntervalMs: number;
    /**
     * Upper bound on a single upstream fetch. Without it one hung request (no response, no reset)
     * leaves the sampler promise unsettled forever and the ring frozen on its last sample.
     * Default: max(5s, 3 x sampleIntervalMs).
     */
    fetchTimeoutMs?: number;
    /**
     * lag>0 only: how old the newest sample may be before the ring is considered *broken* rather than
     * merely lagging. Past this, `get()` bypasses the ring with a direct (timeout-bounded) read and
     * `isStale()` reports true so `/healthz` fails. "Staleness beats an outage" holds for seconds,
     * not for epochs: a view several epochs old makes every worker 404. Default: max(60s, 6 x lagMs).
     */
    maxStaleMs?: number;
}

interface Sample {
    hex: string;
    /**
     * Wall-clock time (ms) the sample was fetched. A reasonable proxy for "the chain time this view
     * reflects" as long as sampling is frequent and upstream latency is small. A stricter version
     * would tag each sample with the ledger timestamp of the read; fetch-time is the v1.
     */
    ts: number;
}

/**
 * Serves the on-chain `network::discovery_view_v0_bcs()` blob, in one of two modes:
 *
 *  - `lagMs === 0` (default): lazy per-request cache. A burst within `cacheTtlMs` is served from
 *    cache; concurrent misses collapse to one upstream read (singleflight). Serves latest.
 *
 *  - `lagMs > 0`: a background sampler (started via `start()`) fetches every `sampleIntervalMs` into
 *    a time-ordered ring; `get()` returns the newest sample whose age ≥ `lagMs`. This trails real
 *    time by ~`lagMs` to dodge the epoch-boundary share-registration race.
 */
export class SnapshotCache {
    private readonly aptos: Aptos;
    private readonly fn: `${string}::${string}::${string}`;

    // lag=0 (latest) mode.
    private cached?: { hex: string; fetchedAtMs: number };
    private inFlight?: Promise<string>;

    // lag>0 (ring) mode. Ordered oldest→newest by push order.
    private ring: Sample[] = [];
    private timer?: ReturnType<typeof setTimeout>;
    private stopped = false;
    private sampling = false;

    private readonly fetchTimeoutMs: number;
    private readonly maxStaleMs: number;
    private readonly rawFetch: () => Promise<string>;

    constructor(
        private readonly cfg: SnapshotConfig,
        private readonly nowMs: () => number = Date.now,
        fetcher?: () => Promise<string>,
    ) {
        this.aptos = new Aptos(new AptosConfig({
            network: Network.CUSTOM,
            fullnode: cfg.fullnode,
            clientConfig: cfg.apiKey ? { HEADERS: { Authorization: `Bearer ${cfg.apiKey}` } } : undefined,
        }));
        this.fn = `${cfg.contractAddr}::network::discovery_view_v0_bcs`;
        this.fetchTimeoutMs = cfg.fetchTimeoutMs ?? Math.max(5_000, 3 * cfg.sampleIntervalMs);
        this.maxStaleMs = cfg.maxStaleMs ?? Math.max(60_000, 6 * cfg.lagMs);
        this.rawFetch = fetcher ?? (() => this.viewUpstream());
    }

    /** lag>0 only: true when the newest sample is older than `maxStaleMs` (or none exists yet). */
    isStale(): boolean {
        if (this.cfg.lagMs <= 0) return false;
        const newest = this.ring[this.ring.length - 1];
        return newest === undefined || this.nowMs() - newest.ts > this.maxStaleMs;
    }

    /** Begin background sampling. No-op in latest (`lagMs<=0`) mode. Call once before serving. */
    start(): void {
        if (this.cfg.lagMs <= 0 || this.timer !== undefined || this.sampling) return;
        this.stopped = false;
        this.sampleLoop();
    }

    /** Stop the background sampler (for graceful shutdown / tests). */
    stop(): void {
        this.stopped = true;
        if (this.timer !== undefined) {
            clearTimeout(this.timer);
            this.timer = undefined;
        }
    }

    /** Return the current discovery blob as a `0x`-prefixed hex string. */
    async get(): Promise<string> {
        if (this.cfg.lagMs > 0) return this.getLagged();

        const cached = this.cached;
        if (cached && this.nowMs() - cached.fetchedAtMs < this.cfg.cacheTtlMs) {
            return cached.hex;
        }
        if (this.inFlight) return this.inFlight;

        this.inFlight = this.fetchUpstream()
            .then((hex) => {
                this.cached = { hex, fetchedAtMs: this.nowMs() };
                return hex;
            })
            .finally(() => {
                this.inFlight = undefined;
            });

        try {
            return await this.inFlight;
        } catch (err) {
            // If a refresh fails but we still hold a previous value, keep serving it (staleness beats
            // an outage). Only surface the error when we have nothing cached.
            if (this.cached) return this.cached.hex;
            throw err;
        }
    }

    // ── lag>0 (ring) mode ──────────────────────────────────────────────────────

    /** Serve the newest sample at least `lagMs` old; warm up / bootstrap when the ring is too young. */
    private async getLagged(): Promise<string> {
        if (this.ring.length > 0 && this.isStale()) {
            // The ring is broken (sampler stuck or upstream down for a long time). Serving it would
            // hand out an epoch the workers have long evicted, so bypass it with a direct bounded
            // read; on failure fall through to the ring as a last resort. Also re-arm the sampler
            // in case its timer chain was lost.
            // eslint-disable-next-line no-console
            console.warn(`[ring] newest sample is ${this.nowMs() - this.ring[this.ring.length - 1]!.ts}ms old (> ${this.maxStaleMs}ms); bypassing ring`);
            this.ensureSampling();
            try {
                return await this.bootstrapFetch();
            } catch {
                // fall through to the stale ring
            }
        }
        const cutoff = this.nowMs() - this.cfg.lagMs;
        for (let i = this.ring.length - 1; i >= 0; i--) {
            if (this.ring[i]!.ts <= cutoff) return this.ring[i]!.hex;
        }
        // Warmup: samples exist but none is old enough yet — serve the oldest we have. (Only for the
        // first ~lagMs after start; better to serve a slightly-too-fresh view than to fail.)
        if (this.ring.length > 0) return this.ring[0]!.hex;
        // Cold start before the first sample landed — bootstrap with one direct read (singleflight).
        return this.bootstrapFetch();
    }

    private async bootstrapFetch(): Promise<string> {
        if (this.inFlight) return this.inFlight;
        this.inFlight = this.fetchUpstream()
            .then((hex) => {
                this.ring.push({ hex, ts: this.nowMs() });
                return hex;
            })
            .finally(() => {
                this.inFlight = undefined;
            });
        return this.inFlight;
    }

    /** Re-arm the sampler if no timer is pending (self-heal after a lost timer chain). */
    private ensureSampling(): void {
        if (this.cfg.lagMs <= 0 || this.stopped || this.timer !== undefined || this.sampling) return;
        this.sampleLoop();
    }

    private sampleLoop(): void {
        if (this.stopped) return;
        this.timer = undefined;
        this.sampling = true;
        const started = this.nowMs();
        void this.fetchUpstream()
            .then((hex) => {
                this.ring.push({ hex, ts: this.nowMs() });
                this.pruneRing();
            })
            .catch((err) => {
                // Skip this sample; the ring keeps serving the last good views. Staleness beats an
                // outage — same principle as the latest-mode catch above.
                // eslint-disable-next-line no-console
                console.warn(`[ring] sample failed: ${err instanceof Error ? err.message : String(err)}`);
            })
            .finally(() => {
                this.sampling = false;
                if (this.stopped) return;
                const elapsed = this.nowMs() - started;
                const delay = Math.max(0, this.cfg.sampleIntervalMs - elapsed);
                this.timer = setTimeout(() => this.sampleLoop(), delay);
            });
    }

    /**
     * Keep the sample we'd currently serve (newest with age ≥ lag) and everything newer; drop older.
     * Self-cleaning, so the ring holds ~`lagMs/sampleIntervalMs` entries. A hard cap guards against
     * clock/config surprises.
     */
    private pruneRing(): void {
        const cutoff = this.nowMs() - this.cfg.lagMs;
        let serveIdx = -1;
        for (let i = this.ring.length - 1; i >= 0; i--) {
            if (this.ring[i]!.ts <= cutoff) {
                serveIdx = i;
                break;
            }
        }
        if (serveIdx > 0) this.ring.splice(0, serveIdx);
        const cap = Math.ceil(this.cfg.lagMs / Math.max(1, this.cfg.sampleIntervalMs)) + 8;
        if (this.ring.length > cap) this.ring.splice(0, this.ring.length - cap);
    }

    /** One upstream read, bounded by `fetchTimeoutMs` so a hung request can never wedge the sampler. */
    private fetchUpstream(): Promise<string> {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const timeout = new Promise<never>((_, reject) => {
            timer = setTimeout(
                () => reject(new Error(`upstream fetch timed out after ${this.fetchTimeoutMs}ms`)),
                this.fetchTimeoutMs,
            );
        });
        return Promise.race([this.rawFetch(), timeout]).finally(() => clearTimeout(timer));
    }

    private async viewUpstream(): Promise<string> {
        const [hex] = await this.aptos.view<[string]>({
            payload: { function: this.fn, typeArguments: [], functionArguments: [] },
        });
        if (typeof hex !== "string") {
            throw new Error(`discovery_view_v0_bcs returned a non-string: ${typeof hex}`);
        }
        return hex;
    }
}
