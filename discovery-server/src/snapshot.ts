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
    /** How long a fetched snapshot is served before a refresh is triggered. */
    cacheTtlMs: number;
}

/**
 * Caches the on-chain `network::discovery_view_v0_bcs()` result and hands it out. A burst of client
 * requests within `cacheTtlMs` is served from cache; a single in-flight upstream read is shared
 * (singleflight) so concurrent misses collapse to one chain call.
 */
export class SnapshotCache {
    private readonly aptos: Aptos;
    private readonly fn: `${string}::${string}::${string}`;
    private cached?: { hex: string; fetchedAtMs: number };
    private inFlight?: Promise<string>;

    constructor(private readonly cfg: SnapshotConfig, private readonly nowMs: () => number = Date.now) {
        this.aptos = new Aptos(new AptosConfig({
            network: Network.CUSTOM,
            fullnode: cfg.fullnode,
            clientConfig: cfg.apiKey ? { HEADERS: { Authorization: `Bearer ${cfg.apiKey}` } } : undefined,
        }));
        this.fn = `${cfg.contractAddr}::network::discovery_view_v0_bcs`;
    }

    /** Return the current discovery blob as a `0x`-prefixed hex string. */
    async get(): Promise<string> {
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

    private async fetchUpstream(): Promise<string> {
        const [hex] = await this.aptos.view<[string]>({
            payload: { function: this.fn, typeArguments: [], functionArguments: [] },
        });
        if (typeof hex !== "string") {
            throw new Error(`discovery_view_v0_bcs returned a non-string: ${typeof hex}`);
        }
        return hex;
    }
}
