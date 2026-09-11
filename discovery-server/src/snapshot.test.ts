// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { SnapshotCache } from "./snapshot.js";

const base = { fullnode: "http://unused/v1", contractAddr: "0x1", cacheTtlMs: 1500 };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("a hung upstream fetch times out and the sampler keeps going", async () => {
    let calls = 0;
    const fetcher = (): Promise<string> => {
        calls++;
        // first call never settles; later calls answer
        return calls === 1 ? new Promise<string>(() => {}) : Promise.resolve(`0x${calls}`);
    };
    const cache = new SnapshotCache(
        { ...base, lagMs: 40, sampleIntervalMs: 10, fetchTimeoutMs: 20 },
        Date.now,
        fetcher,
    );
    cache.start();
    try {
        await sleep(150);
        assert.ok(calls >= 3, `sampler wedged after the hung fetch (calls=${calls})`);
        const hex = await cache.get();
        assert.match(hex, /^0x\d+$/);
        assert.notEqual(hex, "0x1");
    } finally {
        cache.stop();
    }
});

test("a ring older than maxStaleMs is bypassed with a direct read and reported stale", async () => {
    let now = 1_000_000;
    let value = "0xold";
    const cache = new SnapshotCache(
        { ...base, lagMs: 1000, sampleIntervalMs: 100, maxStaleMs: 5000 },
        () => now,
        async () => value,
    );
    // Seed one sample via the bootstrap path (ring empty -> direct read).
    assert.equal(await cache.get(), "0xold");
    now += 1500;
    assert.equal(cache.isStale(), false);
    assert.equal(await cache.get(), "0xold"); // lagged view still fine

    // Sampler is not running (never started) -> the sample ages past maxStaleMs.
    now += 10_000;
    value = "0xfresh";
    assert.equal(cache.isStale(), true);
    assert.equal(await cache.get(), "0xfresh", "stale ring must not be served");
    cache.stop();
});
