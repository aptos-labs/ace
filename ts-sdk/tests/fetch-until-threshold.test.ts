// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { fetchUntilThreshold, ThresholdFetchTask } from "../src/_internal/fetch-until-threshold";

describe("fetchUntilThreshold", () => {
    it("returns at threshold and aborts unfinished tasks", async () => {
        let slowTaskAborted = false;
        const slowTask: ThresholdFetchTask<number> = (signal) => new Promise((resolve) => {
            signal.addEventListener("abort", () => {
                slowTaskAborted = true;
                resolve(null);
            });
        });

        const result = await fetchUntilThreshold({
            tasks: [
                async () => 10,
                async () => 20,
                slowTask,
            ],
            validate: (candidate) => candidate,
            threshold: 2,
            timeoutMs: 10_000,
        });

        expect(result).toEqual([10, 20]);
        expect(slowTaskAborted).toBe(true);
    });

    it("rejects after all tasks settle without enough valid results", async () => {
        await expect(fetchUntilThreshold({
            tasks: [async () => 10, async () => null, async () => { throw new Error("nope"); }],
            validate: (candidate) => candidate,
            threshold: 2,
            timeoutMs: 100,
        })).rejects.toThrow("need 2 results, got 1");
    });

    it("aborts a task at its deadline", async () => {
        vi.useFakeTimers();
        try {
            const hangingTask: ThresholdFetchTask<number> = (signal) => new Promise((resolve) => {
                signal.addEventListener("abort", () => resolve(null));
            });
            const result = fetchUntilThreshold({
                tasks: [hangingTask],
                validate: (candidate) => candidate,
                threshold: 1,
                timeoutMs: 50,
            });
            const rejection = expect(result).rejects.toThrow("need 1 results, got 0");
            await vi.advanceTimersByTimeAsync(50);
            await rejection;
        } finally {
            vi.useRealTimers();
        }
    });

    it("does not validate candidates that arrive after threshold", async () => {
        const validate = vi.fn((candidate: number) => candidate);
        const result = await fetchUntilThreshold({
            tasks: [async () => 10, async () => 20, async () => 30],
            validate,
            threshold: 2,
            timeoutMs: 100,
        });

        expect(result).toEqual([10, 20]);
        expect(validate).toHaveBeenCalledTimes(2);
    });
});
