// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { settleUntilThreshold, ThresholdTask } from "../src/_internal/settle-until-threshold";

describe("settleUntilThreshold", () => {
    it("returns one ordered result per task and discards unfinished work", async () => {
        let slowTaskAborted = false;
        const slowTask: ThresholdTask<number> = (signal) => new Promise((_resolve, reject) => {
            signal.addEventListener("abort", () => {
                slowTaskAborted = true;
                reject(signal.reason);
            });
        });

        const results = await settleUntilThreshold([
            async () => 10,
            async () => 20,
            slowTask,
        ], 2);

        expect(results).toEqual([
            { status: "fulfilled", value: 10 },
            { status: "fulfilled", value: 20 },
            { status: "discarded" },
        ]);
        expect(slowTaskAborted).toBe(true);
    });

    it("returns every rejection when all tasks settle below threshold", async () => {
        const nope = new Error("nope");
        const results = await settleUntilThreshold([
            async () => 10,
            async () => { throw nope; },
            async () => { throw new Error("also nope"); },
        ], 2);

        expect(results[0]).toEqual({ status: "fulfilled", value: 10 });
        expect(results[1]).toEqual({ status: "rejected", reason: nope });
        expect(results[2].status).toBe("rejected");
    });

    it("preserves task indexes when tasks finish out of order", async () => {
        let finishFirst!: (value: number) => void;
        const first = new Promise<number>((resolve) => { finishFirst = resolve; });

        const pending = settleUntilThreshold([
            async () => first,
            async () => 20,
            async () => 30,
        ], 2);
        const results = await pending;
        finishFirst(10);

        expect(results).toEqual([
            { status: "discarded" },
            { status: "fulfilled", value: 20 },
            { status: "fulfilled", value: 30 },
        ]);
    });

    it("rejects invalid thresholds", async () => {
        await expect(settleUntilThreshold([], 0)).rejects.toThrow("threshold must be positive");
    });
});
