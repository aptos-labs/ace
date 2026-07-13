// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { collectSettledWorkerMetadata } from "../src/_internal/worker-metadata";

describe("worker metadata collection", () => {
    it("keeps every readable worker without changing its sdkIdx", async () => {
        const unavailable = new Error("metadata unavailable");
        const settled = await Promise.allSettled([
            Promise.resolve({ sdkIdx: 0, endpoint: "https://worker-0.example" }),
            Promise.reject(unavailable),
            Promise.resolve({ sdkIdx: 2, endpoint: "https://worker-2.example" }),
        ]);

        const collection = collectSettledWorkerMetadata(settled, ["0x1", "0x2", "0x3"]);

        expect(collection.values.map(info => info.sdkIdx)).toEqual([0, 2]);
        expect(collection.errors).toEqual([`0x2: ${String(unavailable)}`]);
    });
});
