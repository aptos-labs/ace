// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { readWorkerResponseBytes } from "../src/_internal/node-request";

describe("worker response size limit", () => {
    it("rejects oversized aggregate headers and cancels the body", async () => {
        const cancel = vi.fn(async () => undefined);
        const body = new ReadableStream<Uint8Array>({ cancel });
        const response = new Response(body, { headers: { "x-worker-data": "123456" } });

        await expect(readWorkerResponseBytes(response, 10, 5)).rejects.toThrow("headers exceed max 5");
        expect(cancel).toHaveBeenCalledOnce();
    });

    it("rejects an oversized declared content length before buffering", async () => {
        const cancel = vi.fn(async () => undefined);
        const body = new ReadableStream<Uint8Array>({ cancel });
        const response = new Response(body, { headers: { "content-length": "11" } });

        await expect(readWorkerResponseBytes(response, 10)).rejects.toThrow("exceeds max 10");
        expect(cancel).toHaveBeenCalledOnce();
    });

    it("cancels a chunked response as soon as it crosses the limit", async () => {
        let cancelled = false;
        const body = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(new Uint8Array(6));
                controller.enqueue(new Uint8Array(5));
            },
            cancel() {
                cancelled = true;
            },
        });

        await expect(readWorkerResponseBytes(new Response(body), 10)).rejects.toThrow("exceeds max 10");
        expect(cancelled).toBe(true);
    });

    it("returns a response body at the limit", async () => {
        const bytes = await readWorkerResponseBytes(
            new Response(new Uint8Array([1, 2, 3, 4])),
            4,
        );
        expect(bytes).toEqual(new Uint8Array([1, 2, 3, 4]));
    });
});
