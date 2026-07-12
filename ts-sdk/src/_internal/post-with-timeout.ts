// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

const DEFAULT_TIMEOUT_MS = 8000;

/** POST a worker request with both caller cancellation and a local deadline. */
export async function postWithTimeout(
    endpoint: string,
    body: string,
    parentSignal: AbortSignal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
    const controller = new AbortController();
    const forwardAbort = () => controller.abort(parentSignal.reason);
    if (parentSignal.aborted) {
        forwardAbort();
    } else {
        parentSignal.addEventListener("abort", forwardAbort, { once: true });
    }
    const timeoutId = setTimeout(() => controller.abort(new Error(`worker request timed out after ${timeoutMs}ms`)), timeoutMs);

    try {
        return await fetch(endpoint, { method: "POST", body, signal: controller.signal });
    } finally {
        clearTimeout(timeoutId);
        parentSignal.removeEventListener("abort", forwardAbort);
    }
}
