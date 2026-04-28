// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/** Extract a human-readable message from any thrown value, including Aptos SDK errors. */
export function formatError(e: unknown): string {
    if (e instanceof Error) {
        const a = e as any;
        // Aptos AptosApiError: actual text lives in data.message
        if (typeof a.data?.message === 'string' && a.data.message) return a.data.message;
        if (typeof a.data?.vm_error_message === 'string' && a.data.vm_error_message) return a.data.vm_error_message;
        if (typeof e.message === 'string' && e.message && !e.message.includes('[object')) return e.message;
    }
    try { return JSON.stringify(e, null, 2); } catch { return String(e); }
}
