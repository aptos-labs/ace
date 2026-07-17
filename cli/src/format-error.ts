// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/** Extract a human-readable message from any thrown value, including Aptos SDK errors. */
export function formatError(e: unknown): string {
    const msg = extractMessage(e);
    return msg + maybeHint(msg, e);
}

function extractMessage(e: unknown): string {
    if (e instanceof Error) {
        const a = e as any;
        // Aptos AptosApiError: actual text lives in data.message
        if (typeof a.data?.message === 'string' && a.data.message) return a.data.message;
        if (typeof a.data?.vm_error_message === 'string' && a.data.vm_error_message) return a.data.vm_error_message;
        if (e.message === 'fetch failed' && a.cause) {
            const code = typeof a.cause.code === 'string' ? a.cause.code : undefined;
            const host = typeof a.cause.hostname === 'string' ? a.cause.hostname : undefined;
            const detail = [code, host].filter(Boolean).join(' ');
            return detail ? `fetch failed (${detail})` : e.message;
        }
        if (typeof e.message === 'string' && e.message && !e.message.includes('[object')) return e.message;
    }
    // Plain object with a .message field (e.g. Geomi gas-station error: { statusCode, error, message }).
    if (e && typeof e === 'object') {
        const o = e as Record<string, unknown>;
        if (typeof o.message === 'string' && o.message) {
            // Try to also surface the HTTP status, when present.
            const status = typeof o.statusCode === 'number' ? o.statusCode : (typeof o.status === 'number' ? o.status : undefined);
            return status ? `${o.message}  (HTTP ${status})` : o.message;
        }
    }
    try { return JSON.stringify(e, null, 2); } catch { return String(e); }
}

/**
 * Append a friendly remediation hint for known error patterns so users don't have to
 * decode the raw chain / Geomi error themselves.
 */
function maybeHint(msg: string, raw: unknown): string {
    // Geomi gas-station: sponsor account out of APT.
    if (msg.includes('INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE')) {
        const sponsor = typeof msg === 'string' ? msg.match(/sponsor:\s*(0x[0-9a-fA-F]+)/)?.[1] : undefined;
        return (
            `\n\nHint: the gas-payer (sponsor) account doesn't have enough APT to cover this transaction.\n` +
            (sponsor ? `  • Sponsor address: ${sponsor}\n` : '') +
            `  • If you're using a Geomi gas station, top it up at https://geomi.dev → "Gas Stations".\n` +
            `  • The "sponsor" is the gas station itself — NOT your admin or worker account.`
        );
    }
    // Geomi gas-station: requested function not in the allowlist.
    if (msg.match(/(not allowed|not in allowlist|not allow-listed|disallowed|not whitelisted)/i)) {
        return (
            `\n\nHint: the gas station rejected this transaction's entry function. If you're using a Geomi\n` +
            `gas station, check the allowlist for this station at https://geomi.dev → "Gas Stations" →\n` +
            `<your station> → "Allowed functions". ACE needs at least:\n` +
            `  • <ace>::worker_config::register_endpoint\n` +
            `  • <ace>::worker_config::register_pke_enc_key\n` +
            `  • <ace>::vss::*\n` +
            `  • <ace>::voting::vote\n` +
            `(replace <ace> with your contract address).`
        );
    }
    // Sequence-number races.
    if (msg.includes('SEQUENCE_NUMBER_TOO_OLD') || msg.includes('SEQUENCE_NUMBER_TOO_NEW')) {
        return (
            `\n\nHint: account sequence_number drifted between build and submit (rare race). ` +
            `Re-run the command — it will pick up the latest seq_num.`
        );
    }
    // Aptos rate limit (free tier).
    if ((raw as { status?: number; statusCode?: number })?.status === 429 ||
        (raw as { status?: number; statusCode?: number })?.statusCode === 429) {
        return (
            `\n\nHint: the Aptos RPC rate-limited you. Either wait a minute and retry, or set\n` +
            `NODE_API_KEY=aptoslabs_… in your environment to authenticate the RPC calls.`
        );
    }
    return '';
}
