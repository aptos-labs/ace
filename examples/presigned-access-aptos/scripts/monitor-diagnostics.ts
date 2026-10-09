// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/** Inspect an Error.cause chain without copying its possibly sensitive text into logs. */
function errorMessages(error: unknown): string[] {
    const messages: string[] = [];
    const seen = new Set<unknown>();
    let current = error;
    while (current !== undefined && current !== null && !seen.has(current) && messages.length < 5) {
        seen.add(current);
        if (current instanceof Error) {
            messages.push(current.message);
            current = current.cause;
        } else if (typeof current === 'string') {
            messages.push(current);
            break;
        } else {
            break;
        }
    }
    return messages;
}

/** A stable cause bucket; never return the raw SDK error, endpoint or response body. */
export function failureDetail(error: unknown): string | undefined {
    const messages = errorMessages(error).join('\n');
    const discoveryHttpStatus = messages.match(/ACE discovery:[^\n]*HTTP (\d{3})/i)?.[1];
    if (discoveryHttpStatus) return `discovery-http-${discoveryHttpStatus}`;
    if (/ACE discovery: session [^\n]* not in snapshot/i.test(messages)) return 'discovery-session-not-in-snapshot';
    if (/ACE discovery: node [^\n]* not in snapshot/i.test(messages)) return 'discovery-node-not-in-snapshot';
    if (/\bterminated\b/i.test(messages)) return 'transport-terminated';
    const threshold = messages.match(/need (\d+) identity key shares, got (\d+)/i);
    if (threshold) return `identity-shares-${threshold[2]}-of-${threshold[1]}`;
    return undefined;
}

/** Bucket failures by their real cause instead of the generic decrypt wrapper. */
export function classifyReason(error: unknown, sdkLogs: string[]): string {
    const message = errorMessages(error).join('\n').toLowerCase();
    if (message.includes('missing required env')) return 'config-error';
    if (message.includes('chain id')) return 'chain-id-mismatch';
    if (message.includes('not in network state')) return 'keypair-missing';
    if (message.includes('committee size') || message.includes('threshold mismatch')) return 'committee-drift';
    if (message.includes('contract version')) return 'version-mismatch';
    if (message.includes('plaintext mismatch')) return 'plaintext-mismatch';

    // Discovery failures can happen before contacting any workers. A generic
    // decrypt wrapper must not turn them into a share-shortfall diagnosis.
    if (message.includes('ace discovery:') || message.includes('not in snapshot')) return 'chain-read-error';

    const lines = sdkLogs.join('\n').toLowerCase();
    if (lines.includes('http 403')) return 'permission-denied';
    if (/http 5\d\d/.test(lines)) return 'worker-5xx';
    if (/http 4\d\d/.test(lines)) return 'worker-4xx';
    if (lines.includes('abort') || lines.includes('timeout')) return 'worker-timeout';
    if (lines.includes('fetch error')) return 'worker-transport-error';
    if (/need \d+ identity key shares, got \d+/.test(message)) {
        return 'threshold-not-met';
    }
    if (message.includes('local decrypt')) return 'decrypt-failed';
    if (message.includes('econn') || message.includes('fetch failed') || message.includes('network state') ||
        message.includes('terminated') || message.includes('view')) return 'chain-read-error';
    return 'unknown';
}
