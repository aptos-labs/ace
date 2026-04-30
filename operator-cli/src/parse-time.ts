// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Parse a time string into a Date. Supports:
 *   - Relative offset: -90s / -1h30m = that long ago; 90s / +1h = that far in the future
 *   - Unix epoch seconds (pure digits ≤ 13 chars): 1704067200
 *   - ISO 8601 or any string parseable by Date: 2024-01-15T10:30:00Z
 */
export function parseTime(s: string): Date {
    // Relative: optional leading '-' for past, no sign or '+' for future
    const relMatch = /^([+-]?)([\ddhms]+)$/.exec(s);
    if (relMatch && /[dhms]/.test(relMatch[2]!)) {
        const sign = relMatch[1] === '-' ? -1 : 1;
        const r = relMatch[2]!;
        const days  = parseInt(/(\d+)d/.exec(r)?.[1] ?? '0');
        const hours = parseInt(/(\d+)h/.exec(r)?.[1] ?? '0');
        const mins  = parseInt(/(\d+)m/.exec(r)?.[1] ?? '0');
        const secs  = parseInt(/(\d+)s/.exec(r)?.[1] ?? '0');
        const ms = (days * 86400 + hours * 3600 + mins * 60 + secs) * 1000;
        return new Date(Date.now() + sign * ms);
    }
    // Pure digits: unix epoch. ≤10 digits = seconds, otherwise milliseconds.
    if (/^\d+$/.test(s)) {
        const n = parseInt(s);
        return new Date(s.length <= 10 ? n * 1000 : n);
    }
    // Anything else: let Date parse it (ISO 8601, locale strings, etc.)
    const d = new Date(s);
    if (isNaN(d.getTime())) throw new Error(`Cannot parse time "${s}"`);
    return d;
}
