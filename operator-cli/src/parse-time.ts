// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Parse a time string into a Date. Supports:
 *   - Relative (interpreted as "that long ago"): 5m, 1h30m, 2d, 5m55s, 1d12h30m
 *   - Unix epoch seconds (pure digits ≤ 13 chars): 1704067200
 *   - ISO 8601 or any string parseable by Date: 2024-01-15T10:30:00Z
 */
export function parseTime(s: string): Date {
    // Relative: only digits and the unit chars d/h/m/s, and at least one unit char
    if (/^[\ddhms]+$/.test(s) && /[dhms]/.test(s)) {
        const days  = parseInt(/(\d+)d/.exec(s)?.[1] ?? '0');
        const hours = parseInt(/(\d+)h/.exec(s)?.[1] ?? '0');
        const mins  = parseInt(/(\d+)m/.exec(s)?.[1] ?? '0');
        const secs  = parseInt(/(\d+)s/.exec(s)?.[1] ?? '0');
        const ms = (days * 86400 + hours * 3600 + mins * 60 + secs) * 1000;
        return new Date(Date.now() - ms);
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
