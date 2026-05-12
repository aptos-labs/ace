// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace image ls` — list available `aptoslabs/ace-node` image tags on Docker Hub.
 *
 * Sorted newest-first. Mainly useful from `node edit` when the operator wants
 * to know which versions exist before pasting one into the `image` field.
 */

import { fetchTagsRaw } from '../docker-hub.js';

function fmtAgo(iso: string): string {
    const ms = Date.now() - Date.parse(iso);
    if (Number.isNaN(ms) || ms < 0) return iso;
    const s = Math.floor(ms / 1000);
    if (s < 60)  return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60)  return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 48)  return `${h}h ago`;
    const d = Math.floor(h / 24);
    if (d < 30)  return `${d}d ago`;
    const mo = Math.floor(d / 30);
    if (mo < 12) return `${mo}mo ago`;
    return `${Math.floor(d / 365)}y ago`;
}

export async function imageLsCommand(opts: { limit?: string }): Promise<void> {
    const limit = Math.max(1, Math.min(100, parseInt(opts.limit ?? '25', 10) || 25));
    process.stdout.write(`Fetching aptoslabs/ace-node tags (newest ${limit})...`);
    let tags;
    try {
        tags = await fetchTagsRaw(limit);
    } catch (e) {
        process.stdout.write(' failed\n');
        throw e;
    }
    process.stdout.write(' done\n\n');

    const nameWidth = Math.max(4, ...tags.map(t => t.name.length));
    console.log(`${'TAG'.padEnd(nameWidth)}  PUSHED              FULL`);
    for (const t of tags) {
        const full = `aptoslabs/ace-node:${t.name}`;
        console.log(`${t.name.padEnd(nameWidth)}  ${fmtAgo(t.lastUpdated).padEnd(18)}  ${full}`);
    }
}
