// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input } from '@inquirer/prompts';
import { escSelect } from './esc-select.js';

export interface ImageTag {
    name: string;          // e.g. "2.1.0" or "5d0f5dc"
    lastUpdated: string;   // ISO timestamp
}

export async function fetchTagsRaw(pageSize: number = 25): Promise<ImageTag[]> {
    const res = await fetch(
        `https://hub.docker.com/v2/repositories/aptoslabs/ace-node/tags?page_size=${pageSize}&ordering=last_updated`,
    );
    const data = await res.json() as { results: { name: string; last_updated: string }[] };
    return data.results.map(r => ({ name: r.name, lastUpdated: r.last_updated }));
}

async function fetchTags(): Promise<string[]> {
    const tags = await fetchTagsRaw(25);
    return tags.map(t => `aptoslabs/ace-node:${t.name}`);
}

/**
 * Returns the selected image string, or undefined if the user cancelled with [Esc].
 */
export async function selectImage(currentImage?: string): Promise<string | undefined> {
    let tags: string[] = [];

    while (true) {
        process.stdout.write('Fetching available image tags...');
        try {
            tags = await fetchTags();
            process.stdout.write(' done\n');
        } catch {
            process.stdout.write(' (unavailable)\n');
        }

        const choices = [
            ...tags.map(t => ({ name: t, value: t })),
            { name: '+ Enter manually', value: '__manual__'  },
            { name: '↻ Refresh',        value: '__refresh__' },
            { name: '← Cancel',         value: '__cancel__'  },
        ];

        const selected = await escSelect({ message: 'Select image', choices });
        if (selected === '__refresh__') continue;
        if (selected === null || selected === '__cancel__') return undefined;
        if (selected !== '__manual__') return selected;

        // Manual entry — fall back to a plain text input
        const manual = (await input({
            message: 'Image (e.g. aptoslabs/ace-node:abc1234)',
            default: currentImage,
        })).trim();
        return manual || undefined;
    }
}
