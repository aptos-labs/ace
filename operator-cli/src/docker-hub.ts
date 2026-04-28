// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input } from '@inquirer/prompts';
import { escSelect } from './esc-select.js';

/**
 * Returns the selected image string, or undefined if the user cancelled with [Esc].
 */
export async function selectImage(currentImage?: string): Promise<string | undefined> {
    process.stdout.write('Fetching available image tags...');
    let tags: string[] = [];
    try {
        const res = await fetch(
            'https://hub.docker.com/v2/repositories/aptoslabs/ace-node/tags?page_size=25&ordering=last_updated',
        );
        const data = await res.json() as { results: { name: string }[] };
        tags = data.results.map(r => `aptoslabs/ace-node:${r.name}`);
        process.stdout.write(' done\n');
    } catch {
        process.stdout.write(' (unavailable)\n');
    }

    const choices = [
        ...tags.map(t => ({ name: t, value: t })),
        { name: '+ Enter manually', value: '__manual__' },
        { name: '← Cancel',        value: '__cancel__' },
    ];

    const selected = await escSelect({ message: 'Select image', choices });
    if (selected === null || selected === '__cancel__') return undefined;

    if (selected !== '__manual__') return selected;

    // Manual entry — fall back to a plain text input
    const manual = (await input({
        message: 'Image (e.g. aptoslabs/ace-node:abc1234)',
        default: currentImage,
    })).trim();
    return manual || undefined;
}
