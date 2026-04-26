// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { select, input } from '@inquirer/prompts';

export async function selectImage(currentImage?: string): Promise<string> {
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

    if (tags.length > 0) {
        return select({
            message: 'Node image',
            choices: tags.map(t => ({ name: t, value: t })),
            default: currentImage && tags.includes(currentImage) ? currentImage : undefined,
        });
    }
    return input({
        message: 'Node image',
        default: currentImage ?? 'aptoslabs/ace-node:latest',
    });
}
