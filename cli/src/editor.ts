// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared `$EDITOR`-based input flow used by `proposal new`, `node edit`, `deployment edit`.
 *
 * Caller supplies a TOML template (with comments documenting each field) and a parser that
 * turns the post-edit content into a typed result. We handle the common boilerplate:
 * opening `$EDITOR` (falls back to `$VISUAL`, then `vi`), writing/reading the temp file,
 * cleaning up, and treating "no changes" or "non-zero editor exit" as cancel.
 */

import { confirm } from '@inquirer/prompts';
import { spawnSync } from 'child_process';
import { readFileSync, unlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

export interface EditorOptions {
    /** Suffix for the temp file (e.g. `.toml`). Default: `.toml`. */
    fileSuffix?: string;
    /** Tag in the temp filename (e.g. `proposal`, `deployment-edit`). Default: `ace`. */
    fileTag?: string;
    /**
     * Warning shown before the editor opens. If non-empty, prompts the user to confirm
     * before proceeding (use this for `deployment edit` where credentials are visible).
     */
    preWarning?: string;
}

export async function buildFromEditor<T>(
    template: string,
    parser: (content: string) => T | null,
    opts: EditorOptions = {},
): Promise<T | null> {
    if (opts.preWarning) {
        console.log(opts.preWarning);
        const ok = await confirm({ message: 'Open editor?', default: false });
        if (!ok) { console.log('Cancelled.'); return null; }
    }

    const suffix = opts.fileSuffix ?? '.toml';
    const tag = opts.fileTag ?? 'ace';
    const tmpFile = join(tmpdir(), `${tag}-${Date.now()}${suffix}`);
    writeFileSync(tmpFile, template, { encoding: 'utf8', mode: 0o600 });

    const editorRaw = process.env.EDITOR ?? process.env.VISUAL ?? 'vi';
    const editorParts = editorRaw.trim().split(/\s+/);
    const editor = editorParts[0]!;
    const editorArgs = [...editorParts.slice(1), tmpFile];

    const result = spawnSync(editor, editorArgs, { stdio: 'inherit' });

    let content: string;
    try {
        content = readFileSync(tmpFile, 'utf8');
    } finally {
        try { unlinkSync(tmpFile); } catch {}
    }

    if (result.status !== 0) {
        console.log('Editor exited with non-zero status — cancelled.');
        return null;
    }

    if (content.trim() === '' || content.trim() === template.trim()) {
        console.log('No changes made — cancelled.');
        return null;
    }

    return parser(content);
}
