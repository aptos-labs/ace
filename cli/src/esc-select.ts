// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { createPrompt, useState, useEffect, useKeypress, isUpKey, isDownKey, isEnterKey, isBackspaceKey } from '@inquirer/core';

// Single global SIGWINCH listener — avoids handler accumulation across prompts.
// Only the currently active createPrompt's resize fn is called.
let _resizeGen = 0;
let _resizeFn: ((n: number) => void) | null = null;
process.on('SIGWINCH', () => {
    process.stdout.write('\x1b[2J\x1b[H');
    _resizeFn?.(++_resizeGen);
});

export interface EscSelectChoice {
    name: string;
    value: string;
}

interface Config {
    message: string;
    choices: EscSelectChoice[];
    pageSize?: number;
}

export function isEscapeKey(key: { name?: string }): boolean {
    return key.name === 'escape';
}

/**
 * Override rl._ttyWrite to prevent readline from adding printable characters
 * (letters, digits, Tab) to its internal line buffer. Without this, readline
 * tracks cursor movement for every printable keypress, causing checkCursorPos()
 * to write cursorTo() and visibly move the terminal cursor.
 */
export function useSuppressPrintableChars(): void {
    useEffect((rl: any) => {
        const orig = rl._ttyWrite?.bind(rl);
        if (!orig) return;
        rl._ttyWrite = (s: string, key: any) => {
            if (key && !key.ctrl && !key.meta) {
                // Swallow Tab and single printable ASCII characters
                if (key.name === 'tab' || (key.sequence?.length === 1 && key.sequence.charCodeAt(0) >= 32)) {
                    return;
                }
            }
            orig(s, key);
        };
        return () => { rl._ttyWrite = orig; };
    }, []);
}

/** Call inside any createPrompt callback to clear+redraw on terminal resize. */
export function useResizeClear(): void {
    const [, setGen] = useState(0);
    useEffect(() => {
        _resizeFn = (n: number) => setGen(n);
        return () => { _resizeFn = null; };
    }, []);
}

// ── escInput ──────────────────────────────────────────────────────────────────

interface InputConfig {
    message: string;
    default?: string;
    /** Replace input characters with bullets (for secrets). */
    mask?: boolean;
}

const escInputPrompt: (config: InputConfig) => Promise<string | null> =
    createPrompt<string | null, InputConfig>((config, done) => {
        useResizeClear();
        useSuppressPrintableChars();
        const [value, setValue] = useState(config.default ?? '');

        useKeypress(key => {
            const seq: string = (key as any).sequence ?? '';
            if (isEscapeKey(key)) {
                done(null);
            } else if (isEnterKey(key)) {
                done(value);
            } else if (isBackspaceKey(key) || key.name === 'delete') {
                setValue(value.slice(0, -1));
            } else if (key.ctrl && key.name === 'u') {
                setValue('');
            } else if (!key.ctrl && seq.length === 1 && seq.charCodeAt(0) >= 32) {
                setValue(value + seq);
            }
        });

        const display = config.mask ? '•'.repeat(value.length) : value;
        const DIM = '\x1b[2m', R = '\x1b[0m', C = '\x1b[36m', B = '\x1b[1m';
        const hint = `${DIM}[Enter] confirm   [Ctrl+U] clear   [Esc] back${R}`;
        return `\x1b[32m?\x1b[0m ${B}${config.message}${R}\n${C}› ${display}${R}\n${hint}`;
    });

/**
 * An [Esc]-cancellable text input. Returns undefined if the user pressed Esc.
 * Default value is pre-filled and [Enter] on an empty field returns ''.
 */
export async function escInput(config: InputConfig): Promise<string | undefined> {
    const result = await escInputPrompt(config);
    return result === null ? undefined : result;
}

// ── escSelect ─────────────────────────────────────────────────────────────────

// Matches the visual style of @inquirer/prompts select.
export const escSelect: (config: Config) => Promise<string | null> =
    createPrompt<string | null, Config>((config, done) => {
        useResizeClear();
        const [cursor, setCursor] = useState(0);
        const choices = config.choices;

        useKeypress(key => {
            if (isEscapeKey(key)) {
                done(null);
            } else if (isUpKey(key)) {
                setCursor(Math.max(0, cursor - 1));
            } else if (isDownKey(key)) {
                setCursor(Math.min(choices.length - 1, cursor + 1));
            } else if (isEnterKey(key)) {
                done(choices[cursor]!.value);
            }
        });

        const header = `\x1b[32m?\x1b[0m \x1b[1m${config.message}\x1b[22m`;
        const items = choices
            .map((c, i) => i === cursor ? `\x1b[36m❯ ${c.name}\x1b[0m` : `  ${c.name}`)
            .join('\n');

        return `${header}\n${items}`;
    });
