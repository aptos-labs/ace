// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { createPrompt, useState, useEffect, useKeypress, isUpKey, isDownKey, isEnterKey } from '@inquirer/core';

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

/** Call inside any createPrompt callback to clear+redraw on terminal resize. */
export function useResizeClear(): void {
    const [, setGen] = useState(0);
    useEffect(() => {
        _resizeFn = (n: number) => setGen(n);
        return () => { _resizeFn = null; };
    }, []);
}

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
