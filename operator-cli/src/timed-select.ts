// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    createPrompt,
    useState,
    useEffect,
    useKeypress,
    isUpKey,
    isDownKey,
    isEnterKey,
} from '@inquirer/core';
import { isEscapeKey, useResizeClear } from './esc-select.js';

export interface TimedSelectChoice {
    name: string;
    value: string;
}

interface Config {
    message: string;
    getTimerLabel: () => string;
    choices: TimedSelectChoice[];
    intervalMs?: number;
}

export const timedSelect: (config: Config) => Promise<string | null> = createPrompt<string | null, Config>((config, done) => {
    useResizeClear();
    const [cursor, setCursor] = useState(0);
    const [timer, setTimer] = useState(config.getTimerLabel());

    useEffect(() => {
        const id = setInterval(
            () => setTimer(config.getTimerLabel()),
            config.intervalMs ?? 1000,
        );
        return () => clearInterval(id);
    }, []);

    useKeypress(key => {
        if (isEscapeKey(key)) {
            done(null);
        } else if (isUpKey(key)) {
            setCursor(Math.max(0, cursor - 1));
        } else if (isDownKey(key)) {
            setCursor(Math.min(config.choices.length - 1, cursor + 1));
        } else if (isEnterKey(key)) {
            done(config.choices[cursor]!.value);
        }
    });

    const header = `? ${config.message}  |  ${timer}`;
    const items = config.choices
        .map((choice, i) => (i === cursor ? `\x1b[36m❯ ${choice.name}\x1b[0m` : `  ${choice.name}`))
        .join('\n');

    return `${header}\n${items}`;
});
