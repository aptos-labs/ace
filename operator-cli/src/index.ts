// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Command } from 'commander';
import { confirm } from '@inquirer/prompts';
import { loadConfig, saveConfig, deriveRpcLabel } from './config.js';
import { runNodeCommand, nodeDetailLoop } from './commands/node.js';

function enterAltScreen(): void {
    process.stdout.write('\x1b[?1049h');
}

function exitAltScreen(): void {
    process.stdout.write('\x1b[?1049l');
}

process.on('exit', exitAltScreen);
process.on('SIGTERM', () => process.exit(0));

const program = new Command();
program.name('ace').description('ACE network operator CLI').version('0.1.0');

program
    .command('nodes')
    .description('Manage your ACE nodes')
    .action(() => { enterAltScreen(); runNodeCommand().catch(exitOnError); });

// Bare `ace` → straight to default node, or node list if none configured
program.action(() => { enterAltScreen(); runMain().catch(exitOnError); });

program.parse();

async function runMain(): Promise<void> {
    let activeNodeKey: string | undefined;

    const onExit = async () => {
        const config = loadConfig();
        if (activeNodeKey && activeNodeKey !== config.defaultNode) {
            const ok = await confirm({
                message: `Set "${activeNodeKey}" as the default node for future sessions?`,
                default: false,
            });
            if (ok) {
                const cfg = loadConfig();
                cfg.defaultNode = activeNodeKey;
                saveConfig(cfg);
                console.log('\n  ✓ Default node updated.\n');
            }
        }
    };

    process.on('SIGINT', async () => {
        await onExit();
        process.exit(0);
    });

    // If there's a default node, open its detail view directly.
    const config = loadConfig();
    const defaultKey = config.defaultNode;
    if (defaultKey && config.nodes[defaultKey]) {
        console.clear();
        const activated = await nodeDetailLoop(defaultKey);
        if (activated) activeNodeKey = activated;
    }

    // Fall through to the node list (Back from detail, or no default).
    const activated = await runNodeCommand();
    if (activated) activeNodeKey = activated;

    await onExit();
}

function exitOnError(e: unknown): void {
    if ((e as { name?: string })?.name === 'ExitPromptError') {
        process.exit(0);
    }
    process.stderr.write(`\nError: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
}
