// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Command } from 'commander';
import { runNodeCommand } from './commands/node.js';
import { runProposalCommand } from './commands/proposal.js';
import { runNetworkStatus } from './commands/network.js';

const program = new Command();
program.name('ace').description('ACE network operator CLI').version('0.1.0');

program
    .command('node')
    .description('Manage your ACE nodes (add, update, delete, set default)')
    .action(() => runNodeCommand().catch(exitOnError));

program
    .command('proposal')
    .description('View and manage governance proposals')
    .option('-p, --profile <name>', 'node profile to use (default: configured default)')
    .action((opts: { profile?: string }) => runProposalCommand(opts).catch(exitOnError));

const networkCmd = program.command('network').description('Network information commands');
networkCmd
    .command('status')
    .description('Show current network state, committee, keypairs, and pending proposals')
    .option('-p, --profile <name>', 'node profile to use (default: configured default)')
    .action((opts: { profile?: string }) => runNetworkStatus(opts).catch(exitOnError));

program.parse();

function exitOnError(e: unknown): void {
    if ((e as { name?: string })?.name === 'ExitPromptError') {
        process.exit(0);
    }
    process.stderr.write(`\nError: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
}
