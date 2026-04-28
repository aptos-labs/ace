// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Command } from 'commander';
import { runOnboarding } from './onboarding.js';
import { loadConfig, saveConfig } from './config.js';
import { networkStatusCommand } from './commands/network-status.js';
import { nodeStatusCommand } from './commands/node-status.js';
import { proposeCommand } from './commands/propose.js';
import { voteCommand } from './commands/vote.js';
import { editNodeCommand } from './commands/edit-node.js';
import { profileListCommand, profileDeleteCommand, profileDefaultCommand } from './commands/profile.js';

const program = new Command();
program.name('ace').description('ACE network operator CLI').version('0.1.0');

// ── new-node ──────────────────────────────────────────────────────────────────

program
    .command('new-node')
    .description('Set up a new ACE node (guided wizard)')
    .action(async () => {
        try {
            const config = loadConfig();
            const { nodeKey, node } = await runOnboarding(config);
            config.nodes[nodeKey] = node;
            if (!config.defaultNode) config.defaultNode = nodeKey;
            saveConfig(config);
            console.log(`\n✓ Node "${node.alias ?? nodeKey}" saved to profile.\n`);
        } catch (e) {
            exitOnError(e);
        }
    });

// ── network-status ────────────────────────────────────────────────────────────

program
    .command('network-status')
    .description('Show on-chain network state (epoch, committee, proposals)')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-w, --watch', 'Continuously refresh every 2s (press Q to quit)')
    .action(async (opts: { profile?: string; watch?: boolean }) => {
        try {
            await networkStatusCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

// ── node-status ───────────────────────────────────────────────────────────────

program
    .command('node-status')
    .description('Show node profile, credentials, committee membership, and deployment comparison')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-w, --watch', 'Continuously refresh every 2s (press Q to quit)')
    .option('--reveal', 'Show secret values (keys, API key) in plaintext')
    .action(async (opts: { profile?: string; watch?: boolean; reveal?: boolean }) => {
        try {
            await nodeStatusCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

// ── propose ───────────────────────────────────────────────────────────────────

program
    .command('propose')
    .description('Create a new on-chain proposal')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .action(async (opts: { profile?: string }) => {
        try {
            await proposeCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

// ── vote ──────────────────────────────────────────────────────────────────────

program
    .command('vote <session-addr>')
    .description('Vote on a proposal by its voting session address')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-y, --yes', 'Skip confirmation prompt')
    .action(async (sessionAddr: string, opts: { profile?: string; yes?: boolean }) => {
        try {
            await voteCommand(sessionAddr, opts);
        } catch (e) {
            exitOnError(e);
        }
    });

// ── edit-node ─────────────────────────────────────────────────────────────────

program
    .command('edit-node')
    .description('Update node image, API key, or gas station key')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .action(async (opts: { profile?: string }) => {
        try {
            await editNodeCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

// ── profile ───────────────────────────────────────────────────────────────────

const profileCmd = program
    .command('profile')
    .description('Manage node profiles');

profileCmd
    .command('list')
    .description('List all profiles')
    .action(() => {
        try {
            profileListCommand();
        } catch (e) {
            exitOnError(e);
        }
    });

profileCmd
    .command('delete <alias>')
    .description('Delete a profile by alias')
    .action(async (alias: string) => {
        try {
            await profileDeleteCommand(alias);
        } catch (e) {
            exitOnError(e);
        }
    });

profileCmd
    .command('default <alias>')
    .description('Set the default profile by alias')
    .action((alias: string) => {
        try {
            profileDefaultCommand(alias);
        } catch (e) {
            exitOnError(e);
        }
    });

program.parse();

function exitOnError(e: unknown): never {
    if ((e as { name?: string })?.name === 'ExitPromptError') process.exit(0);
    process.stderr.write(`\nError: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
}
