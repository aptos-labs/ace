// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Command } from 'commander';
import { runOnboarding } from './onboarding.js';
import { loadConfig, saveConfig } from './config.js';
import { networkStatusCommand } from './commands/network-status.js';
import { nodeStatusCommand } from './commands/node-status.js';
import { proposeCommand } from './commands/propose.js';
import { reviewProposalCommand } from './commands/review-proposal.js';
import { editNodeCommand } from './commands/edit-node.js';
import { profileListCommand, profileDeleteCommand, profileDefaultCommand } from './commands/profile.js';
import { logCommand } from './commands/log.js';

const program = new Command();
program.name('ace').description('ACE network CLI (operator + admin)').version('0.1.0');

// ──────────────────────────────────────────────────────────────────────────────
// `ace node` — operator-side commands
// ──────────────────────────────────────────────────────────────────────────────

const nodeCmd = program.command('node').description('Manage and operate ACE worker nodes');

nodeCmd
    .command('new')
    .description('Set up a new ACE node (guided wizard)')
    .action(async () => {
        try {
            const config = loadConfig();
            const { nodeKey, node } = await runOnboarding();
            config.nodes[nodeKey] = node;
            if (!config.defaultNode) config.defaultNode = nodeKey;
            saveConfig(config);
            console.log(`\n✓ Node "${node.alias ?? nodeKey}" saved to profile.\n`);
        } catch (e) {
            exitOnError(e);
        }
    });

nodeCmd
    .command('ls')
    .description('List all node profiles')
    .action(() => {
        try {
            profileListCommand();
        } catch (e) {
            exitOnError(e);
        }
    });

nodeCmd
    .command('delete [alias]')
    .description('Delete a node profile by alias or account address')
    .option('-a, --account <addr>', 'Match profile by account address')
    .action(async (alias: string | undefined, opts: { account?: string }) => {
        try {
            const key = alias ?? opts.account;
            if (!key) exitOnError(new Error('Provide an alias or --account <addr>'));
            await profileDeleteCommand(key);
        } catch (e) {
            exitOnError(e);
        }
    });

nodeCmd
    .command('default [alias]')
    .description('Set the default node profile by alias or account address')
    .option('-a, --account <addr>', 'Match profile by account address')
    .action((alias: string | undefined, opts: { account?: string }) => {
        try {
            const key = alias ?? opts.account;
            if (!key) exitOnError(new Error('Provide an alias or --account <addr>'));
            profileDefaultCommand(key);
        } catch (e) {
            exitOnError(e);
        }
    });

nodeCmd
    .command('edit')
    .description('Update node image, API key, gas station key, etc.')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-a, --account <addr>', 'Account address of the profile to use')
    .action(async (opts: { profile?: string; account?: string }) => {
        try {
            await editNodeCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

nodeCmd
    .command('status')
    .description('Show node profile, credentials, committee membership, deployment diff')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-a, --account <addr>', 'Account address of the profile to use')
    .option('-w, --watch', 'Continuously refresh every 2s (press Q to quit)')
    .option('--reveal', 'Show secret values (keys, API key) in plaintext')
    .action(async (opts: { profile?: string; account?: string; watch?: boolean; reveal?: boolean }) => {
        try {
            await nodeStatusCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

nodeCmd
    .command('log')
    .description('Stream or query node logs (docker / gcp / local)')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-a, --account <addr>', 'Account address of the profile to use')
    .option('--since <time>', 'Show logs after this time (e.g. -30m, -1h, 2024-01-15T10:00:00Z, 1704067200)')
    .option('--until <time>', 'Show logs before this time (same formats as --since)')
    .option('-w, --watch', 'Stream new log lines (respects --until if set)')
    .action(async (opts: { profile?: string; account?: string; since?: string; until?: string; watch?: boolean }) => {
        try {
            await logCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

// ──────────────────────────────────────────────────────────────────────────────
// `ace proposal` — committee-change & secret-rotation proposals (admin or node)
// ──────────────────────────────────────────────────────────────────────────────

const proposalCmd = program.command('proposal').description('Create or review on-chain proposals');

proposalCmd
    .command('new [file]')
    .description('Create a new on-chain proposal (opens $EDITOR; pass a .toml file to skip editor)')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-a, --account <addr>', 'Account address of the profile to use')
    .action(async (file: string | undefined, opts: { profile?: string; account?: string }) => {
        try {
            await proposeCommand({ ...opts, file });
        } catch (e) {
            exitOnError(e);
        }
    });

proposalCmd
    .command('review')
    .description('Review a proposal and optionally vote on it (interactive TUI)')
    .option('-s, --session <addr>', 'Voting session address of the proposal')
    .option('-p, --profile <alias>', 'Profile alias to use')
    .option('-a, --account <addr>', 'Account address of the profile to use')
    .action(async (opts: { session?: string; profile?: string; account?: string }) => {
        try {
            await reviewProposalCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

// ──────────────────────────────────────────────────────────────────────────────
// `ace network-status` — chain-side read; works with either profile type
// ──────────────────────────────────────────────────────────────────────────────

program
    .command('network-status')
    .description('Show on-chain network state (epoch, committee, proposals, contract version)')
    .option('-p, --profile <alias>', 'Node or deployment profile alias to use')
    .option('-a, --account <addr>', 'Account address (node or admin) of the profile to use')
    .option('-w, --watch', 'Continuously refresh every 2s (press Q to quit)')
    .action(async (opts: { profile?: string; account?: string; watch?: boolean }) => {
        try {
            await networkStatusCommand(opts);
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
