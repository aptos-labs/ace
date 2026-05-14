// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Command } from 'commander';
import { confirm } from '@inquirer/prompts';
import { runOnboarding } from './onboarding.js';
import { loadConfig, saveConfig } from './config.js';
import { formatError } from './format-error.js';
import { networkStatusCommand } from './commands/network-status.js';
import { nodeStatusCommand } from './commands/node-status.js';
import { proposeCommand } from './commands/propose.js';
import { reviewProposalCommand } from './commands/review-proposal.js';
import { editNodeCommand } from './commands/edit-node.js';
import { profileListCommand, profileDeleteCommand, profileDefaultCommand } from './commands/profile.js';
import { logCommand } from './commands/log.js';
import { deploymentListCommand, deploymentDeleteCommand, deploymentDefaultCommand } from './commands/deployment.js';
import { updateContractsCommand } from './commands/update-contracts.js';
import { deploymentEditCommand } from './commands/deployment-edit.js';
import { deploymentNewCommand } from './commands/deployment-new.js';

const program = new Command();
program.name('ace').description('ACE network CLI (operator + admin)').version('0.1.0');

// ──────────────────────────────────────────────────────────────────────────────
// `ace deployment` — admin-side commands (manage deployment profiles)
// ──────────────────────────────────────────────────────────────────────────────

const deploymentCmd = program.command('deployment').description('Manage ACE deployments (admin profiles)');

deploymentCmd
    .command('new')
    .description(
        'Deploy ACE contracts to a chosen network and persist an admin profile (clean tree + ' +
            'release tag at HEAD; ACE_DEPLOYMENT_NEW_SKIP_TAG_CHECK=1 relaxes both — NEXT_RELEASE if untagged)',
    )
    .action(async () => {
        try {
            await deploymentNewCommand();
        } catch (e) {
            exitOnError(e);
        }
    });

deploymentCmd
    .command('ls')
    .description('List all deployment profiles')
    .action(() => {
        try {
            deploymentListCommand();
        } catch (e) {
            exitOnError(e);
        }
    });

deploymentCmd
    .command('delete [alias]')
    .description('Delete a deployment profile by alias or admin address (local-only; on-chain contracts remain)')
    .option('-a, --account <addr>', 'Match deployment by admin address')
    .action(async (alias: string | undefined, opts: { account?: string }) => {
        try {
            const key = alias ?? opts.account;
            if (!key) exitOnError(new Error('Provide an alias or --account <addr>'));
            await deploymentDeleteCommand(key);
        } catch (e) {
            exitOnError(e);
        }
    });

deploymentCmd
    .command('default [alias]')
    .description('Set the default deployment profile by alias or admin address')
    .option('-a, --account <addr>', 'Match deployment by admin address')
    .action((alias: string | undefined, opts: { account?: string }) => {
        try {
            const key = alias ?? opts.account;
            if (!key) exitOnError(new Error('Provide an alias or --account <addr>'));
            deploymentDefaultCommand(key);
        } catch (e) {
            exitOnError(e);
        }
    });

deploymentCmd
    .command('update-contracts')
    .description('Republish all 11 Move packages to the deployment (admin profile required)')
    .option('-p, --profile <alias>', 'Deployment profile alias to use')
    .option('-a, --account <addr>', 'Admin account address of the profile to use')
    .option('--version <X.Y.Z>', 'Version override (default: read from repo-root NEXT_RELEASE)')
    .option('-y, --yes', 'Skip the confirmation prompt')
    .action(async (opts: { profile?: string; account?: string; version?: string; yes?: boolean }) => {
        try {
            await updateContractsCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

deploymentCmd
    .command('edit')
    .description('Edit a deployment profile in $EDITOR (alias, rpcUrl, network, API keys)')
    .option('-p, --profile <alias>', 'Deployment profile alias to use')
    .option('-a, --account <addr>', 'Admin account address of the profile to use')
    .action(async (opts: { profile?: string; account?: string }) => {
        try {
            await deploymentEditCommand(opts);
        } catch (e) {
            exitOnError(e);
        }
    });

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
            if (!config.defaultNode) {
                config.defaultNode = nodeKey;
            } else if (config.defaultNode !== nodeKey) {
                const currentDefault = config.nodes[config.defaultNode];
                const currentLabel = currentDefault?.alias ?? config.defaultNode;
                const setDefault = await confirm({
                    message: `Set "${node.alias ?? nodeKey}" as the default node? (current default: ${currentLabel})`,
                    default: false,
                });
                if (setDefault) config.defaultNode = nodeKey;
            }
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
// `ace loadtest` — operator-facing load testing (account, contract, runner)
// ──────────────────────────────────────────────────────────────────────────────

const loadtestCmd = program.command('loadtest').description('Constant-rate load testing of ACE workers');

loadtestCmd
    .command('setup')
    .description('Generate a test account, wait for faucet funding, deploy the loadtest-acl Move contract. Idempotent per --network.')
    .option('--network <name>', 'Network name (testnet | mainnet | devnet | localnet)', 'testnet')
    .option('--rpc-url <url>', 'Override the default RPC URL for this network')
    .action(async (opts: { network?: string; rpcUrl?: string }) => {
        try {
            const { loadtestSetupCommand } = await import('./commands/loadtest.js');
            await loadtestSetupCommand(opts);
        } catch (e) { exitOnError(e); }
    });

loadtestCmd
    .command('run')
    .description('Drive a constant-rate QPS ramp at the target worker.')
    .option('-a, --account <addr>', 'Target a tracked node profile by account address')
    .option('-e, --endpoint <url>', 'Target an arbitrary worker URL (must be a current committee member)')
    .option('--post-url <url>', "Override the URL the probe actually POSTs to. The mint still uses --endpoint for committee-member lookup (enc-key + slot), but the probe traffic goes to --post-url. Useful for testing through a global LB / proxy / VPC route.")
    .option('--network <name>', 'Network name (matches a prior `loadtest setup`)', 'testnet')
    .option('--contract <addr>', 'ACE contract address to target (default: ts-sdk knownDeployments.preview20260506). Required together with --keypair and --chain-id.')
    .option('--keypair <addr>', 'ACE keypair ID. Required together with --contract and --chain-id.')
    .option('--chain-id <id>', 'Chain ID for the target ACE deployment. Required together with --contract and --keypair.')
    .option('--ramp <csv>', 'Comma-separated QPS levels (default 20,40,80,160,320,640,1280)')
    .option('--duration <sec>', 'Seconds per level (default 330 — covers epoch rotation)')
    .option('--cooldown <sec>', 'Idle seconds between levels (default 60)')
    .option('--timeout <ms>', 'Per-request hard timeout in ms (default 5000 — a request that takes 5s+ is treated as failed; also bounds max in-flight to QPS*timeout so the probe stays within default Node heap)')
    .option('--epoch-delay <sec>', 'Seconds to wait after detecting an epoch change before re-minting (default 10)')
    .option('-o, --output <path>', 'CSV output path (default loadtest-results/results-<run-id>.csv)')
    .action(async (opts: any) => {
        try {
            const { loadtestRunCommand } = await import('./commands/loadtest.js');
            await loadtestRunCommand(opts);
        } catch (e) { exitOnError(e); }
    });

loadtestCmd
    .command('status')
    .description('Show saved load-test state (account, contract) per network.')
    .option('--network <name>', 'Only show one network')
    .action(async (opts: { network?: string }) => {
        try {
            const { loadtestStatusCommand } = await import('./commands/loadtest.js');
            loadtestStatusCommand(opts);
        } catch (e) { exitOnError(e); }
    });

loadtestCmd
    .command('reset')
    .description('Delete the saved load-test state for one network (on-chain APT + contract are NOT deleted).')
    .option('--network <name>', 'Network name', 'testnet')
    .action(async (opts: { network?: string }) => {
        try {
            const { loadtestResetCommand } = await import('./commands/loadtest.js');
            loadtestResetCommand(opts);
        } catch (e) { exitOnError(e); }
    });

// ──────────────────────────────────────────────────────────────────────────────
// `ace image` — Docker Hub registry helpers
// ──────────────────────────────────────────────────────────────────────────────

const imageCmd = program.command('image').description('Inspect available ACE worker images');

imageCmd
    .command('ls')
    .description('List recently pushed aptoslabs/ace-node tags on Docker Hub')
    .option('-n, --limit <count>', 'Number of newest tags to show (max 100)', '25')
    .action(async (opts: { limit?: string }) => {
        try {
            const { imageLsCommand } = await import('./commands/image-ls.js');
            await imageLsCommand(opts);
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
    process.stderr.write(`\nError: ${formatError(e)}\n`);
    process.exit(1);
}
