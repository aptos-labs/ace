// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace loadtest …` — drive constant-rate load at an ACE worker and record the
 * latency-vs-QPS curve. State (test account + ACL contract) is provisioned once
 * per network via `setup`; `run` reuses it.
 *
 * Four subcommands:
 *   setup [--network testnet]          generate a test account, wait for faucet
 *                                      funding, deploy the loadtest-acl Move
 *                                      contract. Idempotent (skips if already
 *                                      set up for the network).
 *   run --target <account|endpoint>    fire the configured QPS ramp.
 *   status                             show what's saved.
 *   reset [--network testnet]          delete the saved state for one network.
 */

import { spawn } from 'child_process';
import { existsSync } from 'fs';
import * as path from 'path';
import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import { CLI } from '../cli-name.js';
import { loadConfig, saveConfig, type LoadTestState } from '../config.js';
import { ensureAccountFunded } from '../onboarding.js';
import { buildOnce, Minter, loadtesterAccountFromSk, type MintConfig } from '../loadtest/mint.js';
import { runProbe } from '../loadtest/probe.js';
import { plotAsciiIfAvailable } from '../loadtest/plot.js';

const DEFAULT_NETWORK = 'testnet';
const DEFAULT_RPC: Record<string, string> = {
    testnet:  'https://api.testnet.aptoslabs.com/v1',
    mainnet:  'https://api.mainnet.aptoslabs.com/v1',
    devnet:   'https://api.devnet.aptoslabs.com/v1',
    localnet: 'http://localhost:8080/v1',
};

const MODULE_NAME = 'acl';
const DOMAIN_BYTES = new TextEncoder().encode('loadtest');

// Path to the loadtest-acl Move package, packaged inside the CLI. Lives under
// `cli/move/` (NOT `cli/contracts/`) to avoid confusion with the repo-root
// `contracts/` tree, which holds the ACE protocol Move packages. The CLI is
// bundled to `cli/dist/index.js`, so `../move/loadtest-acl` resolves correctly
// in both dev (tsx) and built layouts.
const LOADTEST_ACL_PACKAGE = path.resolve(__dirname, '..', 'move', 'loadtest-acl');

// ── setup ─────────────────────────────────────────────────────────────────────

export async function loadtestSetupCommand(opts: { network?: string; rpcUrl?: string }): Promise<void> {
    const network = opts.network ?? DEFAULT_NETWORK;
    const rpcUrl = opts.rpcUrl ?? DEFAULT_RPC[network];
    if (!rpcUrl) throw new Error(`No default RPC URL for network "${network}" — pass --rpc-url.`);

    const config = loadConfig();
    if (config.loadtest?.[network]) {
        const s = config.loadtest[network];
        console.log(`Already set up on ${network}:`);
        printState(s);
        console.log(`\n(To re-setup, run \`${CLI} loadtest reset --network ${network}\` first.)`);
        return;
    }

    console.log(`Setting up loadtest on ${network} (rpc: ${rpcUrl})\n`);

    // 1. Generate a fresh account.
    const account = Account.generate();
    const accountAddr = account.accountAddress.toStringLong();
    const accountSk = '0x' + Buffer.from(
        (account.privateKey as { toUint8Array(): Uint8Array }).toUint8Array(),
    ).toString('hex');
    console.log(`Generated account: ${accountAddr}\n`);

    // 2. Wait for the operator to fund it (or auto-mint on devnet/localnet).
    await ensureAccountFunded(rpcUrl, accountAddr);

    // 3. Publish the loadtest-acl Move package at the new account.
    console.log(`\nPublishing loadtest-acl contract...`);
    if (!existsSync(path.join(LOADTEST_ACL_PACKAGE, 'Move.toml'))) {
        throw new Error(
            `Loadtest-acl package not found at ${LOADTEST_ACL_PACKAGE}. ` +
            `The CLI build needs to ship the cli/contracts/ tree alongside dist/index.js.`,
        );
    }
    await publishLoadtestAcl(LOADTEST_ACL_PACKAGE, accountSk, rpcUrl, accountAddr);

    // 4. Save state.
    const cfg2 = loadConfig();
    cfg2.loadtest = cfg2.loadtest ?? {};
    cfg2.loadtest[network] = {
        network,
        rpcUrl,
        accountAddr,
        accountSk,
        contractAddr: accountAddr,
        deployedAt: new Date().toISOString(),
    };
    saveConfig(cfg2);
    console.log(`\n✓ Saved load-test state for ${network} to ~/.ace/config.json`);
}

async function publishLoadtestAcl(
    packageDir: string, privateKeyHex: string, rpcUrl: string, accountAddr: string,
): Promise<void> {
    const args = [
        'move', 'publish',
        '--package-dir', packageDir,
        '--named-addresses', `loadtest=${accountAddr}`,
        '--private-key', privateKeyHex,
        '--url', rpcUrl,
        '--assume-yes',
        '--skip-fetch-latest-git-deps',
    ];
    const redacted = args.map((a, i) => (args[i - 1] === '--private-key' ? '<REDACTED>' : a));
    console.log(`  $ aptos ${redacted.join(' ')}`);
    await new Promise<void>((resolve, reject) => {
        const child = spawn('aptos', args, { stdio: 'inherit' });
        child.once('error', reject);
        child.once('close', (code) => code === 0
            ? resolve()
            : reject(new Error(`aptos move publish failed (exit ${code})`)));
    });
}

// ── run ───────────────────────────────────────────────────────────────────────

export async function loadtestRunCommand(opts: {
    account?: string;
    endpoint?: string;
    network?: string;
    ramp?: string;
    duration?: string;
    cooldown?: string;
    timeout?: string;
    epochDelay?: string;
    output?: string;
}): Promise<void> {
    const network = opts.network ?? DEFAULT_NETWORK;
    const config = loadConfig();
    const state = config.loadtest?.[network];
    if (!state) {
        throw new Error(
            `No load-test state for ${network}. Run \`${CLI} loadtest setup --network ${network}\` first.`,
        );
    }

    // Resolve target endpoint.
    const targetEndpoint = await resolveTargetEndpoint(opts);
    console.log(`Target endpoint: ${targetEndpoint}`);
    console.log(`Network:         ${network}`);
    console.log(`Test account:    ${state.accountAddr}\n`);

    // SDK setup. The keypairId / aceDeployment come from knownDeployments today
    // (preview20260506 for testnet); a future flag could let operators target
    // other deployments.
    const known = ACE.knownDeployments.preview20260506;
    const aceDeployment = known.aceDeployment;
    const keypairId = known.keypairId;
    const chainId = known.chainId;

    const loadtester = loadtesterAccountFromSk(state.accountSk);
    const mintCfg: MintConfig = {
        aceDeployment, keypairId, chainId,
        targetEndpoint,
        loadtester,
        moduleAddr: AccountAddress.fromString(state.contractAddr),
        moduleName: MODULE_NAME,
        domain: DOMAIN_BYTES,
    };

    // Initial mint (also a smoke test).
    console.log('Building initial request body (full SDK decrypt smoke test)...');
    const initial = await buildOnce(mintCfg);
    console.log(`  epoch=${initial.epoch} body=${initial.requestSize}B\n`);

    // Start background re-minter.
    const minter = new Minter({
        initial,
        cfg: mintCfg,
        epochTransitionDelaySec: opts.epochDelay ? Number(opts.epochDelay) : 10,
        onRefresh: (p) => console.log(`  [minter] pool refreshed: epoch=${p.epoch}`),
    });
    const minterPromise = minter.start();

    // Probe ramp.
    const ramp = (opts.ramp ?? '20,40,80,160,320,640,1280').split(',').map(Number);
    const runId = process.env.RUN_ID ?? new Date().toISOString().replace(/[:.]/g, '-').replace('Z', 'Z');
    const resultsPath = path.resolve(opts.output ?? path.join('loadtest-results', `results-${runId}.csv`));

    let csvPath: string;
    try {
        csvPath = await runProbe({
            minter,
            ramp,
            durationSec: opts.duration ? Number(opts.duration) : 330,
            cooldownSec: opts.cooldown ? Number(opts.cooldown) : 60,
            timeoutMs: opts.timeout ? Number(opts.timeout) : 30_000,
            resultsPath,
            stopErrorRate: 0.05,
            stopP99Ms: 10_000,
        });
    } finally {
        minter.stop();
        await minterPromise;
    }

    console.log(`\nResults at ${csvPath}`);
    plotAsciiIfAvailable(csvPath);
}

async function resolveTargetEndpoint(opts: { account?: string; endpoint?: string }): Promise<string> {
    if (opts.endpoint) return opts.endpoint.replace(/\/$/, '');
    if (opts.account) {
        const config = loadConfig();
        const entry = Object.values(config.nodes)
            .find(n => n.accountAddr.toLowerCase() === opts.account!.toLowerCase());
        if (!entry) throw new Error(`No tracked node profile for account ${opts.account}.`);
        if (!entry.endpoint) throw new Error(`Tracked node for ${opts.account} has no endpoint configured.`);
        return entry.endpoint.replace(/\/$/, '');
    }
    throw new Error('Pass --account <addr> (tracked node) or --endpoint <url>.');
}

// ── status / reset ────────────────────────────────────────────────────────────

export function loadtestStatusCommand(opts: { network?: string }): void {
    const config = loadConfig();
    const states = config.loadtest ?? {};
    const networks = opts.network ? [opts.network] : Object.keys(states);
    if (networks.length === 0) {
        console.log(`No load-test state configured. Run \`${CLI} loadtest setup\` to bootstrap.`);
        return;
    }
    for (const network of networks) {
        const s = states[network];
        if (!s) {
            console.log(`No load-test state for ${network}.`);
            continue;
        }
        console.log(`== ${network} ==`);
        printState(s);
        console.log();
    }
}

function printState(s: LoadTestState): void {
    console.log(`  RPC URL       : ${s.rpcUrl}`);
    console.log(`  account       : ${s.accountAddr}`);
    console.log(`  contract      : ${s.contractAddr}`);
    console.log(`  deployed at   : ${s.deployedAt}`);
}

export function loadtestResetCommand(opts: { network?: string }): void {
    const network = opts.network ?? DEFAULT_NETWORK;
    const config = loadConfig();
    if (!config.loadtest?.[network]) {
        console.log(`No load-test state for ${network} — nothing to reset.`);
        return;
    }
    delete config.loadtest[network];
    if (Object.keys(config.loadtest).length === 0) delete config.loadtest;
    saveConfig(config);
    console.log(`✓ Cleared load-test state for ${network} (~/.ace/config.json).`);
    console.log(`  Note: any APT in the test account and the on-chain ACL module are NOT deleted.`);
}

