// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment new` — full deployment wizard.
 *
 * Flow:
 *   1. Pre-flight: HEAD is at a git tag and the working tree is clean. Strict.
 *   2. Pick a network (mainnet | testnet | devnet | localnet | custom).
 *   3. Generate (or import) the admin keypair.
 *   4. Fund the admin (manual prompt for testnet/mainnet, faucet for dev/local).
 *   5. Optional Geomi inputs (shared-node API key, gas-station API key).
 *   6. Deploy all 11 ACE Move packages at the version from `<repo>/NEXT_RELEASE`.
 *   7. Print operator-onboarding blob; wait for operators to register.
 *   8. Collect committee + threshold + epoch duration; call `network::start_initial_epoch`.
 *   9. Persist the deployment profile to `~/.ace/config.json`.
 *
 * The strict tag-clean precondition is intentional and unconditional — it makes
 * deployments reproducible (you can `git checkout <tag>` at any later date and the
 * Move bytecode is identical to what's on chain). No `--allow-dirty` escape hatch.
 */

import * as readline from 'readline';
import { execFileSync } from 'child_process';
import {
    Account,
    AccountAddress,
    Aptos,
    AptosConfig,
    Ed25519PrivateKey,
    Network,
} from '@aptos-labs/ts-sdk';
import { select, input } from '@inquirer/prompts';
import { readFileSync } from 'fs';
import { join } from 'path';

import {
    loadConfig,
    saveConfig,
    makeDeploymentKey,
    type TrackedDeployment,
} from '../config.js';
import {
    ACE_CONTRACT_PACKAGES,
    REPO_ROOT,
    deployContracts,
    ed25519PrivateKeyHex,
} from '../deploy-contracts.js';

const NETWORKS: { name: 'mainnet' | 'testnet' | 'devnet' | 'localnet' | 'custom'; rpcUrl?: string; faucet?: string }[] = [
    { name: 'mainnet',  rpcUrl: 'https://api.mainnet.aptoslabs.com/v1' },
    { name: 'testnet',  rpcUrl: 'https://api.testnet.aptoslabs.com/v1' },
    { name: 'devnet',   rpcUrl: 'https://api.devnet.aptoslabs.com/v1',  faucet: 'https://faucet.devnet.aptoslabs.com' },
    { name: 'localnet', rpcUrl: 'http://localhost:8080/v1',              faucet: 'http://localhost:8081' },
    { name: 'custom' },
];

// ── Pre-flight ────────────────────────────────────────────────────────────────

function git(args: string[]): string {
    return execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
}

function preflightTagAndCleanCheck(): { tag: string; commit: string } {
    let status: string;
    try {
        status = git(['status', '--porcelain']);
    } catch (e) {
        throw new Error(`\`git status\` failed — is ${REPO_ROOT} a git repository? (${(e as Error).message})`);
    }
    if (status.length > 0) {
        throw new Error(
            `Working tree is not clean — \`deployment new\` requires a clean tree at a tagged commit.\n` +
            `Uncommitted/untracked changes:\n${status}`,
        );
    }

    const commit = git(['rev-parse', 'HEAD']);
    const tagsAtHead = git(['tag', '--points-at', 'HEAD']).split('\n').filter(Boolean);
    if (tagsAtHead.length === 0) {
        throw new Error(
            `HEAD (${commit.slice(0, 12)}) is not a tagged commit — \`deployment new\` requires HEAD = a release tag.\n` +
            `Tag the commit (e.g. \`git tag v1.2.3\`) and try again.`,
        );
    }

    // If multiple tags point at HEAD, prefer one that looks like a release version.
    const releaseTag = tagsAtHead.find(t => /^v?\d+\.\d+\.\d+/.test(t)) ?? tagsAtHead[0]!;
    return { tag: releaseTag, commit };
}

// ── Aptos helpers ─────────────────────────────────────────────────────────────

function inferAptosNetwork(rpcUrl: string): Network {
    const u = rpcUrl.toLowerCase();
    if (u.includes('mainnet')) return Network.MAINNET;
    if (u.includes('testnet')) return Network.TESTNET;
    if (u.includes('devnet')) return Network.DEVNET;
    if (u.includes('localhost') || u.includes('127.0.0.1')) return Network.LOCAL;
    return Network.CUSTOM;
}

function makeAptos(rpcUrl: string, faucet: string | undefined, apiKey: string | undefined): Aptos {
    const headers = apiKey ? { Authorization: `Bearer ${apiKey}` } : undefined;
    return new Aptos(new AptosConfig({
        network: inferAptosNetwork(rpcUrl),
        fullnode: rpcUrl,
        faucet,
        clientConfig: headers ? { HEADERS: headers } : undefined,
    }));
}

async function waitForBalance(aptos: Aptos, addr: string, label: string): Promise<void> {
    const deadline = Date.now() + 30 * 60_000; // 30 min
    while (Date.now() < deadline) {
        try {
            const oct = await aptos.getAccountAPTAmount({ accountAddress: AccountAddress.fromString(addr) });
            if (BigInt(oct) > 0n) return;
        } catch { /* account may not exist yet — keep polling */ }
        process.stdout.write(`.`);
        await new Promise(r => setTimeout(r, 5000));
    }
    throw new Error(`Timed out waiting for ${label} ${addr} to be funded.`);
}

async function faucetFund(faucetUrl: string, addr: string, amountOctas: number = 100_000_000_000): Promise<void> {
    const url = `${faucetUrl}/mint?amount=${amountOctas}&address=${addr}`;
    const resp = await fetch(url, { method: 'POST' });
    if (!resp.ok) throw new Error(`Faucet error: ${resp.status} ${await resp.text()}`);
}

// ── Prompts ───────────────────────────────────────────────────────────────────

async function promptNetwork(): Promise<{ network: typeof NETWORKS[number]['name']; rpcUrl: string; faucet?: string }> {
    const choice = await select({
        message: 'Target network:',
        choices: NETWORKS.map(n => ({ name: n.name, value: n.name })),
    });
    const def = NETWORKS.find(n => n.name === choice)!;
    if (choice !== 'custom') {
        return { network: choice, rpcUrl: def.rpcUrl!, faucet: def.faucet };
    }
    const rpcUrl = await input({ message: 'Custom fullnode REST API URL:', validate: v => v.startsWith('http') || 'must be an http(s) URL' });
    const faucetRaw = await input({ message: 'Faucet URL (optional, leave blank to skip auto-fund):' });
    return { network: 'custom', rpcUrl: rpcUrl.trim(), faucet: faucetRaw.trim() || undefined };
}

async function promptAdminKey(): Promise<Account> {
    const mode = await select({
        message: 'Admin keypair:',
        choices: [
            { name: 'Generate a new Ed25519 keypair', value: 'generate' },
            { name: 'Import an existing private key (hex)', value: 'import' },
        ],
    });
    if (mode === 'generate') return Account.generate();
    const keyHex = await input({
        message: 'Admin private key (0x-prefixed 64-char hex):',
        validate: v => /^0x[0-9a-fA-F]{64}$/.test(v.trim()) || 'must be 0x + 64 hex chars',
    });
    const sk = new Ed25519PrivateKey(keyHex.trim());
    return Account.fromPrivateKey({ privateKey: sk });
}

function readNextReleaseVersion(): string {
    return readFileSync(join(REPO_ROOT, 'NEXT_RELEASE'), 'utf8').trim();
}

// ── Main ──────────────────────────────────────────────────────────────────────

export async function deploymentNewCommand(): Promise<void> {
    // 1. Pre-flight.
    const { tag, commit } = preflightTagAndCleanCheck();
    const version = readNextReleaseVersion();
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
        throw new Error(`<repo>/NEXT_RELEASE contains "${version}" which is not in X.Y.Z form.`);
    }
    console.log(`Repo state: tag=${tag}  commit=${commit.slice(0, 12)}  version=${version}\n`);

    // 2. Network.
    const { network, rpcUrl, faucet } = await promptNetwork();

    // 3. Admin key.
    const adminAccount = await promptAdminKey();
    const adminAddr = adminAccount.accountAddress.toStringLong();
    const adminPrivKeyHex = ed25519PrivateKeyHex(adminAccount);
    console.log(`\nAdmin address: ${adminAddr}\n`);

    // 4. Fund.
    if (network === 'mainnet' || network === 'testnet' || (network === 'custom' && !faucet)) {
        console.log(`Fund this admin account on ${network} with enough APT to publish 11 packages.`);
        console.log(`  ${adminAddr}\n`);
        await waitForBalance(makeAptos(rpcUrl, undefined, undefined), adminAddr, 'admin');
        console.log('  ✓ funded.\n');
    } else if (faucet) {
        console.log(`Auto-funding via faucet ${faucet} ...`);
        await faucetFund(faucet, adminAddr);
        await waitForBalance(makeAptos(rpcUrl, faucet, undefined), adminAddr, 'admin');
        console.log('  ✓ funded.\n');
    }

    // 5. Optional API keys.
    const sharedNodeApiKey = (await input({ message: 'Shared Node API Key (optional, blank to skip):' })).trim() || undefined;
    const gasStationApiKey = (await input({ message: 'Gas Station API Key (optional, blank to skip):' })).trim() || undefined;
    if (sharedNodeApiKey) process.env.NODE_API_KEY = sharedNodeApiKey;

    // 6. Deploy contracts.
    console.log(`\nDeploying ${ACE_CONTRACT_PACKAGES.length} packages at version ${version} ...\n`);
    await deployContracts(adminAccount, rpcUrl, ACE_CONTRACT_PACKAGES, version);
    console.log('\n  ✓ All contracts deployed.\n');

    // 7. Operator onboarding blob.
    const operatorBlob = JSON.stringify(
        Object.assign({ rpcUrl, aceAddr: adminAddr },
            sharedNodeApiKey ? { rpcApiKey: sharedNodeApiKey } : {},
            gasStationApiKey ? { gasStationKey: gasStationApiKey } : {},
        ),
    );
    console.log('══════════════════════════════════════════════════════════════════════');
    console.log('  Operator onboarding blob — copy and share with each operator.');
    console.log('  Each runs `ace node new` and pastes this when prompted:');
    console.log('');
    console.log(`  ${operatorBlob}`);
    console.log('══════════════════════════════════════════════════════════════════════\n');

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (q: string): Promise<string> => new Promise(r => rl.question(q, r));

    await ask('Press Enter when all operators have registered their nodes... ');

    // 8. Initial epoch.
    const rawAddrs = await ask('Committee addresses (space-separated): ');
    const nodeAddresses = rawAddrs.trim().split(/\s+/).filter(Boolean).map(s => AccountAddress.fromString(s));
    if (nodeAddresses.length === 0) { rl.close(); throw new Error('No committee addresses provided.'); }

    const rawT = await ask(`Threshold (2 ≤ t ≤ ${nodeAddresses.length}, 2t > ${nodeAddresses.length}): `);
    const threshold = parseInt(rawT.trim(), 10);
    if (isNaN(threshold) || threshold < 2 || threshold > nodeAddresses.length || 2 * threshold <= nodeAddresses.length) {
        rl.close();
        throw new Error(`Invalid threshold: ${rawT}`);
    }

    const rawDur = await ask('Epoch duration in seconds (min 30): ');
    const epochDuration = parseInt(rawDur.trim(), 10);
    if (isNaN(epochDuration) || epochDuration < 30) {
        rl.close();
        throw new Error(`Invalid epoch duration: ${rawDur}`);
    }
    rl.close();

    console.log(`\nCalling start_initial_epoch(nodes=${nodeAddresses.length}, threshold=${threshold}, duration=${epochDuration}s) ...`);
    const aptos = makeAptos(rpcUrl, faucet, sharedNodeApiKey);
    const txn = await aptos.transaction.build.simple({
        sender: adminAccount.accountAddress,
        data: {
            function: `${adminAddr}::network::start_initial_epoch` as `${string}::${string}::${string}`,
            functionArguments: [
                nodeAddresses.map(a => a.toStringLong()),
                threshold,
                epochDuration,
            ],
        },
    });
    const resp = await aptos.signAndSubmitTransaction({ signer: adminAccount, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: resp.hash, options: { checkSuccess: true } });
    console.log('  ✓ Epoch 0 live.\n');

    // 9. Persist profile.
    const config = loadConfig();
    const key = makeDeploymentKey(rpcUrl, adminAddr);
    const dep: TrackedDeployment = {
        rpcUrl,
        aceAddr: adminAddr,
        adminAddress: adminAddr,
        adminPrivateKey: `0x${adminPrivKeyHex}`,
        sharedNodeApiKey,
        gasStationApiKey,
        alias: `${network}-${tag}`,
        network,
        deployedAtTag: tag,
        deployedAtCommit: commit,
        deployedAt: new Date().toISOString(),
    };
    config.deployments[key] = dep;
    if (!config.defaultDeployment) config.defaultDeployment = key;
    saveConfig(config);

    console.log('══════════════════════════════════════════════════════════════════════');
    console.log('  Deployment complete!');
    console.log('');
    console.log(`  Profile alias    : ${dep.alias}`);
    console.log(`  Contract address : ${adminAddr}`);
    console.log(`  Tag / version    : ${tag} / v${version}`);
    console.log('');
    console.log('  Next steps:');
    console.log('    ace network-status              # see the running network');
    console.log('    ace deployment ls               # list saved deployment profiles');
    console.log('══════════════════════════════════════════════════════════════════════');
}
