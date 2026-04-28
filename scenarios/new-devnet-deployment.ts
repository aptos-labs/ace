// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * One-shot devnet deployment wizard.
 *
 * Flow:
 *   1. Generate admin keypair and fund via devnet faucet.
 *   2. Deploy all contracts to devnet.
 *   3. Print Geomi instructions; prompt for optional shared node API key and
 *      gas station API key.
 *   4. Print operator setup info (RPC URL, contract address, API keys).
 *   5. Wait while operators register their nodes via `ace nodes`.
 *   6. Collect initial committee: addresses, threshold, epoch duration.
 *   7. Call network::start_initial_epoch.
 *   8. Write deployment-devnet-<date>.json.
 *   9. Save admin account as an aptos-cli profile (suggested name, user confirms).
 *
 * Usage:
 *   pnpm new-devnet-deployment
 */

import * as readline from 'readline';
import { writeFileSync } from 'fs';
import { execSync } from 'child_process';

import { Account, AccountAddress, Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';

import {
    log,
    deployContracts,
    submitTxn,
    ed25519PrivateKeyHex,
} from './common/helpers';

const DEVNET_RPC_URL = 'https://api.devnet.aptoslabs.com/v1';

// ── readline helpers ──────────────────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q: string): Promise<string> => new Promise(resolve => rl.question(q, resolve));

async function askOptional(prompt: string): Promise<string | undefined> {
    const answer = await ask(prompt);
    return answer.trim() || undefined;
}

// ── devnet faucet ─────────────────────────────────────────────────────────────

async function fundOnDevnet(address: AccountAddress): Promise<void> {
    log(`Requesting devnet faucet for ${address.toStringLong().slice(0, 16)}...`);
    const aptos = new Aptos(new AptosConfig({ network: Network.DEVNET }));
    // Request 5 APT — enough to cover all contract deploys.
    await aptos.fundAccount({ accountAddress: address, amount: 500_000_000 });
    log('Funded successfully.');
}

// ── aptos-cli profile ─────────────────────────────────────────────────────────

function saveAptosProfile(profileName: string, rpcUrl: string, privateKeyHex: string): void {
    const args = [
        'aptos', 'init',
        '--profile', profileName,
        '--network', 'custom',
        '--rest-url', rpcUrl,
        '--private-key', `0x${privateKeyHex}`,
        '--assume-yes',
    ];
    log(`Saving aptos-cli profile "${profileName}"...`);
    execSync(args.join(' '), { stdio: 'inherit' });
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main() {
    process.on('SIGINT', () => {
        log('Caught SIGINT — shutting down.');
        rl.close();
        process.exit(0);
    });

    // ── 1. Generate admin keypair ────────────────────────────────────────────
    const adminAccount = Account.generate();
    const adminAddr = adminAccount.accountAddress.toStringLong();
    const adminPrivKeyHex = ed25519PrivateKeyHex(adminAccount);

    log('');
    log('Generated admin keypair:');
    log(`  Address    : ${adminAddr}`);
    log(`  Public key : ${adminAccount.publicKey.toString()}`);
    log('');

    // ── 2. Fund via devnet faucet ────────────────────────────────────────────
    await fundOnDevnet(adminAccount.accountAddress);

    // ── 3. Deploy contracts ──────────────────────────────────────────────────
    log('');
    log('Deploying contracts to devnet...');
    await deployContracts(adminAccount, [
        'pke', 'worker_config', 'group', 'fiat-shamir-transform',
        'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network',
    ], DEVNET_RPC_URL);
    log('All contracts deployed.');

    // ── 4. Geomi instructions + prompts ──────────────────────────────────────
    log('');
    log('══════════════════════════════════════════════════════════════════════');
    log('  Optional: Geomi node infrastructure');
    log('');
    log('  Geomi (https://geomi.dev) provides managed Aptos Full Nodes and');
    log('  gas stations. With a gas station, committee operators do not need');
    log('  to hold APT to submit transactions.');
    log('');
    log('  If you want Geomi-backed infrastructure:');
    log('    1. Go to https://geomi.dev and sign in.');
    log('    2. Under "Shared Node API Keys", create a key for this network.');
    log('       This key lets all operators share a single full-node endpoint.');
    log('    3. Under "Gas Stations", create a station for this network.');
    log('       The gas station API key funds operator transactions automatically.');
    log('');
    log('  Both are optional — the network works without them.');
    log('══════════════════════════════════════════════════════════════════════');
    log('');

    const sharedNodeApiKey = await askOptional(
        'Shared Node API Key (aptoslabs_... — leave blank to skip): ',
    );

    const gasStationApiKey = await askOptional(
        'Gas Station API Key (aptoslabs_... — leave blank to skip): ',
    );

    // ── 5. Print operator setup info ─────────────────────────────────────────
    const deploymentBlob: Record<string, string> = { rpcUrl: DEVNET_RPC_URL, aceAddr: adminAddr };
    if (sharedNodeApiKey) deploymentBlob.rpcApiKey     = sharedNodeApiKey;
    if (gasStationApiKey) deploymentBlob.gasStationKey = gasStationApiKey;
    const deploymentBlobJson = JSON.stringify(deploymentBlob);

    log('');
    log('══════════════════════════════════════════════════════════════════════');
    log('  Each operator should run `ace nodes` → "Add new node" and paste');
    log('  the deployment blob below when prompted.');
    log('');
    log('  ── deployment blob (copy the line between the dashes) ──────────');
    console.log(deploymentBlobJson);
    log('  ────────────────────────────────────────────────────────────────');
    log('══════════════════════════════════════════════════════════════════════');
    log('');

    // ── 6. Wait for operators ────────────────────────────────────────────────
    await ask('Press Enter when all operators have registered their nodes via `ace nodes`... ');
    log('');

    // ── 7. Collect initial epoch params ──────────────────────────────────────
    const rawAddrs = await ask('Committee addresses (space-separated): ');
    const nodeAddresses = rawAddrs.trim().split(/\s+/).filter(Boolean).map(s => AccountAddress.fromString(s));

    if (nodeAddresses.length === 0) throw new Error('No addresses provided.');

    const rawThreshold = await ask(`Threshold (2 ≤ t ≤ ${nodeAddresses.length}, 2t > ${nodeAddresses.length}): `);
    const threshold = parseInt(rawThreshold.trim(), 10);
    if (isNaN(threshold) || threshold < 2 || threshold > nodeAddresses.length || 2 * threshold <= nodeAddresses.length) {
        throw new Error(`Invalid threshold: ${rawThreshold}`);
    }

    const rawDuration = await ask('Epoch duration in seconds (min 30): ');
    const epochDuration = parseInt(rawDuration.trim(), 10);
    if (isNaN(epochDuration) || epochDuration < 30) {
        throw new Error(`Invalid epoch duration: ${rawDuration}`);
    }

    // ── 8. start_initial_epoch ───────────────────────────────────────────────
    log('');
    log(`Calling start_initial_epoch(nodes=${nodeAddresses.length}, threshold=${threshold}, duration=${epochDuration}s)...`);
    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${adminAddr}::network::start_initial_epoch`,
        args: [nodeAddresses, threshold, epochDuration],
        rpcUrl: DEVNET_RPC_URL,
    })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();
    log('Network started — epoch 0 is live.');

    // ── 9. Write deployment.json ─────────────────────────────────────────────
    const today = new Date().toISOString().slice(0, 10);
    const deploymentFile = `deployment-devnet-${today}.json`;
    const deploymentData: Record<string, unknown> = {
        network: 'devnet',
        rpcUrl: DEVNET_RPC_URL,
        contractAddress: adminAddr,
        adminAddress: adminAddr,
        adminPrivateKey: `0x${adminPrivKeyHex}`,
        committee: nodeAddresses.map(a => a.toStringLong()),
        threshold,
        epochDurationSecs: epochDuration,
        deployedAt: new Date().toISOString(),
    };
    if (sharedNodeApiKey) deploymentData.sharedNodeApiKey = sharedNodeApiKey;
    if (gasStationApiKey) deploymentData.gasStationApiKey = gasStationApiKey;
    writeFileSync(deploymentFile, JSON.stringify(deploymentData, null, 2) + '\n', 'utf8');
    log(`Deployment info written to ${deploymentFile}`);

    // ── 10. Save aptos-cli profile ───────────────────────────────────────────
    const suggestedProfile = `ace-devnet-${today}`;
    const rawProfileName = await ask(`Save as aptos-cli profile [${suggestedProfile}]: `);
    rl.close();

    const profileName = rawProfileName.trim() || suggestedProfile;
    saveAptosProfile(profileName, DEVNET_RPC_URL, adminPrivKeyHex);

    // ── Done ─────────────────────────────────────────────────────────────────
    log('');
    log('══════════════════════════════════════════════════════════════════════');
    log('  Deployment complete!');
    log('');
    log(`  Contract address : ${adminAddr}`);
    log(`  aptos-cli profile: ${profileName}`);
    log(`  Deployment file  : ${deploymentFile}`);
    log('');
    log('  To monitor the network:');
    log(`    ace network status --profile <any-committee-member>`);
    log('══════════════════════════════════════════════════════════════════════');
}

main().catch(err => {
    console.error('Fatal:', err);
    rl.close();
    process.exit(1);
});
